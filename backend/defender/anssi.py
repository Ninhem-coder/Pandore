"""
Rapprochement avis CERT-FR/ANSSI récents ↔ inventaire logiciel complet du tenant — skill
audit-exposure-score (Étape 6). Jusqu'au 2026-08-12 cette section n'existait côté dashboard
que comme un placeholder honnête (AnssiCard.jsx, "Non couvert par cette V1") : ce module
implémente le vrai rapprochement, à la demande de Nicolas de fusionner cette carte avec
l'onglet "Vulnérabilités" plutôt que de la laisser vide.

✅ SCRAPING VÉRIFIÉ EN CONDITIONS RÉELLES le 2026-08-27 (Nicolas : "j'ai l'impression que ça ne
fonctionne pas" sur la tuile ANSSI/CERT-FR de Vue d'ensemble — soupçon confirmé). L'avertissement
d'origine ci-dessous (jamais testé en conditions réelles faute d'accès réseau sortant à
l'écriture de ce module) s'est avéré fondé : DEUX bugs réels trouvés et corrigés.
1. `_extract_entries` (structure de page) était en fait CORRECTE — la recherche générique de
   tout `<a href>` matchant `_REF_PATTERN` fonctionne quelle que soit l'habillage CSS exact
   (confirmé : 20 avis extraits sur la page 1 réelle).
2. `_parse_date` en revanche ratait TOUJOURS — le site utilise `<span class="item-date">Publié
   le 27 août 2026</span>` (date française en toutes lettres), un format que ni `_DATE_ISO` ni
   `_DATE_FR` (JJ/MM/AAAA) ne reconnaissaient. Résultat : `published` valait toujours `None`
   pour CHAQUE avis, donc `collected` restait TOUJOURS vide, silencieusement (pas d'erreur
   levée — `total_extracted` était bien > 0, donc le garde-fou `ScrapeStructureError` ne se
   déclenchait pas non plus). Corrigé par `_DATE_FR_LONG`/`_MONTHS_FR` ci-dessous.
3. La pagination `?page=N` (query string) était ÉGALEMENT fausse — confirmé que le site
   l'ignore silencieusement et resert toujours la page 1. Le vrai format est `/avis/page/N/`
   (segment de chemin), corrigé dans `_fetch_page`. Sans incidence pratique tant que le bug #2
   n'était pas corrigé (aucun avis n'était jamais retenu de toute façon), mais aurait
   silencieusement re-scanné la page 1 en boucle sous `MAX_PAGES` une fois #2 corrigé seul.

L'inventaire logiciel (KQL ci-dessous), lui, avait déjà été vérifié EN DIRECT sur le tenant
de production avant l'écriture initiale de cette fonction (12819 couples éditeur/logiciel
distincts au 2026-08-12, conforme à la règle du projet "toujours vérifier une nouvelle requête
KQL avant de coder") — jamais remis en cause par ce correctif.

Rapprochement volontairement approximatif (titre d'avis ↔ SoftwareVendor/SoftwareName) — voir
SKILL.md Étape 6.3 : jamais présenté comme une certitude côté frontend, toujours accompagné
du lien vers l'avis d'origine pour vérification manuelle par Nicolas avant toute action.
"""
import logging
import re
import unicodedata
from datetime import datetime, timedelta, timezone

import httpx

from common.cache import TTLCache

try:
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover - dépendance à installer côté environnement de Nicolas
    BeautifulSoup = None

from common.http_client import handle_tool_errors, tool_error
from defender.hunting import run_hunting_query

logger = logging.getLogger(__name__)

BASE_URL = "https://cert.ssi.gouv.fr"
LIST_URL = f"{BASE_URL}/avis/"
MAX_PAGES = 5
DEFAULT_WINDOW_DAYS = 14
_CACHE_TTL_SECONDS = 1800  # 30 min — évite de re-scraper cert.ssi.gouv.fr à chaque ouverture
# de l'onglet Vulnérabilités ; le bouton "Rafraîchir" du frontend force le contournement.

_REF_PATTERN = re.compile(r"/avis/(CERTFR-\d{4}-AVI-\d+)/?")
# Usage strictement interne à ce module (extraction des CVE citées dans le détail d'un avis,
# _fetch_avis_detail_cves) — sans rapport avec le _CVE_PATTERN de defender/vulnerabilities.py
# (import direct depuis ce module par defender/watchlist.py pour valider le format d'une
# CVE suivie).
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")
_DATE_ISO = re.compile(r"(\d{4})-(\d{2})-(\d{2})")
_DATE_FR = re.compile(r"(\d{2})/(\d{2})/(\d{4})")
# Format RÉEL de cert.ssi.gouv.fr (confirmé le 2026-08-27 par lecture directe du HTML — voir
# le correctif ci-dessous) : `<span class="item-date">Publié le 27 août 2026</span>`, un format
# ni ISO ni JJ/MM/AAAA — aucun des deux patterns ci-dessus ne le reconnaissait, d'où le bug
# "ANSSI ne trouve jamais rien" (`_parse_date` retournait toujours `None`, voir _parse_date).
_MONTHS_FR = {
    "janvier": 1, "fevrier": 2, "mars": 3, "avril": 4, "mai": 5, "juin": 6,
    "juillet": 7, "aout": 8, "septembre": 9, "octobre": 10, "novembre": 11, "decembre": 12,
}
_DATE_FR_LONG = re.compile(
    r"(\d{1,2})\s+(janvier|f[ée]vrier|mars|avril|mai|juin|juillet|ao[uû]t|septembre|octobre|novembre|d[ée]cembre)\s+(\d{4})",
    re.IGNORECASE,
)

# Mots trop génériques dans un titre d'avis pour servir de base de rapprochement (articles,
# vocabulaire récurrent des titres CERT-FR type "Multiples vulnérabilités dans les produits
# ...") — sans ce filtre, un mot comme "produits" matcherait quasiment tout logiciel du parc.
_STOPWORDS = {
    "dans", "de", "des", "du", "la", "le", "les", "un", "une", "et", "ou", "sur", "pour",
    "par", "multiples", "vulnerabilite", "vulnerabilites", "corrective", "mise", "jour",
    "produits", "produit", "systemes", "systeme", "affectant", "concernant", "logiciels",
    "logiciel", "editeur", "solution", "solutions",
}


def _normalize(text: str) -> str:
    if not text:
        return ""
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    return text.lower()


def _parse_date(text: str):
    if not text:
        return None
    m = _DATE_ISO.search(text)
    if m:
        try:
            return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), tzinfo=timezone.utc)
        except ValueError:
            pass
    m = _DATE_FR.search(text)
    if m:
        try:
            return datetime(int(m.group(3)), int(m.group(2)), int(m.group(1)), tzinfo=timezone.utc)
        except ValueError:
            pass
    m = _DATE_FR_LONG.search(text)
    if m:
        month = _MONTHS_FR.get(_normalize(m.group(2)))
        if month:
            try:
                return datetime(int(m.group(3)), month, int(m.group(1)), tzinfo=timezone.utc)
            except ValueError:
                pass
    return None


def _http_client() -> httpx.Client:
    return httpx.Client(
        headers={"User-Agent": "Mozilla/5.0 (compatible; Pandore/1.0; +local security dashboard)"},
        timeout=20,
        follow_redirects=True,
    )


def _fetch_page(client: httpx.Client, page_num: int) -> str:
    # Format de pagination CONFIRMÉ le 2026-08-27 par lecture directe du site (le premier jet,
    # `?page=N`, était une hypothèse jamais vérifiée en conditions réelles — voir l'avertissement
    # en tête de fichier) : cert.ssi.gouv.fr ignore silencieusement `?page=N` et resert toujours
    # la page 1 (200 OK, contenu identique) — `/avis/page/N/` (segment de chemin, pas de query
    # string) est le VRAI format, confirmé en comparant les deux réponses (la page 2 en chemin
    # ne contient plus les avis de tête de la page 1, contrairement à `?page=2`).
    url = LIST_URL if page_num == 1 else f"{LIST_URL}page/{page_num}/"
    resp = client.get(url)
    resp.raise_for_status()
    return resp.text


def _extract_entries(html: str) -> list[dict]:
    """Extrait (ref, title, url, published) de chaque avis d'une page de listing /avis/.

    Cible les cartes du Système de Design de l'État (DSFR), utilisé par cert.ssi.gouv.fr au
    moment de l'écriture — NON vérifié en direct, voir avertissement en tête de fichier. En
    repli, n'importe quel lien vers /avis/CERTFR-.../ est retenu même hors d'une carte DSFR
    reconnue, avec une recherche de date élargie au texte environnant, pour rester tolérant à
    un habillage légèrement différent de ce qui est supposé ici."""
    if BeautifulSoup is None:
        raise RuntimeError(
            "Le module 'beautifulsoup4' n'est pas installé côté backend local "
            "(pip install beautifulsoup4) — nécessaire pour lire cert.ssi.gouv.fr."
        )

    soup = BeautifulSoup(html, "html.parser")
    entries = []
    seen_refs = set()

    for link in soup.find_all("a", href=_REF_PATTERN):
        href = link.get("href", "")
        m = _REF_PATTERN.search(href)
        if not m:
            continue
        ref = m.group(1)
        if ref in seen_refs:
            continue
        title = link.get_text(strip=True)
        if not title:
            continue

        date_text = ""
        container = link
        for _ in range(5):
            parent = getattr(container, "parent", None)
            if parent is None:
                break
            container = parent
            time_tag = container.find("time") if hasattr(container, "find") else None
            if time_tag is not None:
                date_text = time_tag.get("datetime") or time_tag.get_text(strip=True)
                break
            text_blob = container.get_text(" ", strip=True) if hasattr(container, "get_text") else ""
            if _DATE_ISO.search(text_blob) or _DATE_FR.search(text_blob) or _DATE_FR_LONG.search(text_blob):
                date_text = text_blob
                break

        seen_refs.add(ref)
        entries.append(
            {
                "ref": ref,
                "title": title,
                "url": f"{BASE_URL}/avis/{ref}/",
                "published": _parse_date(date_text),
            }
        )

    return entries


def _fetch_avis_window(window_days: int, max_pages: int = MAX_PAGES):
    """Étape 6.2 du skill : parcourt /avis/ page par page jusqu'à sortir de la fenêtre de
    `window_days` jours (ou après `max_pages` pages, garde-fou anti-boucle).

    Renvoie aussi `total_extracted` (nombre BRUT d'avis extraits sur la/les page(s) lues,
    AVANT filtrage par date) — ajouté à la revue de code du 2026-08-20 pour distinguer deux
    cas qui produisaient le même résultat visible ("aucun avis") sans que rien ne les
    différencie côté appelant : (a) le site répond, la page liste bien des avis, mais aucun
    n'entre dans la fenêtre demandée (résultat légitime) ; (b) `_extract_entries` ne trouve
    STRUCTURELLEMENT rien sur la page (site inaccessible en pratique malgré un 200, ou
    markup DSFR différent de celui supposé — voir l'avertissement en tête de fichier, jamais
    vérifié en conditions réelles). Sans cette distinction, (b) s'affichait comme "rien à
    signaler cette semaine" sur un tableau de bord sécurité — silence indiscernable d'une
    vraie absence de risque."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)
    collected: list[dict] = []
    skipped_no_date = 0
    total_extracted = 0
    seen_first_ref_per_page = None

    with _http_client() as client:
        for page_num in range(1, max_pages + 1):
            html = _fetch_page(client, page_num)
            entries = _extract_entries(html)
            if not entries:
                break
            total_extracted += len(entries)

            # Garde-fou : si la pagination `?page=N` ne fait rien (site qui l'ignore et
            # renvoie toujours la page 1), on le détecte en comparant la première réf trouvée
            # à celle de la page précédente, plutôt que de boucler `max_pages` fois pour rien.
            first_ref = entries[0]["ref"]
            if seen_first_ref_per_page is not None and first_ref == seen_first_ref_per_page:
                break
            seen_first_ref_per_page = first_ref

            stop = False
            for entry in entries:
                if entry["published"] is None:
                    skipped_no_date += 1
                    continue
                if entry["published"] < cutoff:
                    stop = True
                    continue
                collected.append(entry)
            if stop:
                break

    return collected, skipped_no_date, total_extracted


def _section_text(soup, heading_text: str) -> str | None:
    """Premier `<p>` non vide rencontré après le `<h2>` dont le texte contient `heading_text`,
    en s'arrêtant dès le `<h2>` SUIVANT (jamais emprunter le texte de la section d'après si
    celle visée n'a pas de `<p>` — vérifié le 2026-09-10 en inspectant directement des avis
    réels : "Résumé"/"Solutions" ont chacun exactement un `<p>` dans la structure actuelle du
    site, mais rien ne garantit que ça reste toujours vrai)."""
    h2 = soup.find("h2", string=lambda s: s and heading_text in s)
    if h2 is None:
        return None
    for el in h2.find_all_next():
        if el.name == "h2":
            break
        if el.name == "p":
            text = el.get_text(strip=True)
            if text:
                return text
    return None


def _section_list(soup, heading_text: str) -> list[str]:
    """Même principe que `_section_text`, pour la première `<ul>` de la section (ex.
    "Risque"/"Systèmes affectés", listés en puces sur le site réel)."""
    h2 = soup.find("h2", string=lambda s: s and heading_text in s)
    if h2 is None:
        return []
    for el in h2.find_all_next():
        if el.name == "h2":
            break
        if el.name == "ul":
            return [li.get_text(strip=True) for li in el.find_all("li")]
    return []


_detail_cache = TTLCache(_CACHE_TTL_SECONDS)


def _fetch_avis_detail(client: httpx.Client, ref: str) -> dict:
    """Détail complet d'un avis (2026-09-10, demande de Nicolas — "une description, un plan
    d'action en se basant sur le CERT-FR") : CVE citées (comme avant) PLUS "Résumé" et
    "Solutions", les deux sections systématiquement présentes sur un avis réel (vérifié en
    direct contre plusieurs avis avant d'écrire ce code — voir `_section_text`). Cache PAR AVIS
    (distinct du cache de `get_anssi_matches`, qui mémorise le RÉSULTAT agrégé) : `get_anssi_
    matches` et `get_cve_avis` peuvent tous les deux avoir besoin du même avis dans la même
    fenêtre de 30 min, sans le re-télécharger deux fois.
    """
    cached = _detail_cache.get(ref)
    if cached is not None:
        return cached
    resp = client.get(f"{BASE_URL}/avis/{ref}/")
    resp.raise_for_status()
    html = resp.text
    soup = BeautifulSoup(html, "html.parser")
    detail = {
        "cves": sorted(set(_CVE_PATTERN.findall(html))),
        "summary": _section_text(soup, "Résumé"),
        "solution": _section_text(soup, "Solutions"),
        "risks": _section_list(soup, "Risque"),
    }
    _detail_cache.set(ref, detail)
    return detail


_SHORT_VENDOR_ALLOWLIST = {"hp", "f5", "ibm", "sap", "aws", "gcp", "hpe", "sas"}


def _significant_words(title: str) -> list[str]:
    """Seuil abaissé de 4 à 3 caractères, plus une petite liste blanche pour les rares sigles
    de 2 lettres (revue de code du 2026-08-20) : à 4, tout titre d'avis concernant un éditeur
    au nom court (SAP, IBM, ESX/ESXi, Citrix ADC — tous des cas réels et fréquents) ne pouvait
    STRUCTURELLEMENT jamais matcher l'inventaire, puisqu'aucun de leurs tokens identifiants ne
    passait le filtre — un trou de couverture silencieux plutôt qu'un simple faux négatif
    occasionnel. HP/F5 restent sous le seuil de 3 même après ce changement (2 caractères) : la
    liste blanche ci-dessus les couvre explicitement plutôt que de baisser le seuil à 2, ce qui
    laisserait passer trop de bruit (articles/connecteurs français à 2 lettres)."""
    words = re.findall(r"[a-z0-9]+", _normalize(title))
    return [w for w in words if (len(w) >= 3 or w in _SHORT_VENDOR_ALLOWLIST) and w not in _STOPWORDS]


def _match_against_inventory(entries: list[dict], inventory: list[dict]) -> list[dict]:
    """Rapprochement approximatif titre ↔ (SoftwareVendor, SoftwareName) — skill étape 6.3.
    Retient, pour chaque avis, le couple éditeur/logiciel avec le plus de mots significatifs
    du titre en commun (au moins un) ; ignore l'avis si aucun mot significatif n'a de
    correspondance dans l'inventaire complet du parc."""
    # Normalisé UNE SEULE FOIS par item d'inventaire, hors de la boucle `entries` : avant cette
    # revue, les ~12819 couples éditeur/logiciel étaient renormalisés (unicodedata + lower) à
    # CHAQUE avis de la fenêtre CERT-FR, un travail identique répété inutilement pour chaque
    # avis (le cache de 30 min de get_anssi_matches atténuait la fréquence globale, pas ce
    # coût par appel).
    normalized_inventory = [
        (item, _normalize(f"{item['software_vendor']} {item['software_name']}".replace("_", " ")))
        for item in inventory
    ]

    matches = []
    for entry in entries:
        words = _significant_words(entry["title"])
        if not words:
            continue
        best = None
        best_hits: list[str] = []
        for item, haystack in normalized_inventory:
            hits = [w for w in words if w in haystack]
            if hits and len(hits) > len(best_hits):
                best, best_hits = item, hits
        if best:
            matches.append(
                {
                    **entry,
                    "matched_vendor": best["software_vendor"],
                    "matched_name": best["software_name"],
                    "matched_device_count": best.get("device_count"),
                }
            )
    return matches


_INVENTORY_CACHE_KEY = "full_inventory"
# Cache DÉDIÉ à l'inventaire brut, distinct de `_cache` ci-dessous (qui mémorise le résultat
# du RAPPROCHEMENT complet, pas l'inventaire seul) — ajouté le 2026-08-28 à l'origine pour
# l'autocomplétion de la recherche de vulnérabilités (fonction retirée le 2026-09-09, code
# mort après la réécriture v3/v4 de VulnerabilitiesTab.jsx), gardé car toujours utile pour ne
# pas reformuler la requête KQL à chaque rapprochement ANSSI.
_inventory_cache = TTLCache(_CACHE_TTL_SECONDS)


def _get_full_inventory():
    """Inventaire logiciel COMPLET du parc (pas seulement le "top" habituellement affiché,
    voir get_top_vulnerable_software) — 12819 couples éditeur/logiciel distincts vérifiés en
    direct sur le tenant de production le 2026-08-12. Utilisé pour le rapprochement ANSSI,
    jamais affiché tel quel côté frontend."""
    cached = _inventory_cache.get(_INVENTORY_CACHE_KEY)
    if cached is not None:
        return cached, None

    kql = """
DeviceTvmSoftwareInventory
| summarize DeviceCount = dcount(DeviceId) by SoftwareVendor, SoftwareName
| order by DeviceCount desc
"""
    hunting = run_hunting_query(kql)
    if isinstance(hunting, dict) and hunting.get("error"):
        return None, hunting
    inventory = [
        {
            "software_vendor": r.get("SoftwareVendor"),
            "software_name": r.get("SoftwareName"),
            "device_count": r.get("DeviceCount"),
        }
        for r in hunting.get("results", [])
        if r.get("SoftwareVendor") and r.get("SoftwareName")
    ]
    _inventory_cache.set(_INVENTORY_CACHE_KEY, inventory)
    return inventory, None


# TTLCache (common/cache.py, extrait à la revue d'architecture du 2026-08-17) : avant ça, ce
# cache réimplémentait à la main un dict+verrou+TTL quasi identique à celui de
# intune/tools.py::get_compliance_detail, en dérivant légèrement (celui-ci exposait déjà
# `force_refresh`, l'autre pas — désormais unifié des deux côtés). Clé par `window_days` :
# contrairement à l'ancien dict (une seule entrée, remplacée entièrement à chaque changement
# de `window_days`), chaque valeur de `window_days` a maintenant sa propre entrée — en
# pratique le frontend appelle toujours avec la même fenêtre (14 jours), donc pas de
# différence observable, mais plus correct si un jour plusieurs fenêtres coexistent.
#
# `TTLCache.get`/`.set` protègent seulement la LECTURE/ÉCRITURE du cache (même granularité
# qu'avant cette revue), pas l'intégralité du scraping + de la requête KQL ci-dessous : deux
# requêtes arrivant simultanément avec un cache expiré peuvent donc encore, dans de rares cas,
# déclencher chacune un rafraîchissement complet en double — sans risque de corruption du
# cache (juste un travail réseau/KQL redondant), contrairement à l'absence totale de verrou
# d'avant la revue du 2026-08-17 (RÉF : REVUE_CODE_2026-08-17.md).
_cache = TTLCache(_CACHE_TTL_SECONDS)


@handle_tool_errors
def get_anssi_matches(window_days: int = DEFAULT_WINDOW_DAYS, force_refresh: bool = False) -> list[dict]:
    """
    Rapprochement avis CERT-FR/ANSSI des `window_days` derniers jours ↔ inventaire logiciel
    COMPLET du tenant (pas un sous-ensemble) — voir avertissement en tête de fichier sur ce
    qui a et n'a pas pu être vérifié en conditions réelles avant l'écriture de cette fonction.

    Mise en cache 30 min en mémoire process (`_cache`, un `TTLCache` — voir common/cache.py)
    pour éviter de re-scraper cert.ssi.gouv.fr à chaque ouverture de l'onglet Vulnérabilités ;
    `force_refresh=True` (bouton "Rafraîchir" du frontend) contourne le cache.
    """
    if not force_refresh:
        cached = _cache.get(window_days)
        if cached is not None:
            return cached

    inventory, inventory_error = _get_full_inventory()
    if inventory_error is not None:
        return [inventory_error]

    try:
        entries, _skipped_no_date, total_extracted = _fetch_avis_window(window_days=window_days)
    except httpx.HTTPStatusError as exc:
        return [
            tool_error(
                f"cert.ssi.gouv.fr a répondu {exc.response.status_code} — le site est peut-être "
                "temporairement indisponible ou bloque ce type d'accès automatisé.",
                "HTTPStatusError",
            )
        ]
    except httpx.RequestError as exc:
        return [
            tool_error(
                f"Impossible de contacter cert.ssi.gouv.fr ({exc.__class__.__name__}) : {exc}. "
                "Vérifier l'accès réseau sortant du poste exécutant le backend.",
                "RequestError",
            )
        ]

    if total_extracted == 0:
        # Revue de code du 2026-08-20 : la page de listing a répondu (pas d'exception réseau/
        # HTTP ci-dessus) mais `_extract_entries` n'y a trouvé STRUCTURELLEMENT aucun avis —
        # cert.ssi.gouv.fr publie en pratique en continu, une page de listing totalement vide
        # est donc bien plus probablement un scraping cassé (markup différent de celui supposé,
        # voir l'avertissement en tête de fichier) qu'une réalité. On le signale explicitement
        # plutôt que de renvoyer un résultat vide indiscernable d'un "rien à signaler cette
        # semaine" légitime sur un tableau de bord sécurité.
        return [
            tool_error(
                "cert.ssi.gouv.fr a répondu mais aucun avis n'a pu être extrait de la page — le "
                "site a probablement changé de structure (voir l'avertissement en tête de "
                "defender/anssi.py). Ce n'est PAS forcément une absence réelle d'avis récents.",
                "ScrapeStructureError",
            )
        ]

    candidates = _match_against_inventory(entries, inventory)

    results = []
    with _http_client() as client:
        for match in candidates:
            try:
                detail = _fetch_avis_detail(client, match["ref"])
            except httpx.HTTPError as exc:
                logger.warning("Échec récupération détail avis %s : %s", match["ref"], exc)
                detail = {"cves": [], "summary": None, "solution": None, "risks": []}
            results.append(
                {
                    "certfr_ref": match["ref"],
                    "title": match["title"],
                    "published": match["published"].date().isoformat() if match["published"] else None,
                    "url": match["url"],
                    "cve": detail["cves"],
                    # Résumé/plan d'action (2026-09-10) — mêmes champs que `get_cve_avis`,
                    # gratuits ici (déjà extraits par `_fetch_avis_detail` pour le CVE).
                    "summary": detail["summary"],
                    "solution": detail["solution"],
                    "matched_software": f"{match['matched_vendor']} / {match['matched_name']}",
                    "matched_query": match["matched_name"].replace("_", " "),
                    "matched_device_count": match["matched_device_count"],
                }
            )

    results.sort(key=lambda r: r.get("published") or "", reverse=True)

    _cache.set(window_days, results)
    return results


_cve_index_cache = TTLCache(_CACHE_TTL_SECONDS)


def _build_cve_index(window_days: int) -> dict[str, dict]:
    """CVE → détail d'avis, sur TOUTE la fenêtre de jours — INDÉPENDANT du rapprochement par
    nom de logiciel de `get_anssi_matches` (celui-ci ne garde que les avis dont le titre a pu
    être rapproché de l'inventaire ; une CVE peut très bien avoir un avis CERT-FR dont le titre
    n'a matché aucun logiciel connu du tenant — le rapprochement par nom reste volontairement
    approximatif, voir `_match_against_inventory`). Un même CVE cité par plusieurs avis garde
    le PLUS RÉCENT (`_fetch_avis_window` renvoie déjà du plus récent au plus ancien)."""
    entries, _skipped_no_date, _total_extracted = _fetch_avis_window(window_days=window_days)
    index: dict[str, dict] = {}
    with _http_client() as client:
        for entry in entries:
            try:
                detail = _fetch_avis_detail(client, entry["ref"])
            except httpx.HTTPError as exc:
                logger.warning("Échec récupération détail avis %s : %s", entry["ref"], exc)
                continue
            for cve_id in detail["cves"]:
                index.setdefault(
                    cve_id.upper(),
                    {
                        "certfr_ref": entry["ref"],
                        "title": entry["title"],
                        "url": entry["url"],
                        "published": entry["published"].date().isoformat() if entry["published"] else None,
                        "summary": detail["summary"],
                        "solution": detail["solution"],
                    },
                )
    return index


@handle_tool_errors
def get_cve_avis(cve_id: str, window_days: int = DEFAULT_WINDOW_DAYS) -> dict | None:
    """Avis CERT-FR le plus récent citant `cve_id` sur les `window_days` derniers jours, ou
    `None` si aucun (résultat légitime — CERT-FR ne publie pas d'avis pour toutes les CVE,
    voir la revue comparative du 2026-09-10). Page "Vulnérabilités" de Vanitas : contrairement
    à `get_anssi_matches` (pensé pour un rapprochement fleet-wide par nom de logiciel), une
    recherche directe par CVE précise, appelée à la demande depuis la popup de détail.

    Index CVE→avis mis en cache 30 min comme `get_anssi_matches` (même `_CACHE_TTL_SECONDS`) —
    coûteux à construire (un aller-retour par avis de la fenêtre, jusqu'à ~50), jamais reconstruit
    à chaque clic sur une CVE différente tant que le cache est valide.
    """
    index = _cve_index_cache.get(window_days)
    if index is None:
        index = _build_cve_index(window_days)
        _cve_index_cache.set(window_days, index)
    return index.get(cve_id.strip().upper())
