"""
Détection de logiciels/OS en fin de support (EOL) — jalon Vanitas du 2026-09-08, distinct
d'une CVE ponctuelle (recherche/rapprochement Defender déjà couvert par `defender/
vulnerabilities.py`/`defender/anssi.py`) : ici on flague un logiciel/OS obsolète PAR PRINCIPE,
qu'il ait ou non une CVE connue en ce moment.

Réécrit le 2026-09-10 (revue comparative demandée par Nicolas — Lansweeper/Intune/
endoflife.date) pour remplacer le référentiel figé maintenu à la main par des dates RÉELLES,
tirées de l'API publique endoflife.date (https://endoflife.date/docs/api, ~470 produits,
gratuite, sans clé). Trois volets, dans l'ordre des points de la revue :

1. Système d'exploitation — comparé par NUMÉRO DE BUILD (`os_version`, ex. "10.0.26200") au
   produit unifié "windows" du catalogue (couvre Windows 10 ET 11, par feature update, pas
   seulement les versions majeures définitivement mortes comme l'ancienne liste figée) —
   couvre le risque le plus fréquent aujourd'hui : un poste Windows 10/11 sur une build sortie
   de support alors que l'OS "majeur" reste, lui, encore supporté.
2. .NET Framework — même principe que l'ancien code (extraction du numéro de version depuis le
   nom affiché), mais comparé au produit "dotnetfx" plutôt qu'à une liste de 7 entrées figées.
3. Autres logiciels (`PRODUCT_MAP` ci-dessous) — extension VOLONTAIREMENT PARTIELLE à une
   poignée de logiciels réellement suivis par endoflife.date (confirmé un par un en interrogeant
   l'API avant d'écrire ce fichier — beaucoup d'applications de bureau courantes, ex. 7-Zip/VLC/
   Adobe Reader/Microsoft Edge, n'y sont tout simplement PAS répertoriées et ne peuvent donc pas
   être couvertes sans inventer une source de vérité).

`_FALLBACK_*` (bas de fichier) — reprend l'ANCIEN référentiel figé, utilisé UNIQUEMENT si
l'API est injoignable ET qu'aucune réponse n'est encore en cache pour ce produit : ne jamais
perdre une capacité de détection déjà en place à cause d'un simple problème réseau ponctuel.

`detect_eol` ne lève jamais — un inventaire incomplet/inattendu (agent pas encore mis à jour,
API distante en panne) renvoie simplement une liste vide ou partielle plutôt qu'une exception.
"""
import re
from datetime import date, datetime, timezone

import httpx

from common.cache import TTLCache

_ENDOFLIFE_BASE = "https://endoflife.date/api/v1/products"
_HTTP_TIMEOUT = 10.0

# 24h — ce référentiel (dates de fin de support) bouge rarement dans la journée, inutile de le
# refaire à chaque consultation de la page ou passage de la boucle d'alertes (jalon 4).
_releases_cache = TTLCache(ttl_seconds=24 * 3600)

# Au-delà de "déjà EOL", on remonte aussi une échéance PROCHE — répond au point "alerter avant
# l'échéance, pas seulement constater après coup" de la revue comparative (Lansweeper/Intune
# font ça nativement). 90 jours = même ordre de grandeur que les autres seuils d'alerte Vanitas
# déjà en place (VANITAS_ALERT_CERT_WARNING_DAYS).
EOL_UPCOMING_WINDOW_DAYS = 90

# 🔧 Repéré en testant contre la VRAIE API (2026-09-10) : les navigateurs à cycle "evergreen"
# (nouvelle version majeure toutes les 3-4 semaines) ont TOUJOURS un cycle qui expire dans les
# 90 prochains jours — la fenêtre "échéance proche" ci-dessus devient alors du bruit permanent
# ("Chrome expire dans 12 jours" restera vrai indéfiniment tant que le poste reste à jour) au
# lieu d'un signal utile. Pour ces produits, on ne remonte que le cas RÉELLEMENT actionnable :
# déjà EOL (poste resté bloqué sur une vieille version, celui-là mérite d'être vu).
_EVERGREEN_SLUGS = {"chrome", "firefox"}

# Nom affiché (regex, insensible à la casse) → slug endoflife.date. Vérifié un par un contre
# l'API réelle avant d'écrire cette liste (voir la revue comparative du 2026-09-10) — chaque
# entrée est un produit RÉELLEMENT présent dans le catalogue, jamais un slug supposé. Volontai-
# rement partiel : à enrichir au fil de l'eau si un logiciel du parc y apparaît un jour.
PRODUCT_MAP: list[tuple[re.Pattern, str]] = [
    (re.compile(r"Google Chrome", re.IGNORECASE), "chrome"),
    (re.compile(r"Mozilla Firefox|^Firefox\b", re.IGNORECASE), "firefox"),
    (re.compile(r"Node\.js", re.IGNORECASE), "nodejs"),
    (re.compile(r"^PHP\b", re.IGNORECASE), "php"),
    (re.compile(r"MySQL", re.IGNORECASE), "mysql"),
    (re.compile(r"PostgreSQL", re.IGNORECASE), "postgresql"),
    (re.compile(r"Notepad\+\+", re.IGNORECASE), "notepad-plus-plus"),
    # Java — versionnage notoirement irrégulier (ex. "Java 8 Update 411") ; l'extraction ne
    # récupère que le numéro de version MAJEURE, comparaison donc approximative pour les très
    # anciennes distributions — signalé plutôt que caché, même esprit que le rapprochement
    # CVE↔logiciel déjà "volontairement approximatif" ailleurs dans ce projet (anssi.py).
    (re.compile(r"^Java\b|Java\(TM\)|Java SE (Runtime|Development Kit)", re.IGNORECASE), "oracle-jdk"),
]
# Python exclu volontairement de PRODUCT_MAP : le nom affiché ("Python 3.11.5150.0") et le
# format de version au catalogue endoflife.date ("3.11") coïncident bien via `_extract_version`,
# mais Python est presque toujours embarqué DANS un autre logiciel sur un poste bureautique
# (jamais observé comme entrée `apps` autonome sur le parc réel à ce jour) — laissé de côté
# pour ne pas ajouter un appel API pour un cas qui ne s'est encore jamais présenté ; à activer
# si un jour un poste du parc le remonte réellement (juste réajouter la ligne, voir ci-dessus).

_DOTNET_NAME_RE = re.compile(r"\.NET Framework", re.IGNORECASE)
_VERSION_RE = re.compile(r"\d+(?:\.\d+){1,3}")


def _fetch_releases(slug: str) -> list[dict]:
    """`releases` du produit `slug` (endoflife.date API v1), avec cache 24h. Ne lève jamais —
    un souci réseau/API renvoie simplement une liste vide (aucun finding pour ce produit ce
    cycle-ci), jamais une exception qui remonterait jusqu'à `detect_eol`."""
    cached = _releases_cache.get(slug)
    if cached is not None:
        return cached
    try:
        with httpx.Client(
            headers={"User-Agent": "Mozilla/5.0 (compatible; Pandore/1.0; +local security dashboard)"},
            timeout=_HTTP_TIMEOUT,
        ) as client:
            resp = client.get(f"{_ENDOFLIFE_BASE}/{slug}")
            resp.raise_for_status()
            releases = resp.json()["result"]["releases"]
    except Exception:
        return []
    _releases_cache.set(slug, releases)
    return releases


def _extract_version(text: str) -> str | None:
    m = _VERSION_RE.search(text or "")
    return m.group(0) if m else None


def _version_matches_cycle(installed_version: str, cycle_name: str) -> bool:
    """endoflife.date regroupe ses cycles par version MAJEURE (ou majeure.mineure, ex. "129",
    "3.14"), jamais le patch complet réellement installé ("129.0.6668.101") — un cycle
    correspond si ses segments sont un PRÉFIXE EXACT (segment par segment, pas une simple
    comparaison de chaînes) de la version installée."""
    if not installed_version or not cycle_name:
        return False
    installed_parts = installed_version.strip().split(".")
    cycle_parts = cycle_name.strip().split(".")
    if len(installed_parts) < len(cycle_parts):
        return False
    return installed_parts[: len(cycle_parts)] == cycle_parts


def _days_until(eol_from: str | None) -> int | None:
    if not eol_from:
        return None
    try:
        eol_date = date.fromisoformat(eol_from)
    except ValueError:
        return None
    return (eol_date - datetime.now(timezone.utc).date()).days


def _fmt_date_fr(iso_date: str) -> str:
    try:
        d = date.fromisoformat(iso_date)
    except ValueError:
        return iso_date
    return d.strftime("%d/%m/%Y")


def _build_finding(kind: str, name: str, version: str | None, slug: str, release: dict) -> dict | None:
    """`None` si l'échéance n'est ni déjà passée ni assez proche (`EOL_UPCOMING_WINDOW_DAYS`) —
    endoflife.date renvoie des cycles encore largement supportés, pas la peine de les remonter."""
    eol_from = release.get("eolFrom")
    is_eol = bool(release.get("isEol"))
    days = _days_until(eol_from)

    if is_eol:
        message = (
            f"Fin de support depuis le {_fmt_date_fr(eol_from)}"
            if eol_from
            else "Fin de support (date exacte non communiquée par l'éditeur)"
        )
    elif slug not in _EVERGREEN_SLUGS and days is not None and 0 <= days <= EOL_UPCOMING_WINDOW_DAYS:
        message = f"Fin de support dans {days} jour{'s' if days > 1 else ''} ({_fmt_date_fr(eol_from)})"
    else:
        return None

    return {
        "type": kind,
        "name": name,
        "version": version,
        "message": message,
        "eol_date": eol_from,
        "days_until_eol": days,
        "is_eol": is_eol,
        "product_slug": slug,
    }


def _check_dotnet(name: str, raw_version: str | None) -> dict | None:
    version = _extract_version(name) or raw_version
    if not version:
        return None
    releases = _fetch_releases("dotnetfx")
    if not releases:
        return _fallback_dotnet(name, raw_version)
    release = next((r for r in releases if _version_matches_cycle(version, r["name"])), None)
    if release is None:
        return None
    return _build_finding("dotnet", name, version, "dotnetfx", release)


def _check_product_map(name: str, raw_version: str | None) -> dict | None:
    for pattern, slug in PRODUCT_MAP:
        if not pattern.search(name):
            continue
        version = raw_version or _extract_version(name)
        if not version:
            return None
        releases = _fetch_releases(slug)
        if not releases:
            return None  # pas de repli statique pour ces produits (jamais couverts avant)
        release = next((r for r in releases if _version_matches_cycle(version, r["name"])), None)
        if release is None:
            return None
        return _build_finding("software", name, version, slug, release)
    return None


def _check_os(inventory: dict) -> dict | None:
    os_caption = inventory.get("os_caption")
    os_version = inventory.get("os_version")
    if not os_version:
        return _fallback_os(os_caption) if os_caption else None

    releases = _fetch_releases("windows")
    if not releases:
        return _fallback_os(os_caption) if os_caption else None

    candidates = [r for r in releases if (r.get("latest") or {}).get("name") == os_version]
    if not candidates:
        # Build reconnu comme réel mais absent du catalogue (ex. build très récente pas encore
        # référencée) — rien à affirmer plutôt que deviner.
        return None

    # Plusieurs éditions (Entreprise/LTSC vs Grand public/Pro) peuvent partager la MÊME build
    # avec des échéances différentes — on ne connaît pas l'édition exacte de façon fiable depuis
    # `os_caption` (locale variable), donc on retient la plus CONSERVATRICE (échéance la plus
    # proche) : mieux vaut alerter un peu tôt sur un poste LTSC que rater l'échéance réelle d'un
    # poste Pro/Familial, largement majoritaire sur un parc bureautique classique.
    chosen = min(candidates, key=lambda r: r.get("eolFrom") or "9999-12-31")
    return _build_finding("os", os_caption or "Windows", os_version, "windows", chosen)


def detect_eol(inventory: dict) -> list[dict]:
    """Reçoit le JSON déjà renvoyé par `vanitas_client.get_agent_inventory(agent_id)` (au
    minimum `apps: [{name, version, ...}]`, et depuis le volet OS du jalon 2, éventuellement
    `os_caption`/`os_version`) et renvoie la liste des correspondances EOL trouvées :
    `[{type: "dotnet"|"os"|"software", name, version, message, eol_date, days_until_eol,
    is_eol, product_slug}]`."""
    if not isinstance(inventory, dict):
        return []

    findings: list[dict] = []

    for app in inventory.get("apps") or []:
        name = (app or {}).get("name") or ""
        if not name:
            continue
        raw_version = (app or {}).get("version") or None

        if _DOTNET_NAME_RE.search(name):
            finding = _check_dotnet(name, raw_version)
        else:
            finding = _check_product_map(name, raw_version)
        if finding:
            findings.append(finding)

    os_finding = _check_os(inventory)
    if os_finding:
        findings.append(os_finding)

    return findings


# ── Repli si l'API endoflife.date est injoignable (ancien référentiel figé, 2026-09-08) ────
# Binaire, sans date — dégradé mais jamais une perte totale de détection pour une simple panne
# réseau ponctuelle. `_releases_cache` étant partagé par tout le process, un premier appel
# réussi suffit à sortir tous les agents suivants de ce mode dégradé pour les prochaines 24h.

_FALLBACK_KNOWN_EOL_DOTNET: list[tuple[str, str]] = [
    (r"\.NET Framework 4\.5(\.\d+)?(?!\.\d)", "Microsoft .NET Framework 4.5.x — fin de support"),
    (r"\.NET Framework 4\.5\.1", "Microsoft .NET Framework 4.5.1 — fin de support"),
    (r"\.NET Framework 4\.5\.2", "Microsoft .NET Framework 4.5.2 — fin de support"),
    (r"\.NET Framework 4\.6(?!\.\d)", "Microsoft .NET Framework 4.6 — fin de support"),
    (r"\.NET Framework 4\.6\.1", "Microsoft .NET Framework 4.6.1 — fin de support"),
    (r"\.NET Framework 3\.5", "Microsoft .NET Framework 3.5 — fin de support (hors service pack intégré à Windows)"),
    (r"\.NET Framework [12](\.\d+)*", "Microsoft .NET Framework 1.x/2.x — fin de support"),
]
_FALLBACK_KNOWN_EOL_OS: list[tuple[str, str]] = [
    (r"Windows 7", "Windows 7 — fin de support"),
    (r"Windows 8(?!\.1)", "Windows 8 — fin de support"),
    (r"Windows 8\.1", "Windows 8.1 — fin de support"),
    (r"Windows Vista", "Windows Vista — fin de support"),
    (r"Windows XP", "Windows XP — fin de support"),
    (r"Windows Server 2008(?! R2)", "Windows Server 2008 — fin de support"),
    (r"Windows Server 2008 R2", "Windows Server 2008 R2 — fin de support"),
    (r"Windows Server 2012(?! R2)", "Windows Server 2012 — fin de support"),
]
_COMPILED_FALLBACK_DOTNET = [(re.compile(p, re.IGNORECASE), m) for p, m in _FALLBACK_KNOWN_EOL_DOTNET]
_COMPILED_FALLBACK_OS = [(re.compile(p, re.IGNORECASE), m) for p, m in _FALLBACK_KNOWN_EOL_OS]


def _fallback_dotnet(name: str, raw_version: str | None) -> dict | None:
    for pattern, message in _COMPILED_FALLBACK_DOTNET:
        if pattern.search(name):
            return {
                "type": "dotnet",
                "name": name,
                "version": raw_version,
                "message": message + " (référentiel de secours, API endoflife.date injoignable)",
                "eol_date": None,
                "days_until_eol": None,
                "is_eol": True,
                "product_slug": None,
            }
    return None


def _fallback_os(os_caption: str) -> dict | None:
    for pattern, message in _COMPILED_FALLBACK_OS:
        if pattern.search(os_caption):
            return {
                "type": "os",
                "name": os_caption,
                "version": None,
                "message": message + " (référentiel de secours, API endoflife.date injoignable)",
                "eol_date": None,
                "days_until_eol": None,
                "is_eol": True,
                "product_slug": None,
            }
    return None
