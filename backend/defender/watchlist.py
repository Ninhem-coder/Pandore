"""
Persistance + rafraîchissement automatique des CVE "suivies" — backend de l'onglet
"Suivi CVE" du dashboard (sous-catégorie Defender > Vulnérabilité, CveWatchTab.jsx).

Remplace la maquette 100% frontend du 2026-08-10 (liste `MOCK_WATCHED_CVES` codée en dur,
ajout/suppression perdus au rechargement) par un vrai stockage disque et une
re-vérification automatique périodique — demande explicite de Nicolas ("vraie fonctionnalité
complète").

Stockage : un simple fichier JSON local (WATCHLIST_FILE), pas une base de données — même
choix que TOKEN_CACHE_DIR (common/config.py) pour un outil mono-poste/mono-utilisateur, sans
accès concurrent multi-client à gérer. Un verrou en mémoire (threading.Lock) protège
seulement contre une écriture concurrente entre une requête HTTP (ajout/suppression) et la
boucle de rafraîchissement de fond (api_server.py::_watchlist_refresh_loop), qui tournent
dans le même process mais pas le même thread — pas un verrou de fichier multi-process, donc
volontairement pas prévu pour plusieurs instances de `api_server.py` sur la même machine.
"""
import json
import threading
from datetime import datetime, timezone

from common.atomic_io import atomic_write_text
from common.config import BACKEND_DIR
from common.http_client import handle_tool_errors, tool_error
from defender.vulnerabilities import _CVE_PATTERN, search_vulnerabilities

WATCHLIST_FILE = BACKEND_DIR / "data" / "watched_cves.json"
WATCHLIST_FILE.parent.mkdir(exist_ok=True)

_lock = threading.Lock()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_raw() -> list[dict]:
    if not WATCHLIST_FILE.exists():
        return []
    try:
        return json.loads(WATCHLIST_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        # Fichier corrompu/tronqué (ex. écriture interrompue) — repartir d'une liste vide
        # plutôt que de faire planter TOUTE l'API sur un GET aussi anodin que la liste de
        # suivi. Nicolas perd sa liste dans ce cas, mais peut la reconstituer en quelques
        # clics ; un 500 sur chaque chargement du dashboard serait pire.
        return []


def _write_raw(entries: list[dict]) -> None:
    # Écriture atomique (fichier temporaire + renommage, voir common/atomic_io.py) depuis la
    # revue de code du 2026-08-20 : un `write_text` direct laisse une fenêtre où un crash/kill
    # du process pendant l'écriture tronque le fichier — le `_read_raw` suivant tombe alors sur
    # le fallback "liste vide" documenté ci-dessus pour un simple mauvais timing, pas une
    # vraie corruption de données.
    atomic_write_text(WATCHLIST_FILE, json.dumps(entries, ensure_ascii=False, indent=2))


@handle_tool_errors
def list_watched_cves() -> list[dict]:
    """Liste des CVE suivies, avec leur dernier résultat connu (`result` peut être `None` si
    jamais rafraîchie avec succès, ex. juste après un redémarrage backend avant le premier
    cycle). Ordre : plus récemment ajoutée en premier."""
    with _lock:
        return _read_raw()


@handle_tool_errors
def add_watched_cve(cve_code: str) -> dict:
    """Ajoute une CVE au suivi (idempotent — renvoie l'entrée existante si déjà suivie, sans
    la dupliquer ni relancer une vérification) et lance immédiatement une première
    vérification pour une CVE réellement nouvelle, pour que Nicolas voie tout de suite un
    résultat plutôt que d'attendre le prochain passage de la boucle de fond (jusqu'à
    WATCHLIST_REFRESH_SECONDS, 1h par défaut)."""
    cve_code = (cve_code or "").strip().upper()
    if not _CVE_PATTERN.match(cve_code):
        return tool_error(
            f"« {cve_code} » ne ressemble pas à un identifiant CVE valide (format attendu : CVE-2024-3400).",
            "ValidationError",
        )

    with _lock:
        entries = _read_raw()
        existing = next((e for e in entries if e["cve_code"] == cve_code), None)
        if existing:
            return existing
        entry = {
            "cve_code": cve_code,
            "added_at": _now_iso(),
            "last_checked": None,
            "last_error": None,
            "result": None,
        }
        entries.insert(0, entry)
        _write_raw(entries)

    _refresh_one(cve_code)
    with _lock:
        entries = _read_raw()
        return next((e for e in entries if e["cve_code"] == cve_code), entry)


@handle_tool_errors
def remove_watched_cve(cve_code: str) -> bool:
    """Retire une CVE du suivi. Renvoie `False` (pas une erreur) si elle n'y était déjà
    plus — un double-clic sur "ne plus suivre" ou un appel répété ne doit pas être traité
    comme un échec côté frontend."""
    cve_code = (cve_code or "").strip().upper()
    with _lock:
        entries = _read_raw()
        remaining = [e for e in entries if e["cve_code"] != cve_code]
        removed = len(remaining) != len(entries)
        if removed:
            _write_raw(remaining)
        return removed


def _refresh_one(cve_code: str) -> None:
    """Relance search_vulnerabilities pour UNE CVE suivie et met à jour son entrée en place
    sur disque. Ne renvoie rien : appelée soit juste après add_watched_cve (résultat relu
    ensuite depuis le fichier), soit par refresh_all_watched_cves (boucle de fond) — dans les
    deux cas c'est l'entrée persistée qui fait foi, pas une valeur de retour intermédiaire."""
    # search_vulnerabilities est déjà @handle_tool_errors (ne lève jamais), le try/except
    # ici est un filet supplémentaire pour ne jamais laisser une exception remonter jusqu'à
    # la boucle de fond et l'interrompre définitivement.
    try:
        results = search_vulnerabilities(query=cve_code, max_results=1)
    except Exception as e:
        results = [tool_error(f"Échec inattendu de la vérification : {e}")]

    if results and isinstance(results[0], dict) and results[0].get("error"):
        update = {"last_checked": _now_iso(), "last_error": results[0]["message"]}
    elif results:
        update = {"last_checked": _now_iso(), "last_error": None, "result": results[0]}
    else:
        # Liste vide : la CVE ne matche plus aucun device exposé (corrigée sur tout le parc,
        # ou jamais trouvée) — CE N'EST PAS une erreur ici, contrairement à la recherche
        # ponctuelle (VulnerabilitiesTab.jsx) où un résultat vide affiche juste "aucune
        # vulnérabilité trouvée". Dans le suivi, il faut explicitement remettre `result` à un
        # état "0 device exposé" plutôt que de garder affiché le dernier résultat positif
        # périmé comme si la vérification n'avait pas eu lieu.
        update = {
            "last_checked": _now_iso(),
            "last_error": None,
            "result": {"cve_code": cve_code, "affected_count": 0, "devices": []},
        }

    with _lock:
        entries = _read_raw()
        for e in entries:
            if e["cve_code"] == cve_code:
                e.update(update)
                break
        _write_raw(entries)


@handle_tool_errors
def refresh_one(cve_code: str) -> dict:
    """Version "publique" de _refresh_one, pour le bouton "vérifier maintenant" de l'API
    REST (POST /api/defender/watched-cves/{cve_code}/refresh) : relance la vérification ET
    renvoie l'entrée mise à jour, plutôt que None. Renvoie une erreur structurée (pas une
    exception) si la CVE demandée n'est pas/plus dans la liste de suivi.

    Vérifie l'existence deux fois (avant ET après _refresh_one, qui peut prendre plusieurs
    secondes — appel Advanced Hunting) plutôt qu'une seule : la CVE peut avoir été retirée
    du suivi (DELETE déclenché depuis un autre onglet, ou par la boucle de fond) PENDANT la
    vérification. Sans ce second contrôle, la relecture finale pouvait lever `StopIteration`
    non capturée (revue de code du 2026-08-18) — @handle_tool_errors l'aurait rattrapée en
    dernier recours, mais avec un type d'erreur générique au lieu du NotFoundError explicite
    que cette fonction promet déjà pour le cas "jamais suivie"."""
    cve_code = (cve_code or "").strip().upper()
    if not any(e["cve_code"] == cve_code for e in list_watched_cves()):
        return tool_error(f"« {cve_code} » n'est pas dans la liste de suivi.", "NotFoundError")
    _refresh_one(cve_code)
    updated = next((e for e in list_watched_cves() if e["cve_code"] == cve_code), None)
    if updated is None:
        return tool_error(
            f"« {cve_code} » a été retirée de la liste de suivi pendant sa vérification.",
            "NotFoundError",
        )
    return updated


@handle_tool_errors
def refresh_all_watched_cves() -> None:
    """Rafraîchit toutes les CVE suivies l'une après l'autre — appelée par la boucle de fond
    (api_server.py::_watchlist_refresh_loop). Séquentiel plutôt que parallèle (contrairement
    à intune/tools.py::get_compliance_detail, qui parallélise sur des centaines de devices) :
    le nombre de CVE suivies reste attendu comme faible (quelques dizaines au grand maximum),
    et le séquentiel évite de multiplier les requêtes Advanced Hunting simultanées sur le
    même tenant MDE pour un gain de temps négligeable ici."""
    for entry in list_watched_cves():
        _refresh_one(entry["cve_code"])
