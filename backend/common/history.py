"""
Historique quotidien de quelques métriques agrégées (taux de conformité Intune, exposure
score Defender, effectifs) — pour tracer une tendance dans le temps plutôt que de ne voir
que l'instantané actuel du dashboard (demande de Nicolas, 2026-08-18).

Comblait un manque déjà identifié : `defender/vulnerabilities.py::get_exposure_score`
documente depuis la revue d'architecture du 2026-08-17 que MDE n'expose "pas d'historique
côté API (seul le point courant est exposé) — voir README pour la persistance côté
dashboard si besoin d'une courbe de tendance", et le README listait justement "Persister
l'historique (exposure score, snapshots de recommandations)" en évolution possible. C'est
cette persistance-là.

Stockage : un simple fichier JSON local (HISTORY_FILE), même choix que
`defender/watchlist.py` pour un outil mono-poste/mono-utilisateur — pas de base de données.
Un verrou en mémoire (threading.Lock) protège contre une écriture concurrente entre la
boucle de fond (api_server.py::_history_snapshot_loop) et une éventuelle requête REST
simultanée.

Un point par jour CALENDAIRE (heure locale du poste), au maximum : si le backend tourne
plusieurs fois dans la même journée, seul le premier passage de la boucle de fond après
minuit calcule un nouveau point ; les suivants le trouvent déjà présent (`has_snapshot_today`)
et ne font rien. `record_snapshot` est malgré tout idempotent pour la journée en cours (un
second appel le même jour REMPLACE le point du jour plutôt que d'en créer un doublon) — au
cas où la boucle de fond serait un jour appelée plus d'une fois par jour délibérément. Si le
backend n'est jamais lancé un jour donné (Nicolas n'ouvre pas le dashboard), ce jour-là n'a
simplement aucun point — pas de tentative de rattrapage a posteriori, un point manquant se
lit juste comme un trou dans la courbe côté frontend.

Rétention : 90 jours glissants, même ordre de grandeur que l'historique natif du Secure
Score Graph (/security/secureScores, 90 jours max) — élagué à chaque écriture.
"""
import json
import threading
from datetime import date, timedelta

from common.atomic_io import atomic_write_text
from common.config import BACKEND_DIR
from common.http_client import handle_tool_errors

HISTORY_FILE = BACKEND_DIR / "data" / "history.json"
HISTORY_FILE.parent.mkdir(exist_ok=True)
RETENTION_DAYS = 90

_lock = threading.Lock()


def _read_raw() -> list[dict]:
    if not HISTORY_FILE.exists():
        return []
    try:
        return json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        # Fichier corrompu/tronqué (écriture interrompue) — repartir d'un historique vide
        # plutôt que de faire planter le dashboard sur un GET aussi anodin qu'une courbe de
        # tendance. Perte de l'historique dans ce cas, mais un 500 systématique serait pire
        # — même compromis assumé que defender/watchlist.py::_read_raw.
        return []


def _write_raw(entries: list[dict]) -> None:
    # Écriture atomique (fichier temporaire + renommage, voir common/atomic_io.py) depuis la
    # revue de code du 2026-08-20 : un `write_text` direct laisse une fenêtre où un crash/kill
    # du process pendant l'écriture tronque le fichier — le `_read_raw` suivant tombe alors sur
    # le fallback "historique vide" documenté ci-dessus, perdant silencieusement jusqu'à 90
    # jours d'historique pour un simple mauvais timing, pas une vraie corruption de données.
    atomic_write_text(HISTORY_FILE, json.dumps(entries, ensure_ascii=False, indent=2))


def _prune(entries: list[dict]) -> list[dict]:
    cutoff = (date.today() - timedelta(days=RETENTION_DAYS)).isoformat()
    return [e for e in entries if e.get("date", "") >= cutoff]


# Formule du taux de conformité Intune stocké dans les points (2026-10-21) : "compliant-only" =
# appareils `compliant` / total (voir intune/devices.py::get_intune_summary). Les points plus
# anciens n'ont pas ce marqueur : ils utilisaient `(total - noncompliant) / total`, qui comptait
# les appareils en période de grâce et inconnus comme conformes.
COMPLIANCE_RATE_RULE = "compliant-only"


def _with_comparable_compliance_rate(entry: dict) -> dict:
    """Écarte (à la LECTURE, le fichier n'est jamais réécrit) le taux de conformité Intune des
    points calculés avec l'ancienne formule : comparer 85,5 % (strict) à 86,3 % (indulgent)
    afficherait une baisse qui n'existe pas. Les autres champs du point restent intacts."""
    intune = entry.get("intune")
    if isinstance(intune, dict) and intune.get("complianceRateRule") != COMPLIANCE_RATE_RULE and "complianceRate" in intune:
        return {**entry, "intune": {**intune, "complianceRate": None}}
    return entry


@handle_tool_errors
def get_history() -> list[dict]:
    """Historique quotidien complet (jusqu'à RETENTION_DAYS jours), trié du plus ancien au
    plus récent — ordre pratique pour tracer une courbe directement côté frontend sans tri
    supplémentaire côté client."""
    with _lock:
        return [_with_comparable_compliance_rate(e) for e in sorted(_read_raw(), key=lambda e: e.get("date", ""))]


def has_snapshot_today() -> bool:
    """Vrai si un point (même partiel) existe pour aujourd'hui."""
    today = date.today().isoformat()
    with _lock:
        return any(e.get("date") == today for e in _read_raw())


def has_complete_snapshot_today() -> bool:
    """Utilisé par la boucle de fond (api_server.py) : vrai seulement si le point du jour
    existe ET couvre Intune et Defender. Un point partiel (domaine en erreur au moment du
    calcul) est retenté au tour suivant au lieu de bloquer la journée. Vanitas n'est pas exigé :
    un serveur Vanitas volontairement absent ferait recalculer le point toutes les heures."""
    today = date.today().isoformat()
    with _lock:
        return any(
            e.get("date") == today and e.get("intune") is not None and e.get("defender") is not None
            for e in _read_raw()
        )


def record_snapshot(
    intune_point: dict | None, defender_point: dict | None, vanitas_point: dict | None = None
) -> None:
    """Enregistre le point du jour — remplace un éventuel point déjà présent pour
    AUJOURD'HUI seulement (idempotent si rappelé plusieurs fois le même jour), ne touche
    jamais aux jours précédents. `intune_point`/`defender_point`/`vanitas_point` peuvent être
    `None` si ce domaine était en erreur au moment du snapshot (permission manquante, backend
    Graph/MDE/Vanitas indisponible) — mieux vaut un point partiel qui ne couvre qu'un des trois
    domaines que pas de point du tout ce jour-là.

    `vanitas_point` (2026-09-17, jalon "tendances Vanitas") — 3ᵉ domaine, même mécanisme/stockage/
    rétention que les deux autres. Ajouté en paramètre OPTIONNEL en queue pour que les entrées
    d'historique antérieures à ce jalon (sans clé `vanitas`) restent lisibles telles quelles : un
    jour ancien sans `vanitas` se lit juste comme un trou en début de courbe côté frontend."""
    today = date.today().isoformat()
    entry = {"date": today, "intune": intune_point, "defender": defender_point, "vanitas": vanitas_point}
    with _lock:
        entries = [e for e in _read_raw() if e.get("date") != today]
        entries.append(entry)
        _write_raw(_prune(entries))
