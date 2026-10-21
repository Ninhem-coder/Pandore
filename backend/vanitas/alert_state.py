"""
État persistant des alertes Vanitas (agent silencieux, nouvelle vulnérabilité critique, nouvel
échec de conformité) — jalons du 2026-09-08. Même motif que `defender/watchlist.py` : un
fichier JSON local + `threading.Lock()` + écriture atomique (`common/atomic_io.py`), pas de
base de données pour un besoin aussi petit (une poignée d'agents, projet personnel).

Le fichier est gitignoré : c'est un état PUREMENT DÉRIVÉ (recalculable depuis les données
Vanitas/Graph si perdu), comme `app_name_cache.json` — pas une donnée d'intention utilisateur
comme `app_library.json`.

Deux rôles dans un seul fichier :
- `agents.<agent_id>` : dernier état connu par agent (`stale_alerted`, `cert_alerted`,
  `known_critical_cves`, `known_failing_rules`), pour ne notifier que sur une TRANSITION
  (front montant) — jamais un rappel à chaque cycle tant qu'une situation reste inchangée.
- `recent` : journal borné (50 dernières entrées) des alertes déclenchées, indépendant du
  succès/échec de l'envoi d'email — c'est la source de la liste "Alertes récentes" de
  "Vue d'ensemble" (Vanitas), qui reste la SEULE surface visible tant que le SMTP n'est pas
  configuré (décision explicite de Nicolas : email choisi comme canal, mais pas configuré pour
  l'instant).
"""
import json
import threading
from datetime import datetime, timezone

from common.atomic_io import atomic_write_text
from common.config import BACKEND_DIR

ALERT_STATE_FILE = BACKEND_DIR / "data" / "vanitas_alert_state.json"
ALERT_STATE_FILE.parent.mkdir(exist_ok=True)

_MAX_RECENT = 50

_lock = threading.Lock()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_raw() -> dict:
    if not ALERT_STATE_FILE.exists():
        return {"agents": {}, "recent": []}
    try:
        data = json.loads(ALERT_STATE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        # Même politique que watchlist.py : un fichier corrompu/tronqué (écriture interrompue)
        # repart d'un état vide plutôt que de faire planter les boucles de fond qui en dépendent
        # — c'est de l'état dérivé, aucune perte de données réelle.
        return {"agents": {}, "recent": []}
    data.setdefault("agents", {})
    data.setdefault("recent", [])
    return data


def _write_raw(data: dict) -> None:
    atomic_write_text(ALERT_STATE_FILE, json.dumps(data, ensure_ascii=False, indent=2))


def get_agent_state(agent_id: str) -> dict:
    """État connu pour un agent — jamais `None` : un agent jamais vu renvoie l'état par défaut
    (pas encore signalé silencieux, aucune CVE/règle connue)."""
    with _lock:
        data = _read_raw()
        return data["agents"].get(
            agent_id,
            {
                "stale_alerted": False,
                # cert_alerted (2026-09-08) — même garde-fou anti-spam que stale_alerted,
                # pour l'alerte d'expiration de certificat (_vanitas_agent_health_loop).
                "cert_alerted": False,
                "known_critical_cves": [],
                "known_failing_rules": [],
            },
        )


def set_agent_state(agent_id: str, **fields) -> None:
    """Fusionne `fields` dans l'état existant de `agent_id` (jamais un remplacement complet —
    les 3 champs du jalon 1/3 sont mis à jour indépendamment selon la boucle appelante)."""
    with _lock:
        data = _read_raw()
        current = data["agents"].get(
            agent_id, {"stale_alerted": False, "known_critical_cves": [], "known_failing_rules": []}
        )
        current.update(fields)
        data["agents"][agent_id] = current
        _write_raw(data)


def record_event(event_type: str, agent_id: str, hostname: str, message: str) -> None:
    """Ajoute une entrée au journal `recent`, tronqué aux `_MAX_RECENT` plus récentes. Appelée
    à CHAQUE déclenchement d'alerte, que `notify.send_email` réussisse ou non — le journal ne
    doit jamais dépendre du succès de l'envoi (voir docstring du module)."""
    with _lock:
        data = _read_raw()
        data["recent"].insert(
            0,
            {
                "type": event_type,
                "agent_id": agent_id,
                "hostname": hostname,
                "message": message,
                "at": _now_iso(),
            },
        )
        data["recent"] = data["recent"][:_MAX_RECENT]
        _write_raw(data)


def list_recent(limit: int = 20) -> list[dict]:
    with _lock:
        data = _read_raw()
        return data["recent"][:limit]
