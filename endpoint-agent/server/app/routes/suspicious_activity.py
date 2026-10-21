"""Activités suspectes — jalon "détection comportementale sur les postes".

Deux familles de routes, même découpage que `routes/compliance.py`/`routes/shell.py` :
- Côté AGENT (`/agents/{agent_id}/suspicious-events`, `/agents/{agent_id}/suspicious-rules`) —
  mTLS via `get_current_agent`. L'ingestion est un batch IDEMPOTENT sur `(agent_id,
  local_event_id)` : le filtrage des événements est déjà fait côté agent (moteur de règles
  local), ce serveur ne fait que déposer ce qui matche déjà une règle, sans jamais dupliquer un
  lot rejoué après un timeout réseau (voir `SuspiciousEvent` dans `models.py`).
- Côté DASHBOARD (`require_shell_token`, même secret partagé que le reste des routes
  dashboard-facing sensibles) — liste filtrable/détail/triage/synthèse pour l'onglet "Activités
  suspectes". `PUT .../suspicious-events/{id}` valide les transitions de statut plutôt que
  d'accepter n'importe quelle valeur : `new` → `acknowledged`/`false_positive`/`escalated`,
  `acknowledged` → `false_positive`/`escalated` — `false_positive`/`escalated` sont terminaux.
"""
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Agent, SuspiciousEvent
from ..security import get_actor, get_current_agent, require_shell_token

router = APIRouter(tags=["suspicious-activity"])

# Jeu de règles par défaut (V1, pas encore d'UI d'édition — voir le plan du jalon) : un fichier
# de config statique servi tel quel, PAS stocké en DB. Chemin ABSOLU (comme `db.py::init_db`) —
# le répertoire de travail au moment d'une requête n'est pas garanti être `server/`.
_DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent / "suspicious_rules_default.json"

# Cycle de vie de `SuspiciousEvent.status` — voir la docstring du modèle pour le raisonnement.
# `false_positive`/`escalated` sont terminaux (aucune clé dans cette table = aucune transition
# sortante autorisée).
_ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    "new": {"acknowledged", "false_positive", "escalated"},
    "acknowledged": {"false_positive", "escalated"},
}


# ── Côté agent (mTLS) ────────────────────────────────────────────────────────────────────────


class SuspiciousEventIn(BaseModel):
    local_event_id: str
    occurred_at: datetime
    signal_type: Literal["process", "event_log", "network", "usb"]
    severity: Literal["low", "med", "high"]
    matched_rule: str
    summary: str
    detail: dict[str, Any] | None = None


class SuspiciousEventsIn(BaseModel):
    events: list[SuspiciousEventIn]


class IngestSuspiciousEventsOut(BaseModel):
    ok: bool
    inserted: int
    skipped: int


@router.post("/agents/{agent_id}/suspicious-events", response_model=IngestSuspiciousEventsOut)
def post_suspicious_events(
    agent_id: str,
    payload: SuspiciousEventsIn,
    agent: Agent = Depends(get_current_agent),
    db: Session = Depends(get_db),
) -> IngestSuspiciousEventsOut:
    if agent.id != agent_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Ce certificat ne correspond pas à cet agent.")

    if not payload.events:
        return IngestSuspiciousEventsOut(ok=True, inserted=0, skipped=0)

    local_ids = [e.local_event_id for e in payload.events]
    already_known: set[str] = {
        row[0]
        for row in db.query(SuspiciousEvent.local_event_id)
        .filter(SuspiciousEvent.agent_id == agent_id, SuspiciousEvent.local_event_id.in_(local_ids))
        .all()
    }

    inserted = 0
    for e in payload.events:
        # Skip silencieux — un replay du même lot après un timeout réseau ne doit RIEN dupliquer
        # ni renvoyer d'erreur (voir docstring `SuspiciousEvent`). `already_known` est mis à jour
        # au fil de la boucle pour couvrir aussi un doublon interne AU MÊME lot (agent bugué/
        # buffer disque relu deux fois), pas seulement un doublon contre ce qui est déjà en base.
        if e.local_event_id in already_known:
            continue
        db.add(
            SuspiciousEvent(
                agent_id=agent_id,
                hostname=agent.hostname,
                signal_type=e.signal_type,
                severity=e.severity,
                matched_rule=e.matched_rule,
                summary=e.summary,
                detail=json.dumps(e.detail) if e.detail is not None else None,
                local_event_id=e.local_event_id,
                occurred_at=e.occurred_at,
            )
        )
        already_known.add(e.local_event_id)
        inserted += 1

    db.commit()
    return IngestSuspiciousEventsOut(ok=True, inserted=inserted, skipped=len(payload.events) - inserted)


@router.get("/agents/{agent_id}/suspicious-rules")
def get_suspicious_rules(
    agent_id: str,
    agent: Agent = Depends(get_current_agent),
) -> dict:
    """Sert le fichier de config tel quel — pas de modèle Pydantic dédié : ce jalon n'a
    volontairement aucune UI d'édition, le schéma est celui du fichier `suspicious_rules_
    default.json` (voir le plan), lu à la demande pour qu'une édition manuelle du fichier soit
    visible sans redémarrer ce serveur."""
    if agent.id != agent_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Ce certificat ne correspond pas à cet agent.")

    with _DEFAULT_RULES_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


# ── Côté dashboard (secret partagé) ──────────────────────────────────────────────────────────


class SuspiciousEventOut(BaseModel):
    id: str
    agent_id: str
    hostname: str
    signal_type: str
    severity: str
    matched_rule: str
    summary: str
    local_event_id: str
    occurred_at: datetime
    received_at: datetime
    status: str
    handled_by: str | None
    handled_at: datetime | None
    handled_note: str | None


def _to_out(e: SuspiciousEvent) -> SuspiciousEventOut:
    return SuspiciousEventOut(
        id=e.id,
        agent_id=e.agent_id,
        hostname=e.hostname,
        signal_type=e.signal_type,
        severity=e.severity,
        matched_rule=e.matched_rule,
        summary=e.summary,
        local_event_id=e.local_event_id,
        occurred_at=e.occurred_at,
        received_at=e.received_at,
        status=e.status,
        handled_by=e.handled_by,
        handled_at=e.handled_at,
        handled_note=e.handled_note,
    )


@router.get(
    "/suspicious-events",
    response_model=list[SuspiciousEventOut],
    dependencies=[Depends(require_shell_token)],
)
def list_suspicious_events(
    agent_id: str | None = None,
    signal_type: str | None = None,
    severity: str | None = None,
    status_: str | None = Query(default=None, alias="status"),
    since: datetime | None = None,
    # "Alertes précédentes" (jalon "confinement", 2026-09-17) — borne haute pour reconstituer la
    # fenêtre [alerte_principale - 3h, alerte_principale[ sans dépendre d'un filtrage client sur
    # une liste potentiellement plus large (`since` seul renverrait aussi les événements
    # POSTÉRIEURS à l'alerte principale, y compris elle-même).
    until: datetime | None = None,
    db: Session = Depends(get_db),
) -> list[SuspiciousEventOut]:
    """`status_` (pas `status`, mot réservé du module `fastapi.status` déjà importé partout dans
    ce fichier) — `alias="status"` fait que le paramètre de query REÇU reste bien `?status=...`
    côté appelant, seul le nom Python interne diffère."""
    query = db.query(SuspiciousEvent)
    if agent_id is not None:
        query = query.filter(SuspiciousEvent.agent_id == agent_id)
    if signal_type is not None:
        query = query.filter(SuspiciousEvent.signal_type == signal_type)
    if severity is not None:
        query = query.filter(SuspiciousEvent.severity == severity)
    if status_ is not None:
        query = query.filter(SuspiciousEvent.status == status_)
    if since is not None:
        query = query.filter(SuspiciousEvent.occurred_at >= since)
    if until is not None:
        query = query.filter(SuspiciousEvent.occurred_at < until)

    events = query.order_by(SuspiciousEvent.occurred_at.desc()).all()
    return [_to_out(e) for e in events]


class SuspiciousEventDetailOut(SuspiciousEventOut):
    detail: dict[str, Any] | None


@router.get(
    "/suspicious-events/summary",
    dependencies=[Depends(require_shell_token)],
)
def get_suspicious_events_summary(db: Session = Depends(get_db)) -> dict:
    """Comptage global (pas de filtre — la tuile KPI porte sur tout le parc) par sévérité et par
    statut, pour la tuile "N événements non traités" du plan. Déclarée AVANT la route
    paramétrée `/suspicious-events/{event_id}` ci-dessous : FastAPI résout les routes dans
    l'ordre de déclaration, `summary` matcherait sinon `{event_id}` en premier."""
    by_severity: dict[str, int] = {}
    by_status: dict[str, int] = {}

    for row in db.query(SuspiciousEvent.severity).all():
        by_severity[row[0]] = by_severity.get(row[0], 0) + 1
    for row in db.query(SuspiciousEvent.status).all():
        by_status[row[0]] = by_status.get(row[0], 0) + 1

    return {"by_severity": by_severity, "by_status": by_status}


@router.get(
    "/suspicious-events/{event_id}",
    response_model=SuspiciousEventDetailOut,
    dependencies=[Depends(require_shell_token)],
)
def get_suspicious_event(event_id: str, db: Session = Depends(get_db)) -> SuspiciousEventDetailOut:
    event = db.get(SuspiciousEvent, event_id)
    if event is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Événement introuvable.")

    return SuspiciousEventDetailOut(
        **_to_out(event).model_dump(),
        detail=json.loads(event.detail) if event.detail else None,
    )


class UpdateSuspiciousEventIn(BaseModel):
    status: Literal["acknowledged", "false_positive", "escalated"]
    note: str | None = None


@router.put(
    "/suspicious-events/{event_id}",
    response_model=SuspiciousEventOut,
    dependencies=[Depends(require_shell_token)],
)
def update_suspicious_event(
    event_id: str,
    payload: UpdateSuspiciousEventIn,
    db: Session = Depends(get_db),
    actor: str | None = Depends(get_actor),
) -> SuspiciousEventOut:
    event = db.get(SuspiciousEvent, event_id)
    if event is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Événement introuvable.")

    allowed = _ALLOWED_TRANSITIONS.get(event.status, set())
    if payload.status not in allowed:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Transition invalide : {event.status!r} -> {payload.status!r}.",
        )

    event.status = payload.status
    event.handled_by = actor
    event.handled_at = datetime.now(timezone.utc)
    if payload.note is not None:
        event.handled_note = payload.note

    db.commit()
    db.refresh(event)
    return _to_out(event)
