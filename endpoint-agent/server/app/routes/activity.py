"""Journal d'activité unifié (2026-09-09, demande de Nicolas — "changer Commandes en onglet de
Log pour chaque action... qui a créé quoi").

Fusionne à la LECTURE deux sources qui gardent chacune leur propre table/contrat :
- `AgentCommand` (jalon 4) — ce qui a été envoyé à un poste (catégorie "poste" toujours).
- `AuditEvent` (2026-09-09, `../audit.py`) — les mutations admin sur les catalogues (règles de
  conformité, installeurs, groupes).

Pas de nouvelle table de fusion : les deux sources ont des cycles de vie et des volumes de
purge différents (voir `routes/maintenance.py`), les recombiner à chaque lecture reste bon
marché à l'échelle de ce projet (quelques centaines de lignes au total).

`completed_at`/`parameters` ajoutés le 2026-09-09 (popup de détail complet côté dashboard,
demande de Nicolas — "on n'a pas plus de détail ?") : les deux existaient déjà sur
`AgentCommand` mais n'étaient exposés nulle part. Concept propre aux commandes (un début ET
une fin) — toujours `None` pour une entrée "audit" (mutation instantanée sur un catalogue),
jamais un "—" qui inviterait à se demander pourquoi c'est vide."""
import json
from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Agent, AgentCommand, AuditEvent
from ..security import require_shell_token

router = APIRouter(tags=["activity"])


class ActivityEntryOut(BaseModel):
    id: str
    source: str  # "command" | "audit"
    category: str
    actor: str | None
    action: str
    target_label: str
    detail: str | None
    outcome: str | None  # "ok" | "fail" | "pending" | None — toujours `None` pour une entrée "audit"
    created_at: datetime
    completed_at: datetime | None = None
    parameters: dict | None = None


def _command_outcome(command: AgentCommand) -> str | None:
    if command.status in ("pending", "running"):
        return "pending"
    if command.success is None:
        return None
    return "ok" if command.success else "fail"


def _command_parameters(command: AgentCommand) -> dict | None:
    """`AgentCommand.parameters` est un JSON brut sérialisé par l'appelant (queue_command.py,
    `build_install_parameters` pour install_application) — la plupart des types de commande
    n'en ont pas (`None`). Parsing défensif : un JSON corrompu ne doit jamais faire échouer
    toute la lecture du journal, seulement faire disparaître cette section du popup."""
    if not command.parameters:
        return None
    try:
        parsed = json.loads(command.parameters)
    except (json.JSONDecodeError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


@router.get(
    "/activity-log", response_model=list[ActivityEntryOut], dependencies=[Depends(require_shell_token)]
)
def list_activity_log(db: Session = Depends(get_db)) -> list[ActivityEntryOut]:
    entries: list[ActivityEntryOut] = []

    command_rows = db.query(AgentCommand, Agent.hostname).join(Agent, Agent.id == AgentCommand.agent_id).all()
    for command, hostname in command_rows:
        entries.append(
            ActivityEntryOut(
                id=f"command-{command.id}",
                source="command",
                category="poste",
                actor=command.actor,
                action=command.command_type,
                target_label=hostname,
                detail=command.result,
                outcome=_command_outcome(command),
                created_at=command.created_at,
                completed_at=command.completed_at,
                parameters=_command_parameters(command),
            )
        )

    for event in db.query(AuditEvent).all():
        entries.append(
            ActivityEntryOut(
                id=f"audit-{event.id}",
                source="audit",
                category=event.category,
                actor=event.actor,
                action=event.action,
                target_label=event.target_label,
                detail=event.detail,
                outcome=None,
                created_at=event.created_at,
            )
        )

    entries.sort(key=lambda e: e.created_at, reverse=True)
    return entries
