"""Terminal PowerShell interactif — jalon 9.

Deux familles de routes bien séparées :
- Côté AGENT (`/agents/{agent_id}/shell/...`) — mTLS via `get_current_agent`, exactement le
  même mécanisme que le canal de commande fermé (`routes/commands.py`). Ce sont des requêtes
  HTTP normales, jamais un websocket — aucun risque avec le monkeypatch ASGI dont dépend
  `get_current_agent` (voir security.py), qui suppose un scope `"http"`.
- Côté DASHBOARD (`/shell/sessions/{session_id}/...`) — protégées par `require_shell_token`
  (secret partagé, `X-Shell-Token`), au-delà du modèle "loopback uniquement" qui suffit pour le
  reste de Vanitas : une session ouverte permet d'observer/piloter une exécution de code niveau
  SYSTEM, pas juste lire un inventaire ou lancer une commande du catalogue fermé.

`ShellSessionEvent` sert À LA FOIS de file de relais (l'agent ne récupère que les entrées
d'id > `last_delivered_input_id`) ET de journal d'audit permanent (rien n'est jamais purgé ici).
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Agent, ShellSession, ShellSessionEvent
from ..security import get_current_agent, require_shell_token

router = APIRouter(tags=["shell"])

# Au-delà de ce délai sans nouvelle d'un agent sur SA session (poll-input ou output), on la
# considère probablement morte côté dashboard — calculé à la volée à chaque lecture, jamais une
# tâche de fond dédiée (aucune n'existe ailleurs dans ce serveur pour ce genre de ménage).
STALE_AFTER_SECONDS = 120


def _touch(db: Session, session: ShellSession) -> None:
    session.last_activity_at = datetime.now(timezone.utc)
    db.commit()


def _is_stale(session: ShellSession) -> bool:
    if session.status != "active":
        return False
    age = (datetime.now(timezone.utc) - session.last_activity_at).total_seconds()
    return age > STALE_AFTER_SECONDS


# ── Côté agent (mTLS) ────────────────────────────────────────────────────────────────────────


@router.post("/agents/{agent_id}/shell/sessions")
def create_session(
    agent_id: str,
    agent: Agent = Depends(get_current_agent),
    db: Session = Depends(get_db),
) -> dict:
    if agent.id != agent_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Ce certificat ne correspond pas à cet agent.")

    session = ShellSession(agent_id=agent_id)
    db.add(session)
    db.commit()
    db.refresh(session)
    return {"id": session.id}


class PollInputOut(BaseModel):
    lines: list[str]
    stop_requested: bool


@router.get("/agents/{agent_id}/shell/sessions/{session_id}/poll-input", response_model=PollInputOut)
def poll_input(
    agent_id: str,
    session_id: str,
    agent: Agent = Depends(get_current_agent),
    db: Session = Depends(get_db),
) -> PollInputOut:
    if agent.id != agent_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Ce certificat ne correspond pas à cet agent.")

    session = db.get(ShellSession, session_id)
    if session is None or session.agent_id != agent_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session introuvable pour cet agent.")

    new_inputs = db.scalars(
        select(ShellSessionEvent)
        .where(
            ShellSessionEvent.session_id == session_id,
            ShellSessionEvent.direction == "input",
            ShellSessionEvent.id > session.last_delivered_input_id,
        )
        .order_by(ShellSessionEvent.id)
    ).all()

    if new_inputs:
        session.last_delivered_input_id = new_inputs[-1].id
    _touch(db, session)

    return PollInputOut(lines=[e.content for e in new_inputs], stop_requested=session.stop_requested)


class OutputChunkIn(BaseModel):
    content: str
    source: str  # "stdout" | "stderr"


class OutputIn(BaseModel):
    chunks: list[OutputChunkIn]


@router.post("/agents/{agent_id}/shell/sessions/{session_id}/output")
def post_output(
    agent_id: str,
    session_id: str,
    payload: OutputIn,
    agent: Agent = Depends(get_current_agent),
    db: Session = Depends(get_db),
) -> dict:
    if agent.id != agent_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Ce certificat ne correspond pas à cet agent.")

    session = db.get(ShellSession, session_id)
    if session is None or session.agent_id != agent_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session introuvable pour cet agent.")

    for chunk in payload.chunks:
        db.add(ShellSessionEvent(session_id=session_id, direction="output", source=chunk.source, content=chunk.content))
    _touch(db, session)

    return {"ok": True}


class CloseSessionIn(BaseModel):
    status: str  # "closed" | "timed_out"


@router.post("/agents/{agent_id}/shell/sessions/{session_id}/close")
def close_session(
    agent_id: str,
    session_id: str,
    payload: CloseSessionIn,
    agent: Agent = Depends(get_current_agent),
    db: Session = Depends(get_db),
) -> dict:
    if agent.id != agent_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Ce certificat ne correspond pas à cet agent.")

    session = db.get(ShellSession, session_id)
    if session is None or session.agent_id != agent_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session introuvable pour cet agent.")

    if payload.status not in ("closed", "timed_out"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Statut de fermeture invalide.")

    session.status = payload.status
    session.last_activity_at = datetime.now(timezone.utc)
    db.commit()
    return {"ok": True}


# ── Côté dashboard (secret partagé) ──────────────────────────────────────────────────────────


class SessionStatusOut(BaseModel):
    id: str
    agent_id: str
    status: str
    started_at: datetime
    last_activity_at: datetime
    is_stale: bool


def _to_status_out(session: ShellSession) -> SessionStatusOut:
    return SessionStatusOut(
        id=session.id,
        agent_id=session.agent_id,
        status=session.status,
        started_at=session.started_at,
        last_activity_at=session.last_activity_at,
        is_stale=_is_stale(session),
    )


@router.get(
    "/shell/sessions/{session_id}",
    response_model=SessionStatusOut,
    dependencies=[Depends(require_shell_token)],
)
def get_session(session_id: str, db: Session = Depends(get_db)) -> SessionStatusOut:
    session = db.get(ShellSession, session_id)
    if session is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session introuvable.")
    return _to_status_out(session)


@router.get(
    "/agents/{agent_id}/shell/sessions/latest",
    response_model=SessionStatusOut | None,
    dependencies=[Depends(require_shell_token)],
)
def get_latest_session(agent_id: str, db: Session = Depends(get_db)) -> SessionStatusOut | None:
    """Le dashboard queue "start_shell_session" via le canal de commande fermé partagé
    (`POST /agents/{id}/commands`) SANS jamais connaître l'id de session à l'avance — l'agent
    ne crée la vraie `ShellSession` que jusqu'à ~5 min plus tard, une fois qu'il a récupéré la
    commande (même délai que n'importe laquelle des 6 autres). Cette route permet au dashboard
    de découvrir cet id dès qu'il existe, en repolling jusqu'à obtenir une réponse non nulle."""
    session = db.scalars(
        select(ShellSession).where(ShellSession.agent_id == agent_id).order_by(ShellSession.started_at.desc())
    ).first()
    return _to_status_out(session) if session else None


class SessionEventOut(BaseModel):
    id: int
    direction: str
    source: str | None
    content: str
    created_at: datetime


@router.get(
    "/shell/sessions/{session_id}/events",
    response_model=list[SessionEventOut],
    dependencies=[Depends(require_shell_token)],
)
def get_events(session_id: str, since_id: int = 0, db: Session = Depends(get_db)) -> list[SessionEventOut]:
    session = db.get(ShellSession, session_id)
    if session is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session introuvable.")

    events = db.scalars(
        select(ShellSessionEvent)
        .where(ShellSessionEvent.session_id == session_id, ShellSessionEvent.id > since_id)
        .order_by(ShellSessionEvent.id)
    ).all()
    return [
        SessionEventOut(id=e.id, direction=e.direction, source=e.source, content=e.content, created_at=e.created_at)
        for e in events
    ]


class SendInputIn(BaseModel):
    line: str


@router.post(
    "/shell/sessions/{session_id}/input",
    dependencies=[Depends(require_shell_token)],
)
def send_input(session_id: str, payload: SendInputIn, db: Session = Depends(get_db)) -> dict:
    session = db.get(ShellSession, session_id)
    if session is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session introuvable.")
    if session.status != "active":
        raise HTTPException(status.HTTP_409_CONFLICT, "Cette session n'est plus active.")

    db.add(ShellSessionEvent(session_id=session_id, direction="input", content=payload.line))
    db.commit()
    return {"ok": True}


@router.post(
    "/shell/sessions/{session_id}/stop",
    dependencies=[Depends(require_shell_token)],
)
def stop_session(session_id: str, db: Session = Depends(get_db)) -> dict:
    session = db.get(ShellSession, session_id)
    if session is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session introuvable.")

    session.stop_requested = True
    db.commit()
    return {"ok": True}
