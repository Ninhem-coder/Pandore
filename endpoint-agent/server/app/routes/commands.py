"""Canal de commande — jalon 4.

`pending`/`result` sont authentifiés par mTLS (même mécanisme que le reste depuis le jalon 3,
`Depends(get_current_agent)` + contrôle anti-usurpation).

🔧 Bug de sécurité CRITIQUE trouvé et corrigé le 2026-09-07 (revue de sécurité complète, suite
à l'ajout de l'authentification multi-comptes côté Pandore) : `queue_command`/`list_commands`/
`list_fleet_commands` n'avaient AUCUNE authentification — ni mTLS, ni `X-Shell-Token` — alors
que `queue_command` accepte n'importe quel `command_type` du catalogue, y compris
`start_shell_session` (ouvre un VRAI terminal PowerShell SYSTEM sur l'agent) et
`uninstall_agent`. Le commentaire d'origine ("même précédent que GET /agents/{id}/
vulnerabilities... visibilité en lecture seule acceptée") était faux sur le fond : ces routes
ne sont PAS de la lecture seule, elles DÉCLENCHENT une action côté agent. Combiné à
`GET /agents` (liste les hostnames/id) également non authentifiée, un attaquant qui atteint
simplement le port du serveur Vanitas pouvait ouvrir un shell SYSTEM ou désinstaller l'agent
sur N'IMPORTE QUEL poste du parc sans connaître aucun secret. Corrigé par
`Depends(require_shell_token)` sur les 3 routes ci-dessous (même secret déjà utilisé pour
observer/piloter une session shell ouverte, jalon 9) — `backend/vanitas/client.py` (le seul
appelant légitime, le backend Pandore) attache déjà ce header à CHAQUE requête via son client
HTTP partagé, donc ce correctif ne casse aucun usage existant.
"""
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import commands as commands_catalog
from ..db import get_db
from ..models import Agent, AgentCommand
from ..security import get_actor, get_current_agent, require_shell_token

router = APIRouter(tags=["commands"])


class PendingCommandOut(BaseModel):
    id: int
    command_type: str
    parameters: str | None


class CommandResultIn(BaseModel):
    success: bool
    result: str | None = None


class CommandOut(BaseModel):
    id: int
    command_type: str
    parameters: str | None
    status: str
    created_at: datetime
    completed_at: datetime | None
    success: bool | None
    result: str | None
    # Journal d'activité (2026-09-09) — voir AgentCommand.actor.
    actor: str | None = None


class FleetCommandOut(CommandOut):
    """Comme `CommandOut`, avec l'identité de l'agent — jalon 5, pour la page fleet-wide du
    dashboard (`GET /commands`) : `GET /agents/{id}/commands` seul ne dit pas QUI, praticable
    avec un agent de test, pas avec un parc."""

    agent_id: str
    hostname: str


def _format_evtx_time(dt: datetime) -> str:
    """Formate une date pour la condition XPath `@SystemTime` de "fetch_event_log"
    (`EventLogFetcher.BuildXPath`, côté agent) — 🔧 bug trouvé le 2026-09-16 (retour de Nicolas :
    une recherche sur 2 jours avec tous les niveaux cochés sur "Security" renvoyait 0 résultat,
    alors que ce canal a forcément des connexions dans une telle fenêtre). Cause : `dt.isoformat()`
    seul produit un suffixe `+00:00` ("2026-09-16T00:00:00+00:00"), alors que le moteur de requête
    EvtQuery n'interprète la comparaison `@SystemTime>=/<=` comme une comparaison de DATE (et non
    une comparaison de chaîne lexicographique) que si la valeur se termine par `Z` — le format
    exact que Windows écrit lui-même dans le XML d'un événement. Avec `+00:00`, la condition ne
    matchait jamais rien, silencieusement (pas d'erreur XPath, juste 0 événement)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


class EventLogQueryIn(BaseModel):
    """Paramètres de "fetch_event_log" (2026-09-16) — saisis par l'utilisateur depuis le
    dashboard, PAS une référence vers un catalogue serveur comme `installer_id`/
    `agent_package_id` juste en dessous. Validés dans `commands_catalog.build_event_log_
    parameters` (canaux connus, période cohérente, plafond d'événements) avant sérialisation."""

    channels: list[str]
    since: datetime
    until: datetime
    event_ids_include: list[int] | None = None
    event_ids_exclude: list[int] | None = None
    levels: list[str] | None = None
    after_record_id: int | None = None
    max_events: int | None = None


class QueueCommandIn(BaseModel):
    command_type: str
    # Push d'application (2026-09-08) — seul type de commande qui a besoin d'une référence
    # supplémentaire aujourd'hui : quel installeur du catalogue pousser. Ignoré pour tout autre
    # `command_type`, jamais une erreur si absent/superflu.
    installer_id: str | None = None
    # Mise à jour de l'agent (2026-09-11) — même principe qu'`installer_id`, pour
    # "update_agent" : quel paquet AgentPackage pousser. Champ séparé plutôt que de réutiliser
    # `installer_id` : deux catalogues distincts (InstallerPackage vs AgentPackage), jamais
    # mélangés (voir commands.py::build_update_parameters).
    agent_package_id: str | None = None
    # Journal d'événements Windows à la demande (2026-09-16) — requis pour "fetch_event_log",
    # ignoré sinon, même principe que les deux champs juste au-dessus.
    event_log_query: EventLogQueryIn | None = None
    # Jalon "confinement" (2026-09-17) — référence vers l'alerte "activité suspecte"
    # déclenchante. Requis pour "kill_process" (le PID/nom de process en sont extraits
    # SERVEUR-SIDE, voir commands_catalog.build_kill_process_parameters — jamais transmis en
    # clair par le dashboard, qui n'a aucun moyen de les vérifier). Optionnel pour
    # "isolate_network" (un isolement manuel sans alerte précise reste possible), ignoré sinon.
    event_id: str | None = None


@router.get("/agents/{agent_id}/commands/pending", response_model=list[PendingCommandOut])
def fetch_pending_commands(
    agent_id: str,
    agent: Agent = Depends(get_current_agent),
    db: Session = Depends(get_db),
) -> list[PendingCommandOut]:
    if agent.id != agent_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Ce certificat ne correspond pas à cet agent.")

    pending = db.scalars(
        select(AgentCommand).where(AgentCommand.agent_id == agent_id, AgentCommand.status == "pending")
    ).all()

    # Marquées "running" dès qu'elles sont servies — si l'agent plante avant de rapporter un
    # résultat, la commande reste visible comme "running" dans l'audit plutôt que d'être
    # re-servie indéfiniment à chaque poll suivant (pas de retry automatique dans ce jalon).
    for command in pending:
        command.status = "running"
    db.commit()

    return [
        PendingCommandOut(id=c.id, command_type=c.command_type, parameters=c.parameters)
        for c in pending
    ]


@router.post("/agents/{agent_id}/commands/{command_id}/result")
def report_command_result(
    agent_id: str,
    command_id: int,
    payload: CommandResultIn,
    agent: Agent = Depends(get_current_agent),
    db: Session = Depends(get_db),
) -> dict:
    if agent.id != agent_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Ce certificat ne correspond pas à cet agent.")

    command = db.get(AgentCommand, command_id)
    if command is None or command.agent_id != agent.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Commande introuvable pour cet agent.")

    command.status = "completed" if payload.success else "failed"
    command.success = payload.success
    command.result = payload.result
    command.completed_at = datetime.now(timezone.utc)

    # Jalon "confinement" (2026-09-17) — `Agent.network_isolated*` reflète l'état RÉEL du
    # poste, jamais la simple mise en file : peuplé/effacé UNIQUEMENT ici, sur un résultat
    # positif confirmé par l'agent lui-même (voir le docstring du modèle) — un isolement affiché
    # avant cette confirmation serait trompeur si l'agent est hors ligne ou que la commande a
    # échoué (ex. résolution DNS du serveur impossible, voir ContainmentRunner.cs).
    if command.command_type == "isolate_network" and payload.success:
        # 🔧 Revue de sécurité du 2026-09-17 — `json.loads` protégé : une ligne `parameters`
        # corrompue (édition manuelle en test, bug futur) ne doit jamais faire échouer TOUT le
        # rapport de résultat avant `db.commit()` ci-dessous, ce qui laisserait la commande
        # bloquée à `running` indéfiniment alors que l'agent a bien répondu.
        try:
            params = json.loads(command.parameters) if command.parameters else {}
        except (json.JSONDecodeError, TypeError):
            params = {}
        agent.network_isolated = True
        agent.network_isolated_at = datetime.now(timezone.utc)
        agent.network_isolated_by = command.actor
        agent.network_isolated_reason = params.get("reason_summary") or "Isolement manuel"
        agent.network_isolated_event_id = params.get("reason_event_id")
    elif command.command_type == "lift_isolation" and payload.success:
        agent.network_isolated = False
        agent.network_isolated_at = None
        agent.network_isolated_by = None
        agent.network_isolated_reason = None
        agent.network_isolated_event_id = None

    db.commit()

    return {"ok": True}


@router.get("/agents/{agent_id}/commands", response_model=list[CommandOut])
def list_commands(
    agent_id: str, db: Session = Depends(get_db), _auth: None = Depends(require_shell_token)
) -> list[CommandOut]:
    commands = db.scalars(
        select(AgentCommand)
        .where(AgentCommand.agent_id == agent_id)
        .order_by(AgentCommand.created_at.desc())
    ).all()
    return [
        CommandOut(
            id=c.id,
            command_type=c.command_type,
            parameters=c.parameters,
            status=c.status,
            created_at=c.created_at,
            completed_at=c.completed_at,
            success=c.success,
            result=c.result,
            actor=c.actor,
        )
        for c in commands
    ]


@router.post("/agents/{agent_id}/commands", response_model=FleetCommandOut)
def queue_command(
    agent_id: str,
    payload: QueueCommandIn,
    db: Session = Depends(get_db),
    actor: str | None = Depends(get_actor),
    _auth: None = Depends(require_shell_token),
) -> FleetCommandOut:
    """Queue une commande via HTTP — jalon 5, pour le bouton "Lancer" du dashboard DSI.

    `require_shell_token` (2026-09-07, revue de sécurité — voir l'en-tête du fichier) : ce
    n'est pas un agent mTLS qui appelle ici, c'est le backend Pandore pour le compte d'un admin
    via le dashboard — le secret partagé joue ici le rôle qu'un token de session/rôle admin
    jouerait, faute d'un vrai modèle multi-utilisateur côté Vanitas lui-même.
    """
    agent = db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Agent inconnu.")

    parameters = None
    if payload.command_type == "install_application":
        if not payload.installer_id:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "installer_id requis pour install_application.")
        try:
            parameters = commands_catalog.build_install_parameters(db, payload.installer_id)
        except ValueError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    elif payload.command_type == "update_agent":
        if not payload.agent_package_id:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "agent_package_id requis pour update_agent.")
        try:
            parameters = commands_catalog.build_update_parameters(db, payload.agent_package_id)
        except ValueError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    elif payload.command_type == "fetch_event_log":
        if payload.event_log_query is None:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "event_log_query requis pour fetch_event_log.")
        q = payload.event_log_query
        try:
            parameters = commands_catalog.build_event_log_parameters(
                channels=q.channels,
                since=_format_evtx_time(q.since),
                until=_format_evtx_time(q.until),
                event_ids_include=q.event_ids_include,
                event_ids_exclude=q.event_ids_exclude,
                levels=q.levels,
                after_record_id=q.after_record_id,
                max_events=q.max_events,
            )
        except ValueError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    elif payload.command_type == "kill_process":
        if not payload.event_id:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "event_id requis pour kill_process.")
        try:
            parameters = commands_catalog.build_kill_process_parameters(db, agent_id, payload.event_id)
        except ValueError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    elif payload.command_type == "isolate_network":
        try:
            parameters = commands_catalog.build_isolate_network_parameters(db, agent_id, payload.event_id)
        except ValueError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc

    try:
        command = commands_catalog.create_command(
            db, agent, payload.command_type, parameters=parameters, actor=actor
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    return FleetCommandOut(
        id=command.id,
        command_type=command.command_type,
        parameters=command.parameters,
        status=command.status,
        created_at=command.created_at,
        completed_at=command.completed_at,
        success=command.success,
        result=command.result,
        actor=command.actor,
        agent_id=agent.id,
        hostname=agent.hostname,
    )


@router.get("/commands", response_model=list[FleetCommandOut])
def list_fleet_commands(
    db: Session = Depends(get_db), _auth: None = Depends(require_shell_token)
) -> list[FleetCommandOut]:
    """Historique fleet-wide (jalon 5) — page "Commandes" du dashboard DSI."""
    rows = (
        db.query(AgentCommand, Agent.hostname)
        .join(Agent, Agent.id == AgentCommand.agent_id)
        .order_by(AgentCommand.created_at.desc())
        .all()
    )
    return [
        FleetCommandOut(
            id=c.id,
            command_type=c.command_type,
            parameters=c.parameters,
            status=c.status,
            created_at=c.created_at,
            completed_at=c.completed_at,
            success=c.success,
            result=c.result,
            actor=c.actor,
            agent_id=c.agent_id,
            hostname=hostname,
        )
        for c, hostname in rows
    ]
