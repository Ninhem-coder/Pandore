"""Endpoints de consultation — liste des agents connus et détail de leur dernier inventaire.

🔧 Revue de sécurité du 2026-09-07 : ces routes étaient documentées "lecture seule, usage local
sur le poste du serveur", mais le serveur est en réalité déployé et joignable par tout le parc
(`SERVERURL=https://<serveur>:8443`, voir le README) — l'hypothèse "loopback uniquement" ne
tenait pas en pratique. Combinée à `queue_command` (voir `routes/commands.py`, correctif du
même jour), l'absence d'auth ici permettait à quiconque atteignant le port de lister tous les
postes/id du parc, condition préalable à cibler `queue_command`/`DELETE` sans rien connaître
d'autre. Gatées par le même `require_shell_token` que le reste des routes dashboard sensibles
— `backend/vanitas/client.py` l'attache déjà à chaque requête, aucun usage légitime cassé.
"""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..group_membership import group_ids_for_agents
from ..models import Agent, AgentGroupMembership, DeviceGroup, InventorySnapshot, RevokedCertificate
from ..security import get_actor, require_shell_token

router = APIRouter(tags=["agents"])


class AgentSummary(BaseModel):
    id: str
    hostname: str
    enrolled_at: datetime
    last_seen: datetime | None
    apps_count: int
    cert_serial: str | None
    cert_not_after: datetime | None
    # Traçabilité de version (2026-09-08) — `None` pour tout agent qui n'a pas encore renvoyé
    # d'inventaire depuis ce jalon (agent pas encore redéployé).
    agent_version: str | None = None
    # Groupes (2026-09-08, many-to-many + dynamiques ; règles multi-critères + imbrication
    # 2026-09-10) — union des groupes STATIQUES auxquels ce poste a été explicitement affecté,
    # des groupes DYNAMIQUES dont la règle le matche, et de tout groupe qui le contient
    # indirectement via un sous-groupe imbriqué. Liste vide = poste non groupé (jamais `None`,
    # plus simple à consommer côté UI).
    group_ids: list[str] = []
    # Confinement (jalon "mini-EDR", 2026-09-17) — état courant, voir le docstring de
    # `Agent.network_isolated` (models.py). Exposé ici plutôt que via une route dédiée : la page
    # "Postes isolés" n'est qu'un filtre sur la liste déjà chargée par `useVanitasAgents()`, pas
    # un nouvel appel réseau.
    network_isolated: bool = False
    network_isolated_at: datetime | None = None
    network_isolated_by: str | None = None
    network_isolated_reason: str | None = None
    network_isolated_event_id: str | None = None


class InstalledAppOut(BaseModel):
    name: str
    version: str | None
    publisher: str | None
    install_date: str | None


class AgentInventory(BaseModel):
    agent_id: str
    hostname: str
    collected_at: datetime | None
    apps: list[InstalledAppOut]
    # OS (jalon EOL, 2026-09-08) — `None` sur un agent pas encore mis à jour pour les envoyer
    # (voir InventorySnapshot.os_caption/os_version/os_build_number), jamais une erreur.
    os_caption: str | None = None
    os_version: str | None = None
    os_build_number: str | None = None
    # Panneau "Système d'exploitation" (2026-09-11) — même contrat optionnel que les 3 ci-dessus.
    os_architecture: str | None = None
    os_registered_user: str | None = None
    os_install_date: datetime | None = None
    os_utc_offset: str | None = None


def _latest_snapshot(db: Session, agent_id: str) -> InventorySnapshot | None:
    return (
        db.query(InventorySnapshot)
        .filter(InventorySnapshot.agent_id == agent_id)
        .order_by(InventorySnapshot.collected_at.desc())
        .first()
    )


@router.get("/agents", response_model=list[AgentSummary])
def list_agents(
    db: Session = Depends(get_db), _auth: None = Depends(require_shell_token)
) -> list[AgentSummary]:
    agents = db.query(Agent).order_by(Agent.hostname).all()
    group_ids_by_agent = group_ids_for_agents(db, agents)
    result = []
    for agent in agents:
        snapshot = _latest_snapshot(db, agent.id)
        result.append(
            AgentSummary(
                id=agent.id,
                hostname=agent.hostname,
                enrolled_at=agent.enrolled_at,
                last_seen=agent.last_seen,
                apps_count=len(snapshot.apps) if snapshot else 0,
                cert_serial=agent.cert_serial,
                cert_not_after=agent.cert_not_after,
                agent_version=agent.agent_version,
                group_ids=group_ids_by_agent.get(agent.id, []),
                network_isolated=agent.network_isolated,
                network_isolated_at=agent.network_isolated_at,
                network_isolated_by=agent.network_isolated_by,
                network_isolated_reason=agent.network_isolated_reason,
                network_isolated_event_id=agent.network_isolated_event_id,
            )
        )
    return result


@router.get("/agents/{agent_id}/inventory", response_model=AgentInventory)
def get_agent_inventory(
    agent_id: str, db: Session = Depends(get_db), _auth: None = Depends(require_shell_token)
) -> AgentInventory:
    agent = db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Agent inconnu.")

    snapshot = _latest_snapshot(db, agent_id)
    apps = (
        [
            InstalledAppOut(
                name=a.name,
                version=a.version,
                publisher=a.publisher,
                install_date=a.install_date,
            )
            for a in snapshot.apps
        ]
        if snapshot
        else []
    )

    return AgentInventory(
        agent_id=agent.id,
        hostname=agent.hostname,
        collected_at=snapshot.collected_at if snapshot else None,
        apps=apps,
        os_caption=snapshot.os_caption if snapshot else None,
        os_version=snapshot.os_version if snapshot else None,
        os_build_number=snapshot.os_build_number if snapshot else None,
        os_architecture=snapshot.os_architecture if snapshot else None,
        os_registered_user=snapshot.os_registered_user if snapshot else None,
        os_install_date=snapshot.os_install_date if snapshot else None,
        os_utc_offset=snapshot.os_utc_offset if snapshot else None,
    )


def _agent_summary(db: Session, agent: Agent) -> AgentSummary:
    snapshot = _latest_snapshot(db, agent.id)
    return AgentSummary(
        id=agent.id,
        hostname=agent.hostname,
        enrolled_at=agent.enrolled_at,
        last_seen=agent.last_seen,
        apps_count=len(snapshot.apps) if snapshot else 0,
        cert_serial=agent.cert_serial,
        cert_not_after=agent.cert_not_after,
        agent_version=agent.agent_version,
        group_ids=group_ids_for_agents(db, [agent]).get(agent.id, []),
        network_isolated=agent.network_isolated,
        network_isolated_at=agent.network_isolated_at,
        network_isolated_by=agent.network_isolated_by,
        network_isolated_reason=agent.network_isolated_reason,
        network_isolated_event_id=agent.network_isolated_event_id,
    )


@router.post(
    "/agents/{agent_id}/groups/{group_id}",
    response_model=AgentSummary,
    dependencies=[Depends(require_shell_token)],
)
def add_agent_to_group(
    agent_id: str, group_id: str, db: Session = Depends(get_db), actor: str | None = Depends(get_actor)
) -> AgentSummary:
    """Ajoute une adhésion STATIQUE (2026-09-08, many-to-many) — un poste peut appartenir à
    plusieurs groupes à la fois, contrairement au jalon v1 (un seul `group_id`). Jamais pour un
    groupe DYNAMIQUE (règle, 2026-09-10) : ses membres sont calculés par la règle, une adhésion
    manuelle n'aurait aucun effet visible (`resolve_group_agents` ne lit jamais
    `AgentGroupMembership` pour un groupe dynamique) — refusée explicitement plutôt que
    silencieusement inefficace."""
    agent = db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Agent inconnu.")
    group = db.get(DeviceGroup, group_id)
    if group is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Groupe introuvable.")
    if group.rules:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Ce groupe est dynamique (motif de nom) — ses membres sont calculés automatiquement, "
            "aucune affectation manuelle possible.",
        )
    if db.get(AgentGroupMembership, {"agent_id": agent_id, "group_id": group_id}) is None:
        db.add(AgentGroupMembership(agent_id=agent_id, group_id=group_id))
        audit.record_event(
            db, "groupe", "agent_added", group.name, actor=actor, detail=f"poste {agent.hostname}"
        )
        db.commit()
    return _agent_summary(db, agent)


@router.delete(
    "/agents/{agent_id}/groups/{group_id}",
    response_model=AgentSummary,
    dependencies=[Depends(require_shell_token)],
)
def remove_agent_from_group(
    agent_id: str, group_id: str, db: Session = Depends(get_db), actor: str | None = Depends(get_actor)
) -> AgentSummary:
    agent = db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Agent inconnu.")
    deleted = db.query(AgentGroupMembership).filter(
        AgentGroupMembership.agent_id == agent_id, AgentGroupMembership.group_id == group_id
    ).delete()
    if deleted:
        group = db.get(DeviceGroup, group_id)
        audit.record_event(
            db, "groupe", "agent_removed", group.name if group else group_id,
            actor=actor, detail=f"poste {agent.hostname}",
        )
    db.commit()
    return _agent_summary(db, agent)


@router.delete("/agents/{agent_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_agent(
    agent_id: str,
    db: Session = Depends(get_db),
    actor: str | None = Depends(get_actor),
    _auth: None = Depends(require_shell_token),
) -> None:
    """Retrait de l'inventaire (jalon 7) — supprime l'agent ET tout son historique (snapshots/
    apps/commandes, cascade `models.py::Agent.snapshots`/`.commands`). N'agit QUE côté serveur :
    si l'agent est encore réellement installé et actif sur son poste, il continuera de tourner
    mais recevra 404 ("Agent inconnu") sur son prochain push/poll — déjà le comportement
    existant de `POST /agents/{id}/inventory`, inchangé ici. Pensé pour un poste déjà
    décommissionné/désinstallé, pas comme un substitut à la désinstallation réelle.

    🔧 Révocation ajoutée le 2026-09-08 (revue de sécurité) : avant ce correctif, retirer un
    agent ne faisait disparaître QUE sa ligne DB — le certificat mTLS restait cryptographiquement
    valide (chaîne jusqu'à la CA) jusqu'à expiration naturelle (90 jours), même pour un poste
    compromis/décommissionné. `agent.cert_serial` (déjà tenu à jour à chaque enrôlement/
    renouvellement) est enregistré dans `RevokedCertificate` AVANT la suppression de la ligne
    Agent — cette table est SÉPARÉE de `agents` précisément pour survivre à cette suppression.
    Voir `security.py::get_current_agent` pour la vérification côté handshake."""
    agent = db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Agent inconnu.")

    if agent.cert_serial:
        db.merge(
            RevokedCertificate(
                cert_serial=agent.cert_serial.lower(), agent_id=agent.id, hostname=agent.hostname
            )
        )

    audit.record_event(db, "poste", "removed", agent.hostname, actor=actor)
    db.delete(agent)
    db.commit()
