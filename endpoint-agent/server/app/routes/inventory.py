"""Endpoint de remontée d'inventaire : un agent authentifié pousse la liste de ses apps."""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Agent, InstalledApp, InventorySnapshot
from ..security import get_current_agent

router = APIRouter(tags=["inventory"])


class InstalledAppIn(BaseModel):
    name: str
    version: str | None = None
    publisher: str | None = None
    install_date: str | None = None


class InventoryPushRequest(BaseModel):
    apps: list[InstalledAppIn]
    # OS (jalon EOL, 2026-09-08, `OsInfoCollector.cs` côté agent) — tous optionnels : un agent
    # pas encore mis à jour ne les envoie pas du tout (Pydantic les laisse à `None`), un agent à
    # jour dont la collecte WMI a échoué sur ce poste précis les envoie explicitement à `null`.
    # Dans les deux cas, jamais une erreur de validation qui ferait échouer tout l'envoi
    # d'inventaire pour ces 3 champs décoratifs.
    os_caption: str | None = None
    os_version: str | None = None
    os_build_number: str | None = None
    # Panneau "Système d'exploitation" (2026-09-11, retour de Nicolas — "possible d'avoir plus
    # d'information ?") — même contrat optionnel, même `OsInfoCollector.cs`, voir son commentaire
    # d'en-tête pour le détail de chaque champ (`os_utc_offset` = décalage structuré, jamais le
    # nom de fuseau localisé).
    os_architecture: str | None = None
    os_registered_user: str | None = None
    os_install_date: datetime | None = None
    os_utc_offset: str | None = None
    # Traçabilité de version (2026-09-08) — `<Version>` du .csproj agent, même contrat optionnel
    # que les champs OS ci-dessus.
    agent_version: str | None = None


class InventoryPushResponse(BaseModel):
    snapshot_id: int
    apps_count: int
    collected_at: datetime


@router.post("/agents/{agent_id}/inventory", response_model=InventoryPushResponse)
def push_inventory(
    agent_id: str,
    payload: InventoryPushRequest,
    agent: Agent = Depends(get_current_agent),
    db: Session = Depends(get_db),
) -> InventoryPushResponse:
    # Le certificat mTLS identifie déjà l'agent de façon fiable — l'agent_id du chemin doit lui
    # correspondre, sinon un agent enrôlé pourrait pousser un inventaire au nom d'un autre.
    if agent.id != agent_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Ce token ne correspond pas à cet agent.")

    snapshot = InventorySnapshot(
        agent_id=agent.id,
        os_caption=payload.os_caption,
        os_version=payload.os_version,
        os_build_number=payload.os_build_number,
        os_architecture=payload.os_architecture,
        os_registered_user=payload.os_registered_user,
        os_install_date=payload.os_install_date,
        os_utc_offset=payload.os_utc_offset,
    )
    db.add(snapshot)
    db.flush()  # attribue snapshot.id avant d'y rattacher les apps

    db.add_all(
        InstalledApp(
            snapshot_id=snapshot.id,
            name=app.name,
            version=app.version,
            publisher=app.publisher,
            install_date=app.install_date,
        )
        for app in payload.apps
    )

    # `last_seen` — plus mis à jour ici : centralisé dans `get_current_agent` (security.py,
    # 2026-09-16) puisque toute route authentifiée par certificat agent prouve tout autant la
    # joignabilité de l'agent qu'un push d'inventaire.
    if payload.agent_version:
        agent.agent_version = payload.agent_version
    db.commit()

    return InventoryPushResponse(
        snapshot_id=snapshot.id,
        apps_count=len(payload.apps),
        collected_at=snapshot.collected_at,
    )
