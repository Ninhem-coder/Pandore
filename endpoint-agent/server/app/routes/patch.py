"""Mises à jour Windows — jalon "patch management" (2026-09-17, maquette validée par Nicolas).

Trois surfaces distinctes, volontairement séparées du catalogue de commandes à la demande
(`app/commands.py`) : le RYTHME de ce jalon est piloté par une politique PERSISTANTE par groupe
(voir `models.py::DeviceGroup.patch_*`), pas par un clic ponctuel comme "Pousser une
application" — c'est une boucle de fond côté agent (`PatchLoop.cs`) qui décide seule quand
scanner/installer/redémarrer, en interrogeant ces routes à son propre rythme :

- `GET /agents/{id}/patch-policy` (mTLS agent) — la politique APPLICABLE à CET agent, résolue
  côté serveur à partir de ses groupes (jamais recalculée différemment côté agent/dashboard).
- `POST /agents/{id}/patch-status` (mTLS agent) — upsert du dernier état connu (une ligne par
  agent, comme `InventorySnapshot`/`ComplianceSnapshot` — le dernier envoi fait foi).
- `GET /patch-status` (dashboard, `require_shell_token`) — vue fleet-wide, statut d'affichage
  calculé ICI (voir `_display_status`) pour que le tableau de bord et une éventuelle notion de
  KPI restent TOUJOURS d'accord avec ce que l'agent voit lui-même côté politique.

Le redémarrage forcé HORS fenêtre ("Forcer maintenant" depuis le dashboard) est une commande
classique (`force_reboot`, voir `app/commands.py`/`routes/commands.py`), pas une route d'ici.
La politique elle-même (activer/désactiver un groupe, fenêtre, délai de grâce) se modifie via
`PUT /groups/{group_id}/patch-policy` dans `routes/groups.py` (co-localisée avec le reste des
mutations de groupe), pas ici.
"""
import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db import get_db
from ..group_membership import group_ids_for_agents
from ..models import Agent, DeviceGroup, PatchStatus
from ..security import get_current_agent, require_shell_token

router = APIRouter(tags=["patch"])


class PatchItem(BaseModel):
    kb: str
    title: str


class PatchPolicyOut(BaseModel):
    enabled: bool
    window_start: str | None = None
    window_end: str | None = None
    grace_days: int | None = None
    # Horodatage (ISO 8601, UTC) depuis lequel un redémarrage est en attente pour CET agent — le
    # calcul du délai de grâce se fait CÔTÉ AGENT (comparaison à son horloge UTC, fiable quelle
    # que soit l'horloge locale/le fuseau) à partir de cette seule valeur, jamais un booléen
    # "délai dépassé" précalculé qui dupliquerait la même logique à deux endroits.
    installed_at: str | None = None


def _resolve_policy(db: Session, agent: Agent) -> DeviceGroup | None:
    """Le PREMIER groupe de l'agent avec une politique active fait foi — limite V1 assumée et
    documentée (voir `models.py::DeviceGroup`) : deux groupes actifs aux fenêtres différentes
    sur un même poste ne sont jamais fusionnés, pas de règle de priorité au-delà de l'ordre de
    résolution de `group_ids_for_agents`."""
    group_ids = group_ids_for_agents(db, [agent]).get(agent.id, [])
    for group_id in group_ids:
        group = db.get(DeviceGroup, group_id)
        if group is not None and group.patch_enabled:
            return group
    return None


@router.get("/agents/{agent_id}/patch-policy", response_model=PatchPolicyOut)
def get_patch_policy(agent: Agent = Depends(get_current_agent), db: Session = Depends(get_db)) -> PatchPolicyOut:
    group = _resolve_policy(db, agent)
    status_row = db.get(PatchStatus, agent.id)
    installed_at = status_row.installed_at if status_row else None
    if group is None:
        return PatchPolicyOut(enabled=False, installed_at=installed_at.isoformat() if installed_at else None)
    return PatchPolicyOut(
        enabled=True,
        window_start=group.patch_window_start,
        window_end=group.patch_window_end,
        grace_days=group.patch_grace_days,
        installed_at=installed_at.isoformat() if installed_at else None,
    )


class PatchStatusIn(BaseModel):
    available: list[PatchItem] = []
    todo: list[PatchItem] = []
    in_progress: list[PatchItem] = []
    installed: list[PatchItem] = []
    # Signal natif Windows (`RebootPending`/`Auto Update\RebootRequired`, voir `PatchRunner.cs`)
    # — JAMAIS déduit côté serveur du seul contenu de `installed`, qui peut être non vide sans
    # qu'un redémarrage soit réellement requis pour certaines mises à jour.
    reboot_pending: bool = False


@router.post("/agents/{agent_id}/patch-status")
def push_patch_status(
    payload: PatchStatusIn,
    agent: Agent = Depends(get_current_agent),
    db: Session = Depends(get_db),
) -> dict:
    row = db.get(PatchStatus, agent.id)
    if row is None:
        row = PatchStatus(agent_id=agent.id)
        db.add(row)

    row.available_json = json.dumps([i.model_dump() for i in payload.available])
    row.todo_json = json.dumps([i.model_dump() for i in payload.todo])
    row.in_progress_json = json.dumps([i.model_dump() for i in payload.in_progress])
    # `installed` — cas particulier : un cycle qui ne fait QUE constater "toujours en attente de
    # redémarrage" (rien de nouveau à installer, l'agent ne re-scanne pas ce qui est déjà posé)
    # pousse une liste VIDE sans que ça signifie "plus rien n'est installé" — seul un cycle qui
    # vient RÉELLEMENT de terminer une installation (liste non vide) ou un poste qui a
    # RÉELLEMENT redémarré (`reboot_pending=False`, nouveau cycle) doit remplacer cette liste.
    if payload.installed or not payload.reboot_pending:
        row.installed_json = json.dumps([i.model_dump() for i in payload.installed])

    if payload.reboot_pending:
        # Ne JAMAIS écraser un `installed_at` déjà posé — c'est le tout PREMIER cycle qui a
        # détecté le redémarrage en attente qui fixe le départ du délai de grâce, pas le
        # dernier (sinon un poste qui reste simplement éteint verrait sa fenêtre de grâce
        # repoussée indéfiniment à chaque nouveau contact, contournant le garde-fou lui-même).
        if row.installed_at is None:
            row.installed_at = datetime.now(timezone.utc)
        elif row.forced_at is None:
            # `forced_at` — horodatage du moment où ce cycle constate POUR LA PREMIÈRE FOIS le
            # dépassement, uniquement pour le journal affiché côté poste (voir la maquette) ;
            # `_display_status` ne s'appuie JAMAIS dessus pour décider "forced" (recalculé à
            # chaque lecture depuis `installed_at`, seule source de vérité pour l'affichage).
            group = _resolve_policy(db, agent)
            grace = (group.patch_grace_days if group else None) or 5
            if datetime.now(timezone.utc) - row.installed_at >= timedelta(days=grace):
                row.forced_at = datetime.now(timezone.utc)
    else:
        # Le poste a réellement redémarré (Windows a levé le signal) — nouveau cycle, l'horloge
        # de grâce ET le marqueur "forcé" repartent de zéro.
        row.installed_at = None
        row.forced_at = None

    db.commit()
    return {"ok": True}


class FleetPatchEntry(BaseModel):
    agent_id: str
    hostname: str
    group_id: str | None = None
    group_name: str | None = None
    status: str
    available: list[PatchItem]
    todo: list[PatchItem]
    in_progress: list[PatchItem]
    installed: list[PatchItem]
    installed_at: str | None = None
    forced_at: str | None = None
    updated_at: str | None = None
    window_start: str | None = None
    window_end: str | None = None
    grace_days: int | None = None


def _display_status(group: DeviceGroup | None, status_row: PatchStatus | None) -> str:
    """Même 6 statuts que la maquette validée (`ok | pending-install | installing |
    pending-window | forced | off`) — calculé ICI, une seule fois, jamais recalculé côté
    frontend pour ne jamais diverger de ce que l'agent applique réellement."""
    if group is None or not group.patch_enabled:
        return "off"
    if status_row is None:
        return "ok"
    if status_row.installed_at is not None:
        grace = group.patch_grace_days or 5
        elapsed = datetime.now(timezone.utc) - status_row.installed_at
        return "forced" if elapsed.days >= grace else "pending-window"
    if json.loads(status_row.in_progress_json or "[]"):
        return "installing"
    if json.loads(status_row.todo_json or "[]"):
        return "pending-install"
    return "ok"


@router.get("/patch-status", response_model=list[FleetPatchEntry], dependencies=[Depends(require_shell_token)])
def list_patch_status(db: Session = Depends(get_db)) -> list[FleetPatchEntry]:
    agents = db.query(Agent).order_by(Agent.hostname).all()
    group_ids_by_agent = group_ids_for_agents(db, agents)
    statuses_by_agent = {row.agent_id: row for row in db.query(PatchStatus).all()}

    entries: list[FleetPatchEntry] = []
    for agent in agents:
        status_row = statuses_by_agent.get(agent.id)
        # Même résolution "premier groupe actif" que `_resolve_policy` — si aucun groupe actif,
        # retombe sur le PREMIER groupe tout court (juste pour l'affichage du badge groupe dans
        # le tableau), sinon `None` (poste dans aucun groupe du tout).
        group: DeviceGroup | None = None
        for group_id in group_ids_by_agent.get(agent.id, []):
            candidate = db.get(DeviceGroup, group_id)
            if candidate is None:
                continue
            if candidate.patch_enabled:
                group = candidate
                break
            if group is None:
                group = candidate

        def _items(field: str) -> list[PatchItem]:
            if status_row is None:
                return []
            raw = getattr(status_row, field)
            return [PatchItem(**i) for i in json.loads(raw or "[]")]

        entries.append(
            FleetPatchEntry(
                agent_id=agent.id,
                hostname=agent.hostname,
                group_id=group.id if group else None,
                group_name=group.name if group else None,
                status=_display_status(group, status_row),
                available=_items("available_json"),
                todo=_items("todo_json"),
                in_progress=_items("in_progress_json"),
                installed=_items("installed_json"),
                installed_at=status_row.installed_at.isoformat() if status_row and status_row.installed_at else None,
                forced_at=status_row.forced_at.isoformat() if status_row and status_row.forced_at else None,
                updated_at=status_row.updated_at.isoformat() if status_row else None,
                window_start=group.patch_window_start if group else None,
                window_end=group.patch_window_end if group else None,
                grace_days=group.patch_grace_days if group else None,
            )
        )
    return entries
