"""Groupes de postes (2026-09-08, demande de Nicolas — "ranger les postes dans des groupes si
trop de devices et pas organisé", étendu le même soir avec les groupes dynamiques et le
many-to-many : "un poste peut appartenir à plusieurs groupes", "un groupe défini par un motif
de nom, ex. *-wks*"). Règles multi-critères + groupes imbriqués ajoutés le 2026-09-10 suite à
une revue de la fonctionnalité comparée à Intune (dynamic groups)/Jamf (Smart Groups)/Tanium
(computer groups) — voir `app/group_membership.py` pour le détail du modèle de résolution,
partagé avec `routes/agents.py` (badges `group_ids` par poste).

Deux types de groupe, jamais mélangés pour un même groupe (voir `models.py::DeviceGroup`) :
- STATIQUE (`rules` nul) — membres = table de jointure `AgentGroupMembership`, affectation
  manuelle via `routes/agents.py::add_agent_to_group`/`remove_agent_from_group`.
- DYNAMIQUE (`rules` renseigné) — membres calculés à la volée, jamais stockés.
Les DEUX peuvent en plus contenir des groupes ENFANTS (`DeviceGroupLink`).

Toutes les routes sous `require_shell_token`, même tier de sensibilité que le reste des
lectures/mutations dashboard.
"""
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import audit
from .. import commands as commands_catalog
from ..db import get_db
from ..group_membership import normalize_rules, resolve_group_agents, would_create_cycle
from ..models import AgentGroupMembership, AgentPackage, DeviceGroup, DeviceGroupLink, InstallerPackage
from ..security import get_actor, require_shell_token

router = APIRouter(tags=["groups"])


def _device_count(db: Session, group: DeviceGroup) -> int:
    return len(resolve_group_agents(db, group))


class RuleConditionOut(BaseModel):
    field: str
    operator: str
    value: str


class RulesOut(BaseModel):
    combinator: str
    conditions: list[RuleConditionOut]


class GroupOut(BaseModel):
    id: str
    name: str
    rules: RulesOut | None
    child_group_ids: list[str]
    created_at: datetime
    updated_at: datetime
    device_count: int
    # Politique de mise à jour Windows (2026-09-17) — LECTURE seule ici (même route `GET
    # /groups` déjà consommée par la liste de groupes), pour que le badge "politique active"
    # soit visible sans un aller-retour supplémentaire. Écriture via `PUT .../patch-policy`
    # ci-dessous, jamais mêlée à `UpdateGroupIn` (nom/règles) — deux préoccupations distinctes.
    patch_enabled: bool
    patch_window_start: str | None
    patch_window_end: str | None
    patch_grace_days: int


def _to_group_out(db: Session, group: DeviceGroup) -> GroupOut:
    children = db.query(DeviceGroupLink.child_group_id).filter(
        DeviceGroupLink.parent_group_id == group.id
    ).all()
    return GroupOut(
        id=group.id,
        name=group.name,
        rules=json.loads(group.rules) if group.rules else None,
        child_group_ids=[c[0] for c in children],
        created_at=group.created_at,
        updated_at=group.updated_at,
        device_count=_device_count(db, group),
        patch_enabled=group.patch_enabled,
        patch_window_start=group.patch_window_start,
        patch_window_end=group.patch_window_end,
        patch_grace_days=group.patch_grace_days,
    )


@router.get("/groups", response_model=list[GroupOut], dependencies=[Depends(require_shell_token)])
def list_groups(db: Session = Depends(get_db)) -> list[GroupOut]:
    groups = db.query(DeviceGroup).order_by(DeviceGroup.name).all()
    return [_to_group_out(db, g) for g in groups]


class RuleConditionIn(BaseModel):
    field: str
    operator: str
    value: str


class RulesIn(BaseModel):
    combinator: str = "all"
    conditions: list[RuleConditionIn] = []


class CreateGroupIn(BaseModel):
    name: str
    rules: RulesIn | None = None


@router.post("/groups", response_model=GroupOut, dependencies=[Depends(require_shell_token)])
def create_group(
    payload: CreateGroupIn, db: Session = Depends(get_db), actor: str | None = Depends(get_actor)
) -> GroupOut:
    if not payload.name.strip():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Le nom du groupe est obligatoire.")
    try:
        rules = normalize_rules(payload.rules.model_dump() if payload.rules else None)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e
    group = DeviceGroup(name=payload.name.strip(), rules=json.dumps(rules) if rules else None)
    db.add(group)
    audit.record_event(
        db, "groupe", "created", group.name, actor=actor,
        detail=f"dynamique, {len(rules['conditions'])} critère(s)" if rules else "statique",
    )
    db.commit()
    db.refresh(group)
    return _to_group_out(db, group)


class UpdateGroupIn(BaseModel):
    name: str | None = None
    rules: RulesIn | None = None
    clear_rules: bool = False


@router.put("/groups/{group_id}", response_model=GroupOut, dependencies=[Depends(require_shell_token)])
def update_group(
    group_id: str, payload: UpdateGroupIn, db: Session = Depends(get_db), actor: str | None = Depends(get_actor)
) -> GroupOut:
    group = db.get(DeviceGroup, group_id)
    if group is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Groupe introuvable.")
    if payload.name is not None:
        if not payload.name.strip():
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Le nom du groupe ne peut pas être vide.")
        group.name = payload.name.strip()
    if payload.clear_rules:
        group.rules = None
    elif payload.rules is not None:
        try:
            new_rules = normalize_rules(payload.rules.model_dump())
        except ValueError as e:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e
        # Basculer un groupe STATIQUE (avec des adhésions déjà enregistrées) vers DYNAMIQUE
        # laisserait des lignes `AgentGroupMembership` orphelines, invisibles nulle part
        # (`resolve_group_agents` ne les lit plus une fois `rules` renseigné) — purgées
        # explicitement plutôt que laissées comme un état incohérent silencieux.
        if new_rules and not group.rules:
            db.query(AgentGroupMembership).filter(AgentGroupMembership.group_id == group_id).delete()
        group.rules = json.dumps(new_rules) if new_rules else None
    group.updated_at = datetime.now(timezone.utc)
    audit.record_event(db, "groupe", "updated", group.name, actor=actor)
    db.commit()
    db.refresh(group)
    return _to_group_out(db, group)


class UpdatePatchPolicyIn(BaseModel):
    enabled: bool
    # "HH:MM" — validés ici (format simple, pas de dépendance à une lib d'heure) plutôt que
    # côté agent, pour ne jamais laisser une politique mal formée atteindre `PatchLoop.cs`.
    window_start: str | None = None
    window_end: str | None = None
    grace_days: int = 5


def _validate_hhmm(value: str | None, field: str) -> None:
    if value is None:
        return
    parts = value.split(":")
    if len(parts) != 2 or not all(p.isdigit() for p in parts):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"{field} doit être au format HH:MM.")
    hour, minute = int(parts[0]), int(parts[1])
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"{field} doit être une heure valide (00:00–23:59).")


@router.put(
    "/groups/{group_id}/patch-policy", response_model=GroupOut, dependencies=[Depends(require_shell_token)]
)
def update_patch_policy(
    group_id: str, payload: UpdatePatchPolicyIn, db: Session = Depends(get_db), actor: str | None = Depends(get_actor)
) -> GroupOut:
    group = db.get(DeviceGroup, group_id)
    if group is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Groupe introuvable.")
    if payload.enabled and (not payload.window_start or not payload.window_end):
        # Même garde-fou que `ComplianceRule.enabled=False` par défaut (jalon 11) : impossible
        # d'activer une politique de patch SANS fenêtre définie — le pire des deux mondes serait
        # une politique "active" qui installe des mises à jour de sécurité mais ne redémarre
        # jamais faute de fenêtre, laissant un poste indéfiniment en attente.
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Une fenêtre de redémarrage (début et fin) est obligatoire pour activer la politique.",
        )
    _validate_hhmm(payload.window_start, "L'heure de début")
    _validate_hhmm(payload.window_end, "L'heure de fin")
    if payload.grace_days < 1 or payload.grace_days > 30:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Le délai de grâce doit être entre 1 et 30 jours.")

    group.patch_enabled = payload.enabled
    group.patch_window_start = payload.window_start
    group.patch_window_end = payload.window_end
    group.patch_grace_days = payload.grace_days
    group.updated_at = datetime.now(timezone.utc)
    audit.record_event(
        db, "groupe", "patch_policy_updated", group.name, actor=actor,
        detail=(
            f"activée, fenêtre {payload.window_start}-{payload.window_end}, grâce {payload.grace_days}j"
            if payload.enabled else "désactivée"
        ),
    )
    db.commit()
    db.refresh(group)
    return _to_group_out(db, group)


@router.delete("/groups/{group_id}", dependencies=[Depends(require_shell_token)])
def delete_group(
    group_id: str, db: Session = Depends(get_db), actor: str | None = Depends(get_actor)
) -> dict:
    group = db.get(DeviceGroup, group_id)
    if group is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Groupe introuvable.")
    db.query(AgentGroupMembership).filter(AgentGroupMembership.group_id == group_id).delete()
    # Retire aussi ce groupe de toute imbrication existante, qu'il soit PARENT ou ENFANT —
    # sinon un `DeviceGroupLink` pointant vers un `group_id` supprimé deviendrait une référence
    # fantôme (`resolve_group_agents` fait déjà un `db.get(...)` défensif qui l'ignorerait
    # silencieusement, mais autant ne jamais laisser la ligne traîner).
    db.query(DeviceGroupLink).filter(
        (DeviceGroupLink.parent_group_id == group_id) | (DeviceGroupLink.child_group_id == group_id)
    ).delete()
    audit.record_event(db, "groupe", "deleted", group.name, actor=actor)
    db.delete(group)
    db.commit()
    return {"ok": True}


@router.get(
    "/groups/{group_id}/members", response_model=list[str], dependencies=[Depends(require_shell_token)]
)
def get_group_members(group_id: str, db: Session = Depends(get_db)) -> list[str]:
    """Hostnames des membres — statiques OU dynamiques selon le type, PLUS ceux des groupes
    enfants imbriqués — calcul UNIQUE dans `group_membership.py` pour ne jamais dupliquer la
    logique côté dashboard."""
    group = db.get(DeviceGroup, group_id)
    if group is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Groupe introuvable.")
    return sorted(a.hostname for a in resolve_group_agents(db, group))


# ── Groupes imbriqués (2026-09-10) ──────────────────────────────────────────────────────────
# "Un groupe peut contenir d'autres groupes" — voir group_membership.py pour la résolution
# récursive et le contrôle de cycle. Symétrique aux 2 types de groupe (statique ET dynamique
# peuvent avoir des enfants) : l'imbrication est une source de membres SUPPLÉMENTAIRE, jamais
# un 3e type de groupe.


@router.post(
    "/groups/{parent_id}/children/{child_id}",
    response_model=GroupOut,
    dependencies=[Depends(require_shell_token)],
)
def add_child_group(
    parent_id: str, child_id: str, db: Session = Depends(get_db), actor: str | None = Depends(get_actor)
) -> GroupOut:
    parent = db.get(DeviceGroup, parent_id)
    child = db.get(DeviceGroup, child_id)
    if parent is None or child is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Groupe introuvable.")
    if would_create_cycle(db, parent_id, child_id):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Impossible : ce groupe imbriquerait un cycle (un groupe finirait par se contenir lui-même).",
        )
    if db.get(DeviceGroupLink, {"parent_group_id": parent_id, "child_group_id": child_id}) is None:
        db.add(DeviceGroupLink(parent_group_id=parent_id, child_group_id=child_id))
        audit.record_event(
            db, "groupe", "child_added", parent.name, actor=actor, detail=f"sous-groupe « {child.name} »"
        )
        db.commit()
        db.refresh(parent)
    return _to_group_out(db, parent)


@router.delete(
    "/groups/{parent_id}/children/{child_id}",
    response_model=GroupOut,
    dependencies=[Depends(require_shell_token)],
)
def remove_child_group(
    parent_id: str, child_id: str, db: Session = Depends(get_db), actor: str | None = Depends(get_actor)
) -> GroupOut:
    parent = db.get(DeviceGroup, parent_id)
    if parent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Groupe introuvable.")
    deleted = db.query(DeviceGroupLink).filter(
        DeviceGroupLink.parent_group_id == parent_id, DeviceGroupLink.child_group_id == child_id
    ).delete()
    if deleted:
        child = db.get(DeviceGroup, child_id)
        audit.record_event(
            db, "groupe", "child_removed", parent.name, actor=actor,
            detail=f"sous-groupe « {child.name if child else child_id} »",
        )
        db.commit()
        db.refresh(parent)
    return _to_group_out(db, parent)


class PushInstallIn(BaseModel):
    installer_id: str


class PushInstallOut(BaseModel):
    queued: int
    agent_ids: list[str]


@router.post(
    "/groups/{group_id}/push-install",
    response_model=PushInstallOut,
    dependencies=[Depends(require_shell_token)],
)
def push_install_to_group(
    group_id: str, payload: PushInstallIn, db: Session = Depends(get_db), actor: str | None = Depends(get_actor)
) -> PushInstallOut:
    """Pousse l'installation d'un installeur du catalogue vers CHAQUE membre du groupe
    (2026-09-08) — une ligne `AgentCommand` "install_application" par agent résolu (statique,
    dynamique, ou membre d'un groupe enfant imbriqué), même contrat que `queue_command` pour un
    seul poste. Un groupe vide (0 membre) n'est pas une erreur — renvoie simplement `queued: 0`."""
    group = db.get(DeviceGroup, group_id)
    if group is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Groupe introuvable.")

    installer = db.get(InstallerPackage, payload.installer_id)
    if installer is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Installeur introuvable.")
    parameters = commands_catalog.build_install_parameters(db, payload.installer_id, target_label=group.name)

    targets = resolve_group_agents(db, group)
    for agent in targets:
        commands_catalog.create_command(db, agent, "install_application", parameters=parameters, actor=actor)

    # Journal d'activité (2026-09-09) — UNE entrée pour le geste "pousser vers un groupe" (en
    # plus des N lignes AgentCommand individuelles déjà créées ci-dessus, une par poste) :
    # répond à "qui a poussé quoi vers quel groupe" sans avoir à compter N lignes "Poste"
    # identiques pour reconstituer ce geste après coup.
    audit.record_event(
        db, "application", "pushed", installer.name, actor=actor,
        detail=f"{len(targets)} poste(s) — groupe « {group.name} »",
    )
    db.commit()

    return PushInstallOut(queued=len(targets), agent_ids=[a.id for a in targets])


class PushUpdateIn(BaseModel):
    agent_package_id: str


@router.post(
    "/groups/{group_id}/push-update",
    response_model=PushInstallOut,
    dependencies=[Depends(require_shell_token)],
)
def push_update_to_group(
    group_id: str, payload: PushUpdateIn, db: Session = Depends(get_db), actor: str | None = Depends(get_actor)
) -> PushInstallOut:
    """Mise à jour de l'agent (2026-09-11) — même mécanique que `push_install_to_group` juste
    au-dessus, transposée à "update_agent"/`AgentPackage`. Réutilise `PushInstallOut` (même
    forme `{queued, agent_ids}`), pas la peine d'un modèle de sortie dédié."""
    group = db.get(DeviceGroup, group_id)
    if group is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Groupe introuvable.")

    pkg = db.get(AgentPackage, payload.agent_package_id)
    if pkg is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Paquet de mise à jour introuvable.")
    parameters = commands_catalog.build_update_parameters(db, payload.agent_package_id, target_label=group.name)

    targets = resolve_group_agents(db, group)
    for agent in targets:
        commands_catalog.create_command(db, agent, "update_agent", parameters=parameters, actor=actor)

    audit.record_event(
        db, "poste", "agent_update_pushed", f"Agent v{pkg.version}", actor=actor,
        detail=f"{len(targets)} poste(s) — groupe « {group.name} »",
    )
    db.commit()

    return PushInstallOut(queued=len(targets), agent_ids=[a.id for a in targets])
