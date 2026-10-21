"""
Résolution des membres d'un groupe de postes — module PARTAGÉ entre `routes/groups.py`
(gestion des groupes eux-mêmes) et `routes/agents.py` (badges `group_ids` sur chaque poste) :
avant ce jalon, les deux fichiers dupliquaient CHACUN leur propre logique `fnmatch` sur
`DeviceGroup.pattern` — un vrai risque de divergence silencieuse (déjà noté mais jamais corrigé
dans les commentaires de `routes/groups.py`). Une seule source de vérité désormais.

Trois jalons "Groupes" successifs :
1. (2026-09-08) Statique (affectation manuelle, many-to-many) + dynamique (motif de nom glob).
2. (2026-09-10, revue de la fonctionnalité comparée à Intune/Jamf/Tanium) Règles dynamiques
   MULTI-CRITÈRES avec exclusion — `DeviceGroup.rules` (JSON) remplace `DeviceGroup.pattern`
   comme définition d'un groupe dynamique. `pattern` reste une colonne physique (jamais de
   `DROP COLUMN` dans ce projet) mais n'est plus lue : la migration (`scripts/
   migrate_add_group_rules_column.py`) traduit tout `pattern` existant en une règle équivalente
   à un seul critère `{field: "hostname", operator: "glob", value: pattern}`.
3. (2026-09-10, même revue) Groupes IMBRIQUÉS — `DeviceGroupLink` (table de jointure parent/
   enfant). Un groupe, statique OU dynamique, peut désormais AUSSI contenir d'autres groupes :
   ses membres totaux sont l'union de (règle si dynamique) + (adhésions manuelles si statique)
   + (membres résolus récursivement de chaque groupe enfant) — jamais une 3e catégorie de
   groupe "hybride", juste une source de membres supplémentaire pour les deux types existants.

Champs de règle disponibles (`FIELDS`) — bornés à ce que l'agent collecte RÉELLEMENT
aujourd'hui, jamais un champ inventé : `hostname` (Agent.hostname), `os` (dernier
`InventorySnapshot.os_caption` connu), `status` ("online"/"offline", même seuil de 24h que
`isOnline()` côté frontend, vanitasShared.jsx — aucune raison de diverger), `agent_version`
(Agent.agent_version).
"""
import fnmatch
import json
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from .models import Agent, AgentGroupMembership, DeviceGroup, DeviceGroupLink, InventorySnapshot

FIELDS = ("hostname", "os", "status", "agent_version")
OPERATORS = ("contains", "not_contains", "equals", "not_equals", "glob", "not_glob")
COMBINATORS = ("all", "any")

# Même seuil que `vanitasShared.jsx::isOnline` (frontend) — dupliqué ici en dur (langages
# différents) plutôt que dérivé d'une source commune ; documenté pour qu'un futur changement de
# seuil pense à mettre à jour les deux côtés.
ONLINE_THRESHOLD_HOURS = 24

# Garde-fou défensif — le contrôle de cycle à l'écriture (`would_create_cycle`) devrait déjà
# empêcher toute boucle, cette limite ne fait que borner un bug résiduel plutôt que boucler
# indéfiniment si l'invariant était un jour violé.
MAX_NESTING_DEPTH = 10


def normalize_rules(rules: dict | None) -> dict | None:
    """Valide/normalise une règle brute reçue de l'API — `None`/liste de conditions vide =
    "pas de règle" (groupe statique). Lève `ValueError` sur un champ/opérateur/combinateur
    inconnu plutôt que d'accepter silencieusement une règle qui ne matchera jamais rien."""
    if not rules:
        return None
    conditions = rules.get("conditions") or []
    if not conditions:
        return None
    combinator = rules.get("combinator", "all")
    if combinator not in COMBINATORS:
        raise ValueError(f"Combinateur invalide : {combinator!r} (attendu : {'/'.join(COMBINATORS)}).")
    normalized = []
    for c in conditions:
        field = c.get("field")
        operator = c.get("operator")
        value = (c.get("value") or "").strip()
        if field not in FIELDS:
            raise ValueError(f"Champ de règle invalide : {field!r} (attendu : {'/'.join(FIELDS)}).")
        if operator not in OPERATORS:
            raise ValueError(f"Opérateur de règle invalide : {operator!r} (attendu : {'/'.join(OPERATORS)}).")
        if not value:
            raise ValueError("La valeur d'une condition ne peut pas être vide.")
        normalized.append({"field": field, "operator": operator, "value": value})
    if not normalized:
        return None
    return {"combinator": combinator, "conditions": normalized}


def _is_online(agent: Agent) -> bool:
    if not agent.last_seen:
        return False
    last_seen = agent.last_seen
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - last_seen) < timedelta(hours=ONLINE_THRESHOLD_HOURS)


def _latest_os_by_agent(db: Session) -> dict[str, str]:
    """Dernier `os_caption` connu par agent — UN SEUL passage sur `inventory_snapshots` (trié
    par agent puis date décroissante), jamais une requête par agent (N+1)."""
    rows = (
        db.query(InventorySnapshot.agent_id, InventorySnapshot.os_caption, InventorySnapshot.collected_at)
        .order_by(InventorySnapshot.agent_id, InventorySnapshot.collected_at.desc())
        .all()
    )
    latest: dict[str, str] = {}
    for agent_id, os_caption, _collected_at in rows:
        if agent_id not in latest:
            latest[agent_id] = os_caption or ""
    return latest


def _condition_matches(actual: str, operator: str, target: str) -> bool:
    actual_l, target_l = actual.lower(), target.lower()
    if operator == "contains":
        return target_l in actual_l
    if operator == "not_contains":
        return target_l not in actual_l
    if operator == "equals":
        return actual_l == target_l
    if operator == "not_equals":
        return actual_l != target_l
    if operator == "glob":
        return fnmatch.fnmatch(actual_l, target_l)
    if operator == "not_glob":
        return not fnmatch.fnmatch(actual_l, target_l)
    return False


def agents_matching_rules(db: Session, rules: dict, all_agents: list[Agent] | None = None) -> list[Agent]:
    """Postes qui satisfont la règle dynamique d'un groupe — `all_agents` optionnel (déjà
    chargé par l'appelant, évite de reposer la même requête quand plusieurs groupes sont
    résolus dans le même appel, voir `group_ids_for_agents` ci-dessous)."""
    agents = all_agents if all_agents is not None else db.query(Agent).all()
    combinator = rules.get("combinator", "all")
    conditions = rules.get("conditions", [])
    if not conditions:
        return []
    os_by_agent = _latest_os_by_agent(db) if any(c["field"] == "os" for c in conditions) else {}
    matched = []
    for agent in agents:
        values = {
            "hostname": agent.hostname or "",
            "os": os_by_agent.get(agent.id, ""),
            "status": "online" if _is_online(agent) else "offline",
            "agent_version": agent.agent_version or "",
        }
        outcomes = [_condition_matches(values[c["field"]], c["operator"], c["value"]) for c in conditions]
        ok = all(outcomes) if combinator == "all" else any(outcomes)
        if ok:
            matched.append(agent)
    return matched


def would_create_cycle(db: Session, parent_group_id: str, child_group_id: str) -> bool:
    """`True` si imbriquer `child_group_id` DANS `parent_group_id` créerait un cycle — soit
    parce que c'est le même groupe, soit parce que `parent_group_id` est déjà un descendant
    (direct ou transitif) de `child_group_id` (auquel cas `child` finirait par se contenir
    lui-même une fois le lien ajouté). BFS bornée par le nombre de groupes existants, jamais
    plus qu'une poignée à l'échelle de ce projet."""
    if parent_group_id == child_group_id:
        return True
    seen: set[str] = set()
    queue = [child_group_id]
    while queue:
        current = queue.pop()
        if current == parent_group_id:
            return True
        if current in seen:
            continue
        seen.add(current)
        rows = db.query(DeviceGroupLink.child_group_id).filter(
            DeviceGroupLink.parent_group_id == current
        ).all()
        queue.extend(r[0] for r in rows)
    return False


def resolve_group_agents(
    db: Session,
    group: DeviceGroup,
    _all_agents: list[Agent] | None = None,
    _depth: int = 0,
    _visited: set[str] | None = None,
) -> list[Agent]:
    """Membres TOTAUX d'un groupe — union de (règle si dynamique) + (adhésions manuelles si
    statique) + (membres résolus récursivement de chaque groupe enfant imbriqué). `_visited`
    empêche un cycle résiduel de boucler indéfiniment (filet de sécurité — `would_create_cycle`
    devrait déjà l'empêcher à l'écriture) ; `MAX_NESTING_DEPTH` borne la profondeur pour la même
    raison défensive. `_all_agents` restreint l'univers considéré (voir `group_ids_for_agents`,
    qui l'appelle avec UN SEUL agent pour tester son appartenance sans tout recharger)."""
    visited = _visited if _visited is not None else set()
    if group.id in visited or _depth > MAX_NESTING_DEPTH:
        return []
    visited.add(group.id)
    all_agents = _all_agents if _all_agents is not None else db.query(Agent).all()

    by_id: dict[str, Agent] = {}
    if group.rules:
        for a in agents_matching_rules(db, json.loads(group.rules), all_agents=all_agents):
            by_id[a.id] = a
    else:
        memberships = db.query(AgentGroupMembership).filter(AgentGroupMembership.group_id == group.id).all()
        agent_ids = {m.agent_id for m in memberships}
        for a in all_agents:
            if a.id in agent_ids:
                by_id[a.id] = a

    child_links = db.query(DeviceGroupLink).filter(DeviceGroupLink.parent_group_id == group.id).all()
    for link in child_links:
        child = db.get(DeviceGroup, link.child_group_id)
        if child is None:
            continue
        for a in resolve_group_agents(db, child, _all_agents=all_agents, _depth=_depth + 1, _visited=visited):
            by_id[a.id] = a

    return list(by_id.values())


def group_ids_for_agents(db: Session, agents: list[Agent]) -> dict[str, list[str]]:
    """Remplace l'ex-`routes/agents.py::_group_ids_by_agent` — calcule, pour chaque poste, la
    liste des groupes dont il est membre (toutes sources confondues : règle, adhésion manuelle,
    appartenance via un groupe enfant imbriqué). Un seul passage sur tous les groupes, chacun
    résolu une fois avec `agents` comme univers restreint (coûte 1 résolution par groupe, pas
    1 par (groupe, agent))."""
    groups = db.query(DeviceGroup).all()
    result: dict[str, list[str]] = {a.id: [] for a in agents}
    for group in groups:
        members = resolve_group_agents(db, group, _all_agents=agents)
        member_ids = {a.id for a in members}
        for agent_id in result:
            if agent_id in member_ids:
                result[agent_id].append(group.id)
    return result
