"""Conformité — jalon 11.

Trois familles de routes, même découpage mixte que `routes/shell.py` :
- Côté AGENT (`/agents/{agent_id}/compliance/...`) — mTLS via `get_current_agent`, le catalogue
  des règles ACTIVÉES (avec leur script complet, l'agent en a besoin pour les exécuter) et le
  dépôt des résultats d'un cycle de vérification.
- Côté DASHBOARD (`require_shell_token`, 2026-09-07 — voir `routes/agents.py`/`routes/
  commands.py` pour la revue de sécurité qui a généralisé ce correctif) — même secret partagé
  sur TOUTES les routes dashboard, y compris les "simples" lectures de résultats : elles
  exposent quand même hostnames/état/preuve texte de tout le parc.
- Côté DASHBOARD, gestion du catalogue (`require_shell_token`) — lire le catalogue COMPLET (avec
  `script_content`) et le créer/éditer/supprimer : définir du code qui s'exécute en SYSTEM sur
  tout le parc, sans surveillance, est une action bien plus sensible qu'une simple lecture de
  résultats, jamais exposée sans le secret partagé déjà en place pour le jalon 9.
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..models import Agent, ComplianceResult, ComplianceRule, ComplianceSnapshot
from ..security import get_actor, get_current_agent, require_shell_token

router = APIRouter(tags=["compliance"])


def _latest_snapshot(db: Session, agent_id: str) -> ComplianceSnapshot | None:
    return (
        db.query(ComplianceSnapshot)
        .filter(ComplianceSnapshot.agent_id == agent_id)
        .order_by(ComplianceSnapshot.collected_at.desc())
        .first()
    )


# ── Côté agent (mTLS) ────────────────────────────────────────────────────────────────────────


class AgentRuleOut(BaseModel):
    id: str
    name: str
    script_content: str


@router.get("/agents/{agent_id}/compliance/rules", response_model=list[AgentRuleOut])
def get_rules_for_agent(
    agent_id: str,
    agent: Agent = Depends(get_current_agent),
    db: Session = Depends(get_db),
) -> list[AgentRuleOut]:
    if agent.id != agent_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Ce certificat ne correspond pas à cet agent.")

    rules = db.query(ComplianceRule).filter(ComplianceRule.enabled.is_(True)).all()
    return [AgentRuleOut(id=r.id, name=r.name, script_content=r.script_content) for r in rules]


class ComplianceResultIn(BaseModel):
    rule_id: str
    rule_name: str
    compliant: bool | None  # None = erreur d'exécution (timeout/échec de lancement)
    detail: str | None = None


class ComplianceResultsIn(BaseModel):
    results: list[ComplianceResultIn]


@router.post("/agents/{agent_id}/compliance/results")
def post_compliance_results(
    agent_id: str,
    payload: ComplianceResultsIn,
    agent: Agent = Depends(get_current_agent),
    db: Session = Depends(get_db),
) -> dict:
    if agent.id != agent_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Ce certificat ne correspond pas à cet agent.")

    snapshot = ComplianceSnapshot(agent_id=agent_id)
    db.add(snapshot)
    db.flush()  # obtenir snapshot.id avant d'ajouter les résultats enfants

    for r in payload.results:
        db.add(
            ComplianceResult(
                snapshot_id=snapshot.id,
                rule_id=r.rule_id,
                rule_name=r.rule_name,
                compliant=r.compliant,
                detail=r.detail,
            )
        )
    db.commit()
    return {"ok": True, "snapshot_id": snapshot.id}


# ── Côté dashboard, lecture libre ────────────────────────────────────────────────────────────


class RuleSummaryOut(BaseModel):
    id: str
    name: str
    enabled: bool
    updated_at: datetime


@router.get(
    "/compliance/rules/summary",
    response_model=list[RuleSummaryOut],
    dependencies=[Depends(require_shell_token)],
)
def list_rules_summary(db: Session = Depends(get_db)) -> list[RuleSummaryOut]:
    """JAMAIS `script_content` ici — c'est le code qui s'exécute en SYSTEM sur tout le parc,
    voir `require_shell_token` pour le catalogue complet plus bas."""
    rules = db.query(ComplianceRule).order_by(ComplianceRule.name).all()
    return [RuleSummaryOut(id=r.id, name=r.name, enabled=r.enabled, updated_at=r.updated_at) for r in rules]


class ComplianceResultOut(BaseModel):
    rule_id: str
    rule_name: str
    compliant: bool | None
    detail: str | None


class AgentComplianceOut(BaseModel):
    agent_id: str
    hostname: str
    collected_at: datetime | None
    results: list[ComplianceResultOut]


@router.get(
    "/agents/{agent_id}/compliance",
    response_model=AgentComplianceOut,
    dependencies=[Depends(require_shell_token)],
)
def get_agent_compliance(agent_id: str, db: Session = Depends(get_db)) -> AgentComplianceOut:
    agent = db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Agent inconnu.")

    snapshot = _latest_snapshot(db, agent_id)
    results = (
        [
            ComplianceResultOut(
                rule_id=r.rule_id, rule_name=r.rule_name, compliant=r.compliant, detail=r.detail
            )
            for r in snapshot.results
        ]
        if snapshot
        else []
    )
    return AgentComplianceOut(
        agent_id=agent.id,
        hostname=agent.hostname,
        collected_at=snapshot.collected_at if snapshot else None,
        results=results,
    )


class RuleFleetSummaryOut(BaseModel):
    rule_id: str
    rule_name: str
    compliant_count: int
    non_compliant_count: int
    error_count: int


@router.get(
    "/compliance/summary",
    response_model=list[RuleFleetSummaryOut],
    dependencies=[Depends(require_shell_token)],
)
def get_compliance_summary(db: Session = Depends(get_db)) -> list[RuleFleetSummaryOut]:
    """Agrégat fleet-wide par règle, classé par impact (le plus de postes en échec en premier)
    — même motif que `vulnerabilities.py::get_top_vulnerabilities` : itère les agents, prend le
    dernier snapshot de chacun, agrège en mémoire plutôt qu'une table matérialisée dédiée
    (disproportionné à l'échelle de ce projet)."""
    agents = db.query(Agent).all()
    by_rule: dict[str, RuleFleetSummaryOut] = {}

    for agent in agents:
        snapshot = _latest_snapshot(db, agent.id)
        if snapshot is None:
            continue
        for r in snapshot.results:
            entry = by_rule.get(r.rule_id)
            if entry is None:
                entry = RuleFleetSummaryOut(
                    rule_id=r.rule_id, rule_name=r.rule_name,
                    compliant_count=0, non_compliant_count=0, error_count=0,
                )
                by_rule[r.rule_id] = entry
            if r.compliant is None:
                entry.error_count += 1
            elif r.compliant:
                entry.compliant_count += 1
            else:
                entry.non_compliant_count += 1

    return sorted(by_rule.values(), key=lambda e: (-e.non_compliant_count, -e.error_count))


# ── Côté dashboard, gestion du catalogue (secret partagé) ───────────────────────────────────


class RuleOut(BaseModel):
    id: str
    name: str
    script_content: str
    enabled: bool
    created_at: datetime
    updated_at: datetime


def _to_rule_out(rule: ComplianceRule) -> RuleOut:
    return RuleOut(
        id=rule.id, name=rule.name, script_content=rule.script_content,
        enabled=rule.enabled, created_at=rule.created_at, updated_at=rule.updated_at,
    )


@router.get(
    "/compliance/rules",
    response_model=list[RuleOut],
    dependencies=[Depends(require_shell_token)],
)
def list_rules(db: Session = Depends(get_db)) -> list[RuleOut]:
    rules = db.query(ComplianceRule).order_by(ComplianceRule.name).all()
    return [_to_rule_out(r) for r in rules]


class CreateRuleIn(BaseModel):
    name: str
    script_content: str


@router.post(
    "/compliance/rules",
    response_model=RuleOut,
    dependencies=[Depends(require_shell_token)],
)
def create_rule(
    payload: CreateRuleIn, db: Session = Depends(get_db), actor: str | None = Depends(get_actor)
) -> RuleOut:
    if not payload.name.strip() or not payload.script_content.strip():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Nom et script sont obligatoires.")

    # `enabled` toujours forcé à False à la création, jamais fait confiance à un éventuel champ
    # du payload pour ce point précis — voir ComplianceRule.enabled.
    rule = ComplianceRule(name=payload.name.strip(), script_content=payload.script_content, enabled=False)
    db.add(rule)
    audit.record_event(db, "conformite", "created", rule.name, actor=actor)
    db.commit()
    db.refresh(rule)
    return _to_rule_out(rule)


class UpdateRuleIn(BaseModel):
    name: str | None = None
    script_content: str | None = None
    enabled: bool | None = None


@router.put(
    "/compliance/rules/{rule_id}",
    response_model=RuleOut,
    dependencies=[Depends(require_shell_token)],
)
def update_rule(
    rule_id: str, payload: UpdateRuleIn, db: Session = Depends(get_db), actor: str | None = Depends(get_actor)
) -> RuleOut:
    rule = db.get(ComplianceRule, rule_id)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Règle introuvable.")
    was_enabled = rule.enabled

    if payload.name is not None:
        if not payload.name.strip():
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Le nom ne peut pas être vide.")
        rule.name = payload.name.strip()
    script_changed = False
    if payload.script_content is not None:
        if not payload.script_content.strip():
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Le script ne peut pas être vide.")
        script_changed = payload.script_content != rule.script_content
        rule.script_content = payload.script_content

    # 🔧 Bug de sécurité corrigé le 2026-09-07 : `ComplianceRule.enabled`/le README documentent
    # l'invariant "toute règle créée OU ÉDITÉE repart à enabled=False" — déjà correct dans
    # `create_rule`, mais PAS ici : éditer le script d'une règle déjà active laissait
    # `rule.enabled` inchangé si `payload.enabled` était omis (le cas normal pour "corriger une
    # faute de frappe"), poussant le nouveau script en direct sur tout le parc au prochain cycle
    # SANS le second geste explicite ("Activer") que ce garde-fou est censé exiger. Forcé à
    # False dès que le script change, sauf si l'appelant redemande explicitement `enabled=true`
    # dans la MÊME requête (repasser par le formulaire d'activation volontairement, pas un oubli
    # silencieux de désactivation).
    if payload.enabled is not None:
        rule.enabled = payload.enabled
    elif script_changed:
        rule.enabled = False

    rule.updated_at = datetime.now(timezone.utc)

    # Journal d'activité (2026-09-09) — distingue "activé"/"désactivé" d'un simple "modifié" :
    # le premier est le geste que le garde-fou ci-dessus est spécifiquement conçu pour exiger
    # (un second geste EXPLICITE avant qu'un script parte en direct sur tout le parc), mérite
    # donc son propre libellé plutôt que de se fondre dans "modifié".
    if rule.enabled != was_enabled:
        action = "enabled" if rule.enabled else "disabled"
    else:
        action = "updated"
    audit.record_event(db, "conformite", action, rule.name, actor=actor)

    db.commit()
    db.refresh(rule)
    return _to_rule_out(rule)


@router.delete("/compliance/rules/{rule_id}", dependencies=[Depends(require_shell_token)])
def delete_rule(
    rule_id: str, db: Session = Depends(get_db), actor: str | None = Depends(get_actor)
) -> dict:
    rule = db.get(ComplianceRule, rule_id)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Règle introuvable.")

    audit.record_event(db, "conformite", "deleted", rule.name, actor=actor)
    db.delete(rule)
    db.commit()
    return {"ok": True}
