"""Purge de rétention de l'historique — 2026-09-08, demande de Nicolas côté Pandore : "on peut
mettre en place le filtre de 7j/14j/30j/90j, et au-delà tu supprimes".

Décision de conception (tranchée avec Nicolas) : la donnée ne peut physiquement être supprimée
que côté serveur Vanitas (c'est là que vit la base SQLite), mais la DÉCISION — quand purger, à
quel seuil — est portée par Pandore (`backend/api_server.py`, une boucle de fond qui appelle
CETTE route périodiquement, même motif déjà en place pour `common/history.py`, rétention 90
jours). Ce module ne fait qu'exposer le mécanisme brut, jamais de planification ici.

Portée volontairement limitée aux tables qui grossissent réellement sans jamais être lues
au-delà du dernier snapshot (voir `models.py`) :
- `compliance_snapshots` (+ ses `compliance_results` enfants)
- `agent_commands`
- `inventory_snapshots` (+ ses `installed_apps` enfants)
- `audit_events` (2026-09-09, journal d'activité) — même raisonnement que `agent_commands` :
  donnée opérationnelle qui grossit à chaque mutation admin, pas un journal d'audit sécurité
  comme `shell_sessions` (voir la section suivante).

`shell_sessions`/`shell_session_events` sont EXCLUES DÉLIBÉRÉMENT (décision explicite de
Nicolas) : c'est un journal d'audit sécurité (qui a ouvert un shell SYSTEM sur quel poste,
quand — voir leur propre docstring dans models.py, "ne doit JAMAIS" être effacé même quand
l'agent lui-même est retiré), pas une simple donnée opérationnelle comme les trois ci-dessus.

Suppression en masse (`Query.delete()`), PAS via l'objet ORM un par un — à cette échelle, un
`db.delete(obj)` par ligne serait inutilement coûteux, et SQLite n'applique de toute façon
aucune cascade FK native (`PRAGMA foreign_keys` jamais activé, voir db.py) : les tables enfants
(`compliance_results`/`installed_apps`) sont donc supprimées EXPLICITEMENT par
`snapshot_id IN (...)` avant de supprimer leurs parents, pas via un cascade qui ne se
déclencherait pas sur ce chemin de suppression en masse.
"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import (
    AgentCommand,
    AuditEvent,
    ComplianceResult,
    ComplianceSnapshot,
    InstalledApp,
    InventorySnapshot,
)
from ..security import require_shell_token

router = APIRouter(tags=["maintenance"])

# Garde-fou : un appelant qui passerait `days=0` (ou une valeur trop petite) purgerait la quasi
# totalité de l'historique en un seul appel — sans intérêt légitime pour cette route (le plus
# court des filtres d'affichage proposés côté Pandore est 7 jours), donc refusé ici plutôt que
# de faire confiance à l'appelant. Pas de plafond haut : un `days` très grand se contente de ne
# rien supprimer, sans risque.
_MIN_RETENTION_DAYS = 7


class PurgeHistoryIn(BaseModel):
    days: int = Field(ge=_MIN_RETENTION_DAYS)


class PurgeHistoryOut(BaseModel):
    cutoff: datetime
    compliance_snapshots_deleted: int
    compliance_results_deleted: int
    agent_commands_deleted: int
    inventory_snapshots_deleted: int
    installed_apps_deleted: int
    audit_events_deleted: int


@router.post(
    "/maintenance/purge-history",
    response_model=PurgeHistoryOut,
    dependencies=[Depends(require_shell_token)],
)
def purge_history(payload: PurgeHistoryIn, db: Session = Depends(get_db)) -> PurgeHistoryOut:
    cutoff = datetime.now(timezone.utc) - timedelta(days=payload.days)

    old_compliance_snapshot_ids = [
        row[0]
        for row in db.query(ComplianceSnapshot.id).filter(ComplianceSnapshot.collected_at < cutoff).all()
    ]
    compliance_results_deleted = 0
    if old_compliance_snapshot_ids:
        compliance_results_deleted = (
            db.query(ComplianceResult)
            .filter(ComplianceResult.snapshot_id.in_(old_compliance_snapshot_ids))
            .delete(synchronize_session=False)
        )
    compliance_snapshots_deleted = (
        db.query(ComplianceSnapshot)
        .filter(ComplianceSnapshot.collected_at < cutoff)
        .delete(synchronize_session=False)
    )

    old_inventory_snapshot_ids = [
        row[0]
        for row in db.query(InventorySnapshot.id).filter(InventorySnapshot.collected_at < cutoff).all()
    ]
    installed_apps_deleted = 0
    if old_inventory_snapshot_ids:
        installed_apps_deleted = (
            db.query(InstalledApp)
            .filter(InstalledApp.snapshot_id.in_(old_inventory_snapshot_ids))
            .delete(synchronize_session=False)
        )
    inventory_snapshots_deleted = (
        db.query(InventorySnapshot)
        .filter(InventorySnapshot.collected_at < cutoff)
        .delete(synchronize_session=False)
    )

    agent_commands_deleted = (
        db.query(AgentCommand).filter(AgentCommand.created_at < cutoff).delete(synchronize_session=False)
    )

    audit_events_deleted = (
        db.query(AuditEvent).filter(AuditEvent.created_at < cutoff).delete(synchronize_session=False)
    )

    db.commit()

    return PurgeHistoryOut(
        cutoff=cutoff,
        compliance_snapshots_deleted=compliance_snapshots_deleted,
        compliance_results_deleted=compliance_results_deleted,
        agent_commands_deleted=agent_commands_deleted,
        inventory_snapshots_deleted=inventory_snapshots_deleted,
        installed_apps_deleted=installed_apps_deleted,
        audit_events_deleted=audit_events_deleted,
    )
