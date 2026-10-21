"""Écriture du journal d'activité (2026-09-09) — un seul point d'entrée pour toutes les routes
qui doivent enregistrer une mutation admin, afin que la forme des lignes `AuditEvent` ne
diverge jamais d'un point d'écriture à l'autre. Voir `models.py::AuditEvent` pour le contrat de
champs et `routes/activity.py` pour la lecture fusionnée avec `AgentCommand`.
"""
from sqlalchemy.orm import Session

from .models import AuditEvent

CATEGORIES: frozenset[str] = frozenset({"poste", "application", "conformite", "groupe"})


def record_event(
    db: Session,
    category: str,
    action: str,
    target_label: str,
    actor: str | None = None,
    detail: str | None = None,
) -> None:
    """N'appelle PAS `db.commit()` — la route appelante commite l'événement dans LA MÊME
    transaction que la mutation qu'il décrit (créer la règle/le groupe/l'installeur ET
    journaliser l'action doivent réussir ou échouer ensemble, jamais l'un sans l'autre)."""
    if category not in CATEGORIES:
        raise ValueError(f"Catégorie de journal inconnue : {category!r}")
    db.add(
        AuditEvent(category=category, action=action, target_label=target_label, actor=actor, detail=detail)
    )
