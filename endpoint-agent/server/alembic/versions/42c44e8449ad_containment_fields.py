"""containment_fields

Revision ID: 42c44e8449ad
Revises: 8bb28607a95e
Create Date: 2026-09-17 17:12:59.601610

Jalon "confinement" (mini-EDR, 2026-09-17) — 5 colonnes d'état sur `agents` (voir le docstring
de `Agent.network_isolated`, app/models.py). `network_isolated` a un `server_default` (colonne
NOT NULL sur une table qui a déjà des lignes) ; les 4 autres sont nullables, aucun défaut requis.

Le brouillon autogénéré incluait aussi des dérives de schéma préexistantes SANS RAPPORT avec ce
jalon (types `TEXT`→`String(N)` sur `agent_commands.actor`/`agents.agent_version`/
`device_groups.pattern`/6 colonnes `inventory_snapshots.os_*`, `agent_commands.result` `VARCHAR
(4000)`→`Text`, et `agents.drop_column('group_id')` — la colonne orpheline documentée dans
`models.py` depuis le passage au many-to-many) : retirées manuellement, comme à chaque
précédente migration de ce projet, pour garder cette révision scopée à ce qu'elle prétend faire.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import app.models  # noqa: F401 — type de colonne personnalisé UTCDateTime (voir app/models.py)


revision: str = '42c44e8449ad'
down_revision: Union[str, None] = '8bb28607a95e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('agents', schema=None) as batch_op:
        batch_op.add_column(sa.Column('network_isolated', sa.Boolean(), nullable=False, server_default=sa.false()))
        batch_op.add_column(sa.Column('network_isolated_at', app.models.UTCDateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('network_isolated_by', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('network_isolated_reason', sa.String(length=500), nullable=True))
        batch_op.add_column(sa.Column('network_isolated_event_id', sa.String(length=32), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('agents', schema=None) as batch_op:
        batch_op.drop_column('network_isolated_event_id')
        batch_op.drop_column('network_isolated_reason')
        batch_op.drop_column('network_isolated_by')
        batch_op.drop_column('network_isolated_at')
        batch_op.drop_column('network_isolated')
