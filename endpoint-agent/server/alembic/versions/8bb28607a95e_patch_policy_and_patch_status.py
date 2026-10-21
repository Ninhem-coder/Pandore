"""patch policy and patch status

Revision ID: 8bb28607a95e
Revises: 1155bbeeee48
Create Date: 2026-09-17 14:46:24.674822

Trimmé à la main après `alembic revision --autogenerate` (voir docs/internal/ARCHITECTURE.md §5) : le
diff brut incluait aussi une pile de changements de TYPE cosmétiques (Text vs String(N)) sur
des colonnes sans rapport, issus de scripts de migration manuels d'avant le passage à Alembic
(2026-09-12) qui avaient déclaré des types légèrement différents de ceux de `models.py` —
SQLite n'applique de toute façon jamais la longueur déclarée d'un `String(N)`, ces écarts sont
purement déclaratifs, jamais une vraie incompatibilité. Les inclure aurait déclenché des
reconstructions de table (`batch_alter_table`) sans rapport avec ce jalon — retirés pour garder
cette migration scopée à ce qu'elle annonce. Même chose pour `agents.drop_column('group_id')`
(colonne orpheline déjà documentée dans `models.py`, retrait à traiter séparément si besoin).

`agent_packages` INCLUS ici bien que sans rapport direct avec les mises à jour Windows : gap
réel découvert en générant ce diff — le modèle `AgentPackage` existe dans `models.py` depuis le
jalon "mise à jour de l'agent" (2026-09-11) mais la baseline Alembic (générée le 2026-09-12) ne
l'a jamais capturé, et `Base.metadata.create_all()` n'est plus appelé au démarrage depuis le
même jour — la table n'existe donc PAS sur la vraie base (confirmé par une lecture directe le
2026-09-14, absente de la liste de tables). Sans ce correctif, toute mise à jour d'agent réelle
échouerait avec "no such table: agent_packages". Vérifié fraîchement AVANT d'appliquer cette
migration que la table est toujours absente sur la vraie base (pas de risque de "already
exists" — même piège que le 2026-09-14 sur les autres tables).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import app.models  # noqa: F401 — type de colonne personnalisé UTCDateTime (voir app/models.py)


revision: str = '8bb28607a95e'
down_revision: Union[str, None] = '1155bbeeee48'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Conditionnel (2026-10-21) : la baseline `b9d83b65afca` crée AUSSI `agent_packages` — sur
    # une base NEUVE, ce `create_table` inconditionnel échouait ("table agent_packages already
    # exists") et le serveur ne démarrait jamais (constaté à la 1re installation sur un poste
    # vierge). La base de prod, stampée sur une baseline sans cette table, en a toujours besoin
    # ici — d'où le test d'existence plutôt qu'un retrait pur et simple.
    if not sa.inspect(op.get_bind()).has_table('agent_packages'):
        op.create_table('agent_packages',
        sa.Column('id', sa.String(length=32), nullable=False),
        sa.Column('version', sa.String(length=100), nullable=False),
        sa.Column('original_filename', sa.String(length=255), nullable=False),
        sa.Column('sha256', sa.String(length=64), nullable=False),
        sa.Column('size_bytes', sa.Integer(), nullable=False),
        sa.Column('uploaded_at', app.models.UTCDateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
        )
    op.create_table('patch_status',
    sa.Column('agent_id', sa.String(length=32), nullable=False),
    sa.Column('available_json', sa.Text(), nullable=False),
    sa.Column('todo_json', sa.Text(), nullable=False),
    sa.Column('in_progress_json', sa.Text(), nullable=False),
    sa.Column('installed_json', sa.Text(), nullable=False),
    sa.Column('installed_at', app.models.UTCDateTime(timezone=True), nullable=True),
    sa.Column('forced_at', app.models.UTCDateTime(timezone=True), nullable=True),
    sa.Column('updated_at', app.models.UTCDateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('agent_id')
    )
    with op.batch_alter_table('device_groups', schema=None) as batch_op:
        batch_op.add_column(sa.Column('patch_enabled', sa.Boolean(), nullable=False, server_default=sa.false()))
        batch_op.add_column(sa.Column('patch_window_start', sa.String(length=5), nullable=True))
        batch_op.add_column(sa.Column('patch_window_end', sa.String(length=5), nullable=True))
        batch_op.add_column(sa.Column('patch_grace_days', sa.Integer(), nullable=False, server_default='5'))


def downgrade() -> None:
    with op.batch_alter_table('device_groups', schema=None) as batch_op:
        batch_op.drop_column('patch_grace_days')
        batch_op.drop_column('patch_window_end')
        batch_op.drop_column('patch_window_start')
        batch_op.drop_column('patch_enabled')

    op.drop_table('patch_status')
    op.drop_table('agent_packages')
