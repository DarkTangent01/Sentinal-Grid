"""incident task checklists and linked incidents

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-26 21:00:00.000000

Additive only: two JSON columns on incidents (existing rows get empty lists).
"""
from alembic import op
import sqlalchemy as sa


revision = '0008'
down_revision = '0007'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('incidents', schema=None) as batch_op:
        batch_op.add_column(sa.Column('tasks', sa.JSON(), nullable=False, server_default='[]'))
        batch_op.add_column(sa.Column('linked', sa.JSON(), nullable=False, server_default='[]'))


def downgrade() -> None:
    with op.batch_alter_table('incidents', schema=None) as batch_op:
        batch_op.drop_column('linked')
        batch_op.drop_column('tasks')
