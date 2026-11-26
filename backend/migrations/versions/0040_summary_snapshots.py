"""Precomputed dashboard summaries (SOC executive summary, SOC operations), refreshed by the worker (app/socmetrics.py)

Revision ID: 0040
Revises: 0039
Create Date: 2026-11-26 07:00:00.000000

Additive: one new table. Downgrade drops it.
"""
from alembic import op
import sqlalchemy as sa


revision = '0040'
down_revision = '0039'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'summary_snapshots',
        sa.Column('key', sa.String(64), primary_key=True, nullable=False),
        sa.Column('computed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('seconds', sa.Float(), nullable=False),
        sa.Column('requested_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('data', sa.JSON(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table('summary_snapshots')
