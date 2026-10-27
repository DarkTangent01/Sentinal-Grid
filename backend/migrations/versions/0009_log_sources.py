"""non-FortiGate log sources (Windows, CEF, syslog)

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-26 22:00:00.000000

Additive only: one new table.
"""
from alembic import op
import sqlalchemy as sa


revision = '0009'
down_revision = '0008'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'log_sources',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(64), nullable=False, unique=True),
        sa.Column('kind', sa.String(16), nullable=False, server_default='windows'),
        sa.Column('source_ips', sa.JSON(), nullable=False),
        sa.Column('site', sa.String(64), nullable=False, server_default=''),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('events_total', sa.BigInteger(), nullable=False, server_default='0'),
        sa.Column('last_event_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_by', sa.String(64), nullable=False, server_default=''),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table('log_sources')
