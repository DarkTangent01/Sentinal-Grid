"""hunting, watchlists, workbooks, automation playbooks

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-26 12:00:00.000000

Additive only: new tables. Custom detections reuse alert_rules (key prefix cq_), so no change there.
"""
from alembic import op
import sqlalchemy as sa


revision = '0006'
down_revision = '0005'
branch_labels = None
depends_on = None

TZ = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        'watchlists',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(64), nullable=False, unique=True),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('kind', sa.String(16), nullable=False, server_default='ip'),
        sa.Column('created_by', sa.String(64), nullable=False),
        sa.Column('created_at', TZ, nullable=False),
        sa.Column('updated_at', TZ, nullable=False),
    )
    op.create_table(
        'watchlist_items',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('watchlist_id', sa.Integer(), sa.ForeignKey('watchlists.id', ondelete='CASCADE'), nullable=False),
        sa.Column('value', sa.String(255), nullable=False),
        sa.Column('label', sa.String(255), nullable=False, server_default=''),
        sa.Column('added_by', sa.String(64), nullable=False, server_default=''),
        sa.Column('expires_at', TZ, nullable=True),
        sa.Column('created_at', TZ, nullable=False),
        sa.UniqueConstraint('watchlist_id', 'value', name='uq_watchlist_value'),
    )
    op.create_index('ix_watchlist_items_watchlist_id', 'watchlist_items', ['watchlist_id'])
    op.create_table(
        'hunting_queries',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('key', sa.String(64), nullable=True, unique=True),
        sa.Column('name', sa.String(128), nullable=False),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('query', sa.Text(), nullable=False),
        sa.Column('range', sa.String(8), nullable=False, server_default='24h'),
        sa.Column('tactic', sa.String(16), nullable=False, server_default=''),
        sa.Column('techniques', sa.JSON(), nullable=False),
        sa.Column('builtin', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('author', sa.String(64), nullable=False, server_default='system'),
        sa.Column('last_run', TZ, nullable=True),
        sa.Column('last_count', sa.BigInteger(), nullable=True),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.Column('created_at', TZ, nullable=False),
    )
    op.create_table(
        'bookmarks',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(128), nullable=False),
        sa.Column('query', sa.Text(), nullable=False),
        sa.Column('window_start', TZ, nullable=True),
        sa.Column('window_end', TZ, nullable=True),
        sa.Column('columns', sa.JSON(), nullable=False),
        sa.Column('rows', sa.JSON(), nullable=False),
        sa.Column('notes', sa.Text(), nullable=False, server_default=''),
        sa.Column('tags', sa.JSON(), nullable=False),
        sa.Column('incident_id', sa.Integer(), sa.ForeignKey('incidents.id', ondelete='SET NULL'), nullable=True),
        sa.Column('created_by', sa.String(64), nullable=False),
        sa.Column('created_at', TZ, nullable=False),
    )
    op.create_index('ix_bookmarks_incident_id', 'bookmarks', ['incident_id'])
    op.create_table(
        'workbooks',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('key', sa.String(64), nullable=True, unique=True),
        sa.Column('name', sa.String(128), nullable=False),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('range', sa.String(8), nullable=False, server_default='24h'),
        sa.Column('panels', sa.JSON(), nullable=False),
        sa.Column('owner', sa.String(64), nullable=False),
        sa.Column('shared', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('created_at', TZ, nullable=False),
        sa.Column('updated_at', TZ, nullable=False),
    )
    op.create_table(
        'automation_rules',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(128), nullable=False),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('priority', sa.Integer(), nullable=False, server_default='100'),
        sa.Column('trigger', sa.String(32), nullable=False),
        sa.Column('conditions', sa.JSON(), nullable=False),
        sa.Column('actions', sa.JSON(), nullable=False),
        sa.Column('stop_processing', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('created_by', sa.String(64), nullable=False),
        sa.Column('run_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_run', TZ, nullable=True),
        sa.Column('created_at', TZ, nullable=False),
        sa.Column('updated_at', TZ, nullable=False),
    )
    op.create_table(
        'automation_runs',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('rule_id', sa.Integer(), sa.ForeignKey('automation_rules.id', ondelete='SET NULL'), nullable=True),
        sa.Column('rule_name', sa.String(128), nullable=False),
        sa.Column('at', TZ, nullable=False),
        sa.Column('trigger', sa.String(32), nullable=False),
        sa.Column('target_type', sa.String(16), nullable=False),
        sa.Column('target_id', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(16), nullable=False),
        sa.Column('results', sa.JSON(), nullable=False),
    )
    op.create_index('ix_automation_runs_rule_id', 'automation_runs', ['rule_id'])
    op.create_index('ix_automation_runs_at', 'automation_runs', ['at'])


def downgrade() -> None:
    for t in ('automation_runs', 'automation_rules', 'workbooks', 'bookmarks', 'hunting_queries', 'watchlist_items', 'watchlists'):
        op.drop_table(t)
