"""ICMP reachability monitoring (targets and state-change log)

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-27 12:00:00.000000

Additive only: two new tables. Probe results live in ClickHouse (icmp_results).
"""
from alembic import op
import sqlalchemy as sa


revision = '0011'
down_revision = '0010'
branch_labels = None
depends_on = None
TZ = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        'icmp_targets',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(128), nullable=False),
        sa.Column('address', sa.String(255), nullable=False, unique=True),
        sa.Column('isp_link_id', sa.Integer(), sa.ForeignKey('isp_links.id', ondelete='SET NULL'), nullable=True),
        sa.Column('isp_name', sa.String(128), nullable=False, server_default=''),
        sa.Column('site', sa.String(128), nullable=False, server_default=''),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('interval_seconds', sa.Integer(), nullable=False, server_default='30'),
        sa.Column('probes', sa.Integer(), nullable=False, server_default='3'),
        sa.Column('timeout_ms', sa.Integer(), nullable=False, server_default='1000'),
        sa.Column('down_after', sa.Integer(), nullable=False, server_default='3'),
        sa.Column('up_after', sa.Integer(), nullable=False, server_default='2'),
        sa.Column('rtt_warn_ms', sa.Float(), nullable=False, server_default='150'),
        sa.Column('loss_warn_pct', sa.Float(), nullable=False, server_default='20'),
        sa.Column('state', sa.String(16), nullable=False, server_default='unknown'),
        sa.Column('state_since', TZ, nullable=True),
        sa.Column('fail_streak', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('ok_streak', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_check', TZ, nullable=True),
        sa.Column('last_rtt_ms', sa.Float(), nullable=True),
        sa.Column('last_loss_pct', sa.Float(), nullable=True),
        sa.Column('created_by', sa.String(64), nullable=False, server_default=''),
        sa.Column('created_at', TZ, nullable=False),
    )
    op.create_table(
        'icmp_events',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('target_id', sa.Integer(), sa.ForeignKey('icmp_targets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('at', TZ, nullable=False),
        sa.Column('from_state', sa.String(16), nullable=False),
        sa.Column('to_state', sa.String(16), nullable=False),
        sa.Column('previous_duration_s', sa.Integer(), nullable=True),
        sa.Column('detail', sa.Text(), nullable=False, server_default=''),
    )
    op.create_index('ix_icmp_events_target_id', 'icmp_events', ['target_id'])
    op.create_index('ix_icmp_events_at', 'icmp_events', ['at'])


def downgrade() -> None:
    op.drop_table('icmp_events')
    op.drop_table('icmp_targets')
