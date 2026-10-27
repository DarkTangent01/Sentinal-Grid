"""BGP peer inventory and live state (from the read-only firewall APIs)

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-27 14:00:00.000000

Additive only: one new table. Samples and route/peer events live in ClickHouse (bgp_samples, bgp_events).
"""
from alembic import op
import sqlalchemy as sa


revision = '0012'
down_revision = '0011'
branch_labels = None
depends_on = None
TZ = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        'bgp_peers',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('firewall_id', sa.Integer(), sa.ForeignKey('firewalls.id', ondelete='CASCADE'), nullable=False),
        sa.Column('peer_ip', sa.String(64), nullable=False),
        sa.Column('remote_as', sa.BigInteger(), nullable=True),
        sa.Column('local_ip', sa.String(64), nullable=False, server_default=''),
        sa.Column('peer_type', sa.String(32), nullable=False, server_default=''),
        sa.Column('admin_status', sa.String(32), nullable=False, server_default=''),
        sa.Column('state', sa.String(32), nullable=False, server_default='unknown'),
        sa.Column('state_since', TZ, nullable=True),
        sa.Column('prefixes', sa.Integer(), nullable=True),
        sa.Column('routes', sa.JSON(), nullable=True),
        sa.Column('routes_truncated', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('last_polled_at', TZ, nullable=True),
        sa.Column('first_seen', TZ, nullable=False),
        sa.UniqueConstraint('firewall_id', 'peer_ip', name='uq_bgp_peer'),
    )
    op.create_index('ix_bgp_peers_firewall_id', 'bgp_peers', ['firewall_id'])


def downgrade() -> None:
    op.drop_table('bgp_peers')
