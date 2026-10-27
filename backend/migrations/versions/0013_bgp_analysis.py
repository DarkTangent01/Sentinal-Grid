"""BGP analysis: neighbor tunnel / config / prefix history, per-firewall routing and configuration snapshot

Revision ID: 0013
Revises: 0012
Create Date: 2026-10-27 16:00:00.000000

Additive only: three nullable columns on bgp_peers and one new table.
"""
from alembic import op
import sqlalchemy as sa


revision = '0013'
down_revision = '0012'
branch_labels = None
depends_on = None
TZ = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.add_column('bgp_peers', sa.Column('interface', sa.String(64), nullable=False, server_default=''))
    op.add_column('bgp_peers', sa.Column('config', sa.JSON(), nullable=True))
    op.add_column('bgp_peers', sa.Column('known_prefixes', sa.JSON(), nullable=True))
    op.create_table(
        'bgp_routers',
        sa.Column('firewall_id', sa.Integer(), sa.ForeignKey('firewalls.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('local_as', sa.BigInteger(), nullable=True),
        sa.Column('router_id', sa.String(64), nullable=False, server_default=''),
        sa.Column('config', sa.JSON(), nullable=True),
        sa.Column('audit', sa.JSON(), nullable=True),
        sa.Column('config_polled_at', TZ, nullable=True),
        sa.Column('rib', sa.JSON(), nullable=True),
        sa.Column('rib_polled_at', TZ, nullable=True),
    )


def downgrade() -> None:
    op.drop_table('bgp_routers')
    op.drop_column('bgp_peers', 'known_prefixes')
    op.drop_column('bgp_peers', 'config')
    op.drop_column('bgp_peers', 'interface')
