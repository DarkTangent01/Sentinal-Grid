"""Switch topology: LLDP / CDP neighbors per switch port

Revision ID: 0016
Revises: 0015
Create Date: 2026-10-28 20:00:00.000000

Additive only: one new table.
"""
from alembic import op
import sqlalchemy as sa


revision = '0016'
down_revision = '0015'
branch_labels = None
depends_on = None
TZ = sa.DateTime(timezone=True)


def upgrade() -> None:
    s = lambda n, size: sa.Column(n, sa.String(size), nullable=False, server_default='')  # noqa: E731
    op.create_table(
        'switch_neighbors',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('switch_id', sa.Integer(), sa.ForeignKey('switches.id', ondelete='CASCADE'), nullable=False),
        sa.Column('local_ifindex', sa.BigInteger(), nullable=True), s('local_port', 128),
        sa.Column('remote_key', sa.String(255), nullable=False), sa.Column('protocol', sa.String(16), nullable=False, server_default='lldp'),
        s('remote_name', 255), s('chassis_id', 128), s('remote_port', 128), s('remote_port_desc', 255), s('remote_mgmt_ip', 64), s('remote_descr', 300),
        sa.Column('capabilities', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('present', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('first_seen', TZ, nullable=False, server_default=sa.func.now()), sa.Column('last_seen', TZ, nullable=True),
        sa.UniqueConstraint('switch_id', 'local_ifindex', 'remote_key', name='uq_switch_neighbor'),
    )
    op.create_index('ix_switch_neighbors_switch_id', 'switch_neighbors', ['switch_id'])


def downgrade() -> None:
    op.drop_table('switch_neighbors')
