"""Shared identity index: devices by MAC (vendor, type, OS, name, connection point, user) and the IP ↔ MAC / IP ↔ user
timelines both products contribute to and read (app/platform/identity.py)

Revision ID: 0039
Revises: 0038
Create Date: 2026-11-25 15:00:00.000000

Additive: three new tables. Downgrade drops them.
"""
from alembic import op
import sqlalchemy as sa


revision = '0039'
down_revision = '0038'
branch_labels = None
depends_on = None

TABLES = ['host_identities', 'ip_mac_bindings', 'ip_user_bindings']


def upgrade() -> None:
    op.create_table(
        'host_identities',
        sa.Column('mac', sa.String(17), primary_key=True, nullable=False),
        sa.Column('vendor', sa.String(128), nullable=False),
        sa.Column('vendor_source', sa.String(32), nullable=False),
        sa.Column('randomized', sa.Boolean(), nullable=False),
        sa.Column('device_type', sa.String(48), nullable=False),
        sa.Column('device_type_confidence', sa.String(16), nullable=False),
        sa.Column('device_evidence', sa.JSON(), nullable=False),
        sa.Column('os', sa.String(64), nullable=False),
        sa.Column('hostname', sa.String(255), nullable=False),
        sa.Column('hostname_source', sa.String(32), nullable=False),
        sa.Column('last_ip', sa.String(64), nullable=False),
        sa.Column('last_user', sa.String(128), nullable=False),
        sa.Column('switch', sa.String(128), nullable=False),
        sa.Column('port', sa.String(128), nullable=False),
        sa.Column('vlan', sa.Integer(), nullable=True),
        sa.Column('ap', sa.String(128), nullable=False),
        sa.Column('ssid', sa.String(64), nullable=False),
        sa.Column('site', sa.String(128), nullable=False),
        sa.Column('sources', sa.JSON(), nullable=False),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_host_identities_last_seen', 'host_identities', ['last_seen'])
    op.create_index('ix_host_identities_last_ip', 'host_identities', ['last_ip'])
    op.create_table(
        'ip_mac_bindings',
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('ip', sa.String(64), nullable=False),
        sa.Column('mac', sa.String(17), nullable=False),
        sa.Column('source', sa.String(32), nullable=False),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('seen', sa.Integer(), nullable=False),
        sa.UniqueConstraint('ip', 'mac', 'source', name='uq_ip_mac_source'),
    )
    op.create_index('ix_ip_mac_bindings_ip', 'ip_mac_bindings', ['ip'])
    op.create_index('ix_ip_mac_bindings_last_seen', 'ip_mac_bindings', ['last_seen'])
    op.create_index('ix_ip_mac_bindings_mac', 'ip_mac_bindings', ['mac'])
    op.create_table(
        'ip_user_bindings',
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('ip', sa.String(64), nullable=False),
        sa.Column('username', sa.String(128), nullable=False),
        sa.Column('source', sa.String(32), nullable=False),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('seen', sa.Integer(), nullable=False),
        sa.UniqueConstraint('ip', 'username', 'source', name='uq_ip_user_source'),
    )
    op.create_index('ix_ip_user_bindings_ip', 'ip_user_bindings', ['ip'])
    op.create_index('ix_ip_user_bindings_last_seen', 'ip_user_bindings', ['last_seen'])
    op.create_index('ix_ip_user_bindings_username', 'ip_user_bindings', ['username'])


def downgrade() -> None:
    for t in reversed(TABLES):
        op.drop_table(t)
