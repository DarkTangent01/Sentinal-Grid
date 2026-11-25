"""Sentinel NMS application & protocol intelligence: classification registry, network ranges / zones, VLAN policies,
custom traffic rules, settings and the IP enrichment cache

Revision ID: 0038
Revises: 0037
Create Date: 2026-11-25 10:00:00.000000

Additive: six new tables, nothing else changes. Built-in signatures and zone policies are seeded by the application
(app/traffic/registry.py ensure_defaults), not by this migration. Downgrade drops the six tables.
"""
from alembic import op
import sqlalchemy as sa


revision = '0038'
down_revision = '0037'
branch_labels = None
depends_on = None

TABLES = ['traffic_signatures', 'traffic_networks', 'traffic_vlan_policies', 'traffic_rules', 'traffic_settings', 'traffic_ip_info']


def upgrade() -> None:
    op.create_table(
        'traffic_signatures',
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('kind', sa.String(8), nullable=False),
        sa.Column('proto', sa.Integer(), nullable=True),
        sa.Column('port_from', sa.Integer(), nullable=True),
        sa.Column('port_to', sa.Integer(), nullable=True),
        sa.Column('match', sa.String(255), nullable=False),
        sa.Column('app', sa.String(64), nullable=False),
        sa.Column('category', sa.String(32), nullable=False),
        sa.Column('encrypted', sa.Boolean(), nullable=True),
        sa.Column('ambiguous', sa.Boolean(), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('builtin_key', sa.String(64), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('updated_by', sa.String(64), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_traffic_signatures_kind', 'traffic_signatures', ['kind'])
    op.create_index('ix_traffic_signatures_builtin_key', 'traffic_signatures', ['builtin_key'])
    op.create_table(
        'traffic_networks',
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('cidr', sa.String(64), nullable=False),
        sa.Column('name', sa.String(128), nullable=False),
        sa.Column('site', sa.String(128), nullable=False),
        sa.Column('vlan', sa.Integer(), nullable=True),
        sa.Column('zone', sa.String(32), nullable=False),
        sa.Column('internal', sa.Boolean(), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('created_by', sa.String(64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint('cidr'),
    )
    op.create_table(
        'traffic_vlan_policies',
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('name', sa.String(128), nullable=False),
        sa.Column('src', sa.String(64), nullable=False),
        sa.Column('dst', sa.String(64), nullable=False),
        sa.Column('action', sa.String(8), nullable=False),
        sa.Column('severity', sa.String(16), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('builtin_key', sa.String(64), nullable=False),
        sa.Column('updated_by', sa.String(64), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        'traffic_rules',
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('name', sa.String(128), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('severity', sa.String(16), nullable=False),
        sa.Column('proto', sa.Integer(), nullable=True),
        sa.Column('ports', sa.JSON(), nullable=False),
        sa.Column('src_cidrs', sa.JSON(), nullable=False),
        sa.Column('dst_cidrs', sa.JSON(), nullable=False),
        sa.Column('exclude_cidrs', sa.JSON(), nullable=False),
        sa.Column('direction', sa.String(16), nullable=False),
        sa.Column('min_bytes', sa.BigInteger(), nullable=False),
        sa.Column('window_minutes', sa.Integer(), nullable=False),
        sa.Column('created_by', sa.String(64), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint('name'),
    )
    op.create_table(
        'traffic_settings',
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('data', sa.JSON(), nullable=False),
        sa.Column('updated_by', sa.String(64), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        'traffic_ip_info',
        sa.Column('ip', sa.String(64), primary_key=True, nullable=False),
        sa.Column('asn', sa.Integer(), nullable=False),
        sa.Column('as_org', sa.String(255), nullable=False),
        sa.Column('country', sa.String(64), nullable=False),
        sa.Column('rdns', sa.String(255), nullable=False),
        sa.Column('domains', sa.JSON(), nullable=False),
        sa.Column('domain_count', sa.Integer(), nullable=False),
        sa.Column('fw_app', sa.String(128), nullable=False),
        sa.Column('fw_app_cat', sa.String(64), nullable=False),
        sa.Column('app', sa.String(64), nullable=False),
        sa.Column('category', sa.String(32), nullable=False),
        sa.Column('confidence', sa.String(16), nullable=False),
        sa.Column('evidence', sa.JSON(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_traffic_ip_info_updated_at', 'traffic_ip_info', ['updated_at'])


def downgrade() -> None:
    for t in reversed(TABLES):
        op.drop_table(t)
