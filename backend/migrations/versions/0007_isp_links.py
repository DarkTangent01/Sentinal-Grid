"""ISP / WAN link inventory

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-26 18:30:00.000000

Additive only: one new table. Links are discovered automatically from SD-WAN logs.
"""
from alembic import op
import sqlalchemy as sa


revision = '0007'
down_revision = '0006'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'isp_links',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('firewall_id', sa.Integer(), sa.ForeignKey('firewalls.id', ondelete='CASCADE'), nullable=False),
        sa.Column('interface', sa.String(64), nullable=False),
        sa.Column('isp_name', sa.String(128), nullable=False, server_default=''),
        sa.Column('circuit_id', sa.String(128), nullable=False, server_default=''),
        sa.Column('bandwidth_mbps', sa.Float(), nullable=True),
        sa.Column('target_availability', sa.Float(), nullable=False, server_default='99.5'),
        sa.Column('outage_checks', sa.JSON(), nullable=False),
        sa.Column('hidden', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('notes', sa.Text(), nullable=False, server_default=''),
        sa.Column('support_contact', sa.String(255), nullable=False, server_default=''),
        sa.Column('alias', sa.String(128), nullable=False, server_default=''),
        sa.Column('description', sa.String(255), nullable=False, server_default=''),
        sa.Column('gateway', sa.String(64), nullable=False, server_default=''),
        sa.Column('as_org', sa.String(255), nullable=False, server_default=''),
        sa.Column('discovered_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint('firewall_id', 'interface', name='uq_isp_link'),
    )
    op.create_index('ix_isp_links_firewall_id', 'isp_links', ['firewall_id'])


def downgrade() -> None:
    op.drop_table('isp_links')
