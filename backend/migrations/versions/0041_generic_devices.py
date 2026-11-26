"""Generic SNMP device inventory: FQDN, tags, manual type, ICMP flag and monitoring template on devices; per-interface
monitoring flag and thresholds; monitoring templates and NMS settings tables (app/switches/templates.py)

Revision ID: 0041
Revises: 0040
Create Date: 2026-11-26 09:00:00.000000

Additive: new nullable / defaulted columns and two new tables. Downgrade removes them.
"""
from alembic import op
import sqlalchemy as sa


revision = '0041'
down_revision = '0040'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'monitoring_templates',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('key', sa.String(48), nullable=True, unique=True),
        sa.Column('name', sa.String(128), nullable=False, unique=True),
        sa.Column('device_type', sa.String(16), nullable=False, server_default=''),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('poll_interval_seconds', sa.Integer(), nullable=False, server_default='60'),
        sa.Column('group_intervals', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('thresholds', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('interface_rules', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('builtin', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('created_by', sa.String(128), nullable=False, server_default=''),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        'monitoring_settings',
        sa.Column('key', sa.String(64), primary_key=True),
        sa.Column('value', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('updated_by', sa.String(128), nullable=False, server_default=''),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    with op.batch_alter_table('switches') as b:
        b.add_column(sa.Column('fqdn', sa.String(255), nullable=False, server_default=''))
        b.add_column(sa.Column('tags', sa.JSON(), nullable=False, server_default='[]'))
        b.add_column(sa.Column('device_type_override', sa.String(16), nullable=False, server_default=''))
        b.add_column(sa.Column('icmp_enabled', sa.Boolean(), nullable=False, server_default=sa.true()))
        b.add_column(sa.Column('template_id', sa.Integer(), nullable=True))
        b.add_column(sa.Column('template_config', sa.JSON(), nullable=False, server_default='{}'))
        b.create_foreign_key('fk_switches_template', 'monitoring_templates', ['template_id'], ['id'], ondelete='SET NULL')
    with op.batch_alter_table('switch_interfaces') as b:
        b.add_column(sa.Column('monitored', sa.Boolean(), nullable=False, server_default=sa.true()))
        b.add_column(sa.Column('thresholds', sa.JSON(), nullable=False, server_default='{}'))


def downgrade() -> None:
    with op.batch_alter_table('switch_interfaces') as b:
        b.drop_column('thresholds')
        b.drop_column('monitored')
    with op.batch_alter_table('switches') as b:
        b.drop_constraint('fk_switches_template', type_='foreignkey')
        for c in ('template_config', 'template_id', 'icmp_enabled', 'device_type_override', 'tags', 'fqdn'):
            b.drop_column(c)
    op.drop_table('monitoring_settings')
    op.drop_table('monitoring_templates')
