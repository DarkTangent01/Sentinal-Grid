"""Sentinel NMS: discovery methods (ICMP / TCP / ARP), HTTPS certificate pinning and Telnet opt-in per device, serial
console servers and ports, wireless controller / cloud integrations, Ansible playbook library and runs

Revision ID: 0036
Revises: 0035
Create Date: 2026-11-20 18:00:00.000000

Additive: four defaulted / nullable columns, five new tables, and switch_discovery_runs.credential_id becomes nullable
(ICMP / TCP / ARP discovery needs no SNMP credential; existing rows keep theirs). Downgrade drops the new tables and
columns; it restores NOT NULL on credential_id only when no row has a NULL there.
"""
from alembic import op
import sqlalchemy as sa


revision = '0036'
down_revision = '0035'
branch_labels = None
depends_on = None

TABLES = ['nms_console_servers', 'nms_console_ports', 'wireless_integrations', 'nms_playbooks', 'nms_playbook_runs']
COLUMNS = {
    "switches": [sa.Column("https_cert_sha256", sa.String(64), nullable=False, server_default=""),
                 sa.Column("access_telnet", sa.Boolean(), nullable=False, server_default=sa.false())],
    "switch_discovery_runs": [sa.Column("methods", sa.JSON(), nullable=True)],
    "nms_access_sessions": [sa.Column("console_port_id", sa.Integer(), nullable=True)],
}


def upgrade() -> None:
    for table, cols in COLUMNS.items():
        for c in cols:
            op.add_column(table, c)
    with op.batch_alter_table("switch_discovery_runs") as b:
        b.alter_column("credential_id", existing_type=sa.Integer(), nullable=True)
    op.create_table(
        'nms_console_servers',
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('name', sa.String(128), nullable=False),
        sa.Column('address', sa.String(64), nullable=False),
        sa.Column('kind', sa.String(16), nullable=False),
        sa.Column('method', sa.String(8), nullable=False),
        sa.Column('credential_id', sa.Integer(), sa.ForeignKey('device_ssh_credentials.id', ondelete='SET NULL'), nullable=True),
        sa.Column('ssh_host_key', sa.Text(), nullable=False),
        sa.Column('site', sa.String(128), nullable=False),
        sa.Column('notes', sa.Text(), nullable=False),
        sa.Column('created_by', sa.String(64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint('name'),
    )
    op.create_table(
        'nms_console_ports',
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('server_id', sa.Integer(), sa.ForeignKey('nms_console_servers.id', ondelete='CASCADE'), nullable=False),
        sa.Column('port', sa.Integer(), nullable=False),
        sa.Column('switch_id', sa.Integer(), sa.ForeignKey('switches.id', ondelete='SET NULL'), nullable=True),
        sa.Column('label', sa.String(128), nullable=False),
        sa.UniqueConstraint('server_id', 'port', name='uq_console_port'),
    )
    op.create_index('ix_nms_console_ports_server_id', 'nms_console_ports', ['server_id'])
    op.create_index('ix_nms_console_ports_switch_id', 'nms_console_ports', ['switch_id'])
    op.create_table(
        'wireless_integrations',
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('name', sa.String(128), nullable=False),
        sa.Column('kind', sa.String(16), nullable=False),
        sa.Column('base_url', sa.String(255), nullable=False),
        sa.Column('org_id', sa.String(128), nullable=False),
        sa.Column('site_filter', sa.JSON(), nullable=False),
        sa.Column('api_version', sa.String(16), nullable=False),
        sa.Column('credential_id', sa.Integer(), sa.ForeignKey('device_ssh_credentials.id', ondelete='SET NULL'), nullable=True),
        sa.Column('verify_tls', sa.Boolean(), nullable=False),
        sa.Column('switch_id', sa.Integer(), sa.ForeignKey('switches.id', ondelete='SET NULL'), nullable=True),
        sa.Column('interval_seconds', sa.Integer(), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('last_sync_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_ok_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_error', sa.Text(), nullable=False),
        sa.Column('stats', sa.JSON(), nullable=False),
        sa.Column('lease_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_by', sa.String(64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint('name'),
    )
    op.create_table(
        'nms_playbooks',
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('name', sa.String(128), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('sha256', sa.String(64), nullable=False),
        sa.Column('kind', sa.String(16), nullable=False),
        sa.Column('findings', sa.JSON(), nullable=False),
        sa.Column('status', sa.String(16), nullable=False),
        sa.Column('created_by', sa.String(64), nullable=False),
        sa.Column('updated_by', sa.String(64), nullable=False),
        sa.Column('approved_by', sa.String(64), nullable=False),
        sa.Column('approved_sha256', sa.String(64), nullable=False),
        sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint('name'),
    )
    op.create_table(
        'nms_playbook_runs',
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('playbook_id', sa.Integer(), sa.ForeignKey('nms_playbooks.id', ondelete='CASCADE'), nullable=False),
        sa.Column('playbook_sha256', sa.String(64), nullable=False),
        sa.Column('kind', sa.String(16), nullable=False),
        sa.Column('mode', sa.String(8), nullable=False),
        sa.Column('device_ids', sa.JSON(), nullable=False),
        sa.Column('status', sa.String(20), nullable=False),
        sa.Column('requested_by', sa.String(64), nullable=False),
        sa.Column('approved_by', sa.String(64), nullable=False),
        sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('cancel_requested', sa.Boolean(), nullable=False),
        sa.Column('output', sa.Text(), nullable=False),
        sa.Column('hosts', sa.JSON(), nullable=False),
        sa.Column('backups', sa.JSON(), nullable=False),
        sa.Column('error', sa.Text(), nullable=False),
        sa.Column('lease_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_nms_playbook_runs_playbook_id', 'nms_playbook_runs', ['playbook_id'])
    op.create_index('ix_nms_playbook_runs_status', 'nms_playbook_runs', ['status', 'created_at'])


def downgrade() -> None:
    for t in reversed(TABLES):
        op.drop_table(t)
    for table, cols in COLUMNS.items():
        with op.batch_alter_table(table) as b:
            for c in cols:
                b.drop_column(c.name)
    conn = op.get_bind()
    if not conn.execute(sa.text("SELECT 1 FROM switch_discovery_runs WHERE credential_id IS NULL LIMIT 1")).first():
        with op.batch_alter_table("switch_discovery_runs") as b:
            b.alter_column("credential_id", existing_type=sa.Integer(), nullable=False)
