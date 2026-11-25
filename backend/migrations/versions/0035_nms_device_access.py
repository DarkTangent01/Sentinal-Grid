"""Sentinel NMS device access: NMS roles, credential vault metadata and group assignment, access sessions, commands,
recordings, diagnostic jobs, configuration change requests, hash-chained access audit

Revision ID: 0035
Revises: 0034
Create Date: 2026-11-20 10:00:00.000000

Additive only: five columns on existing tables (nullable or defaulted) and eight new tables. Existing SSH backup
credentials become kind "ssh". Downgrade drops the new tables and columns.
"""
from alembic import op
import sqlalchemy as sa


revision = '0035'
down_revision = '0034'
branch_labels = None
depends_on = None

TABLES = ['nms_credential_assignments', 'nms_access_sessions', 'nms_access_commands', 'nms_access_recordings', 'nms_diag_jobs', 'nms_diag_results', 'nms_change_requests', 'nms_access_audit']
COLUMNS = {
    "users": [sa.Column("nms_roles", sa.JSON(), nullable=True)],
    "switches": [sa.Column("access_platform", sa.String(24), nullable=False, server_default="")],
    "device_ssh_credentials": [sa.Column("kind", sa.String(16), nullable=False, server_default="ssh"),
                               sa.Column("owner", sa.String(64), nullable=False, server_default=""),
                               sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True)],
}


def upgrade() -> None:
    for table, cols in COLUMNS.items():
        for c in cols:
            op.add_column(table, c)
    op.create_table(
        'nms_credential_assignments',
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('credential_id', sa.Integer(), sa.ForeignKey('device_ssh_credentials.id', ondelete='CASCADE'), nullable=False),
        sa.Column('kind', sa.String(16), nullable=False),
        sa.Column('site', sa.String(128), nullable=False),
        sa.Column('role', sa.String(32), nullable=False),
        sa.Column('vendor', sa.String(16), nullable=False),
        sa.Column('created_by', sa.String(64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_nms_credential_assignments_credential_id', 'nms_credential_assignments', ['credential_id'])
    op.create_table(
        'nms_access_sessions',
        sa.Column('id', sa.String(36), primary_key=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(64), nullable=False),
        sa.Column('switch_id', sa.Integer(), sa.ForeignKey('switches.id', ondelete='SET NULL'), nullable=True),
        sa.Column('device_name', sa.String(128), nullable=False),
        sa.Column('device_address', sa.String(64), nullable=False),
        sa.Column('protocol', sa.String(16), nullable=False),
        sa.Column('mode', sa.String(16), nullable=False),
        sa.Column('change_id', sa.Integer(), nullable=True),
        sa.Column('credential_id', sa.Integer(), nullable=True),
        sa.Column('client_ip', sa.String(64), nullable=False),
        sa.Column('ticket_hash', sa.String(64), nullable=False),
        sa.Column('ticket_expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('state', sa.String(16), nullable=False),
        sa.Column('result', sa.String(32), nullable=False),
        sa.Column('termination_reason', sa.String(64), nullable=False),
        sa.Column('terminate_requested_by', sa.String(64), nullable=False),
        sa.Column('latency_ms', sa.Float(), nullable=True),
        sa.Column('bytes_in', sa.BigInteger(), nullable=False),
        sa.Column('bytes_out', sa.BigInteger(), nullable=False),
        sa.Column('commands', sa.Integer(), nullable=False),
        sa.Column('blocked', sa.Integer(), nullable=False),
        sa.Column('recording', sa.String(16), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('connected_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('ended_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_activity_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_nms_access_sessions_started_at', 'nms_access_sessions', ['started_at'])
    op.create_index('ix_nms_access_sessions_state', 'nms_access_sessions', ['state', 'started_at'])
    op.create_index('ix_nms_access_sessions_switch_id', 'nms_access_sessions', ['switch_id'])
    op.create_index('ix_nms_access_sessions_user_id', 'nms_access_sessions', ['user_id'])
    op.create_table(
        'nms_access_commands',
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('ts', sa.DateTime(timezone=True), nullable=False),
        sa.Column('session_id', sa.String(36), nullable=True),
        sa.Column('job_id', sa.Integer(), nullable=True),
        sa.Column('change_id', sa.Integer(), nullable=True),
        sa.Column('switch_id', sa.Integer(), nullable=True),
        sa.Column('username', sa.String(64), nullable=False),
        sa.Column('command', sa.Text(), nullable=False),
        sa.Column('risk', sa.String(16), nullable=False),
        sa.Column('allowed', sa.Boolean(), nullable=False),
        sa.Column('reason', sa.String(255), nullable=False),
    )
    op.create_index('ix_nms_access_commands_job_id', 'nms_access_commands', ['job_id'])
    op.create_index('ix_nms_access_commands_session_id', 'nms_access_commands', ['session_id'])
    op.create_index('ix_nms_access_commands_switch_id', 'nms_access_commands', ['switch_id'])
    op.create_index('ix_nms_access_commands_ts', 'nms_access_commands', ['ts'])
    op.create_table(
        'nms_access_recordings',
        sa.Column('session_id', sa.String(36), primary_key=True, nullable=False),
        sa.Column('text', sa.Text(), nullable=False),
        sa.Column('truncated', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_nms_access_recordings_created_at', 'nms_access_recordings', ['created_at'])
    op.create_table(
        'nms_diag_jobs',
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('username', sa.String(64), nullable=False),
        sa.Column('kind', sa.String(8), nullable=False),
        sa.Column('templates', sa.JSON(), nullable=False),
        sa.Column('device_ids', sa.JSON(), nullable=False),
        sa.Column('status', sa.String(16), nullable=False),
        sa.Column('total', sa.Integer(), nullable=False),
        sa.Column('completed', sa.Integer(), nullable=False),
        sa.Column('failed', sa.Integer(), nullable=False),
        sa.Column('cancel_requested', sa.Boolean(), nullable=False),
        sa.Column('concurrency', sa.Integer(), nullable=False),
        sa.Column('timeout_seconds', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_nms_diag_jobs_created_at', 'nms_diag_jobs', ['created_at'])
    op.create_table(
        'nms_diag_results',
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('job_id', sa.Integer(), sa.ForeignKey('nms_diag_jobs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('switch_id', sa.Integer(), nullable=True),
        sa.Column('device_name', sa.String(128), nullable=False),
        sa.Column('status', sa.String(16), nullable=False),
        sa.Column('error', sa.Text(), nullable=False),
        sa.Column('outputs', sa.JSON(), nullable=False),
        sa.Column('duration_ms', sa.Integer(), nullable=True),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_nms_diag_results_job', 'nms_diag_results', ['job_id', 'switch_id'])
    op.create_table(
        'nms_change_requests',
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('switch_id', sa.Integer(), sa.ForeignKey('switches.id', ondelete='SET NULL'), nullable=True),
        sa.Column('device_name', sa.String(128), nullable=False),
        sa.Column('title', sa.String(200), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('lines', sa.JSON(), nullable=False),
        sa.Column('rollback_lines', sa.JSON(), nullable=False),
        sa.Column('save_config', sa.Boolean(), nullable=False),
        sa.Column('risk', sa.String(16), nullable=False),
        sa.Column('status', sa.String(20), nullable=False),
        sa.Column('window_start', sa.DateTime(timezone=True), nullable=True),
        sa.Column('window_end', sa.DateTime(timezone=True), nullable=True),
        sa.Column('requested_by', sa.String(64), nullable=False),
        sa.Column('approved_by', sa.String(64), nullable=False),
        sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('decision_comment', sa.Text(), nullable=False),
        sa.Column('executed_by', sa.String(64), nullable=False),
        sa.Column('executed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('pre_snapshot_id', sa.Integer(), nullable=True),
        sa.Column('post_snapshot_id', sa.Integer(), nullable=True),
        sa.Column('preview', sa.Text(), nullable=False),
        sa.Column('output', sa.Text(), nullable=False),
        sa.Column('result', sa.JSON(), nullable=False),
        sa.Column('log', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_nms_change_requests_status', 'nms_change_requests', ['status', 'created_at'])
    op.create_index('ix_nms_change_requests_switch_id', 'nms_change_requests', ['switch_id'])
    op.create_table(
        'nms_access_audit',
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('ts', sa.DateTime(timezone=True), nullable=False),
        sa.Column('username', sa.String(64), nullable=False),
        sa.Column('action', sa.String(64), nullable=False),
        sa.Column('switch_id', sa.Integer(), nullable=True),
        sa.Column('session_id', sa.String(36), nullable=False),
        sa.Column('target', sa.String(255), nullable=False),
        sa.Column('detail', sa.JSON(), nullable=False),
        sa.Column('client_ip', sa.String(64), nullable=False),
        sa.Column('success', sa.Boolean(), nullable=False),
        sa.Column('prev_hash', sa.String(64), nullable=False),
        sa.Column('hash', sa.String(64), nullable=False),
    )
    op.create_index('ix_nms_access_audit_action', 'nms_access_audit', ['action'])
    op.create_index('ix_nms_access_audit_switch_id', 'nms_access_audit', ['switch_id'])
    op.create_index('ix_nms_access_audit_ts', 'nms_access_audit', ['ts'])


def downgrade() -> None:
    for t in reversed(TABLES):
        op.drop_table(t)
    for table, cols in COLUMNS.items():
        with op.batch_alter_table(table) as b:
            for c in cols:
                b.drop_column(c.name)
