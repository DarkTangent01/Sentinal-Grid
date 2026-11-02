"""Infrastructure as Code: projects, versions, managed devices, plans, approvals, jobs, locks, backups, drift, rules,
exceptions, settings, hash-chained audit; IaC roles on users

Revision ID: 0014
Revises: 0013
Create Date: 2026-10-28 10:00:00.000000

Additive only: new tables and one nullable-with-default column on users.
"""
from alembic import op
import sqlalchemy as sa


revision = '0014'
down_revision = '0013'
branch_labels = None
depends_on = None
TZ = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.add_column('users', sa.Column('iac_roles', sa.JSON(), nullable=False, server_default='[]'))
    op.create_table(
        'iac_projects',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(128), nullable=False, unique=True),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('environment', sa.String(16), nullable=False, server_default='development'),
        sa.Column('draft_content', sa.Text(), nullable=False, server_default=''),
        sa.Column('draft_updated_by', sa.String(64), nullable=False, server_default=''),
        sa.Column('draft_updated_at', TZ, nullable=True),
        sa.Column('draft_base_version_id', sa.Integer(), nullable=True),
        sa.Column('approved_version_id', sa.Integer(), nullable=True),
        sa.Column('archived', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('created_by', sa.String(64), nullable=False),
        sa.Column('created_at', TZ, nullable=False),
    )
    op.create_table(
        'iac_versions',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('project_id', sa.Integer(), sa.ForeignKey('iac_projects.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('number', sa.Integer(), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('content_hash', sa.String(64), nullable=False),
        sa.Column('message', sa.Text(), nullable=False, server_default=''),
        sa.Column('author', sa.String(64), nullable=False),
        sa.Column('parent_id', sa.Integer(), nullable=True),
        sa.Column('valid', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('validation', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('approved_at', TZ, nullable=True),
        sa.Column('created_at', TZ, nullable=False),
        sa.UniqueConstraint('project_id', 'number', name='uq_iac_version'),
    )
    op.create_table(
        'iac_devices',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('project_id', sa.Integer(), sa.ForeignKey('iac_projects.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('firewall_id', sa.Integer(), sa.ForeignKey('firewalls.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('managed', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('integration', sa.String(32), nullable=False, server_default='fortigate_api'),
        sa.Column('variables', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('capabilities', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('observed', sa.JSON(), nullable=True),
        sa.Column('observed_hash', sa.String(64), nullable=False, server_default=''),
        sa.Column('observed_at', TZ, nullable=True),
        sa.Column('drift_status', sa.String(16), nullable=False, server_default='unknown'),
        sa.Column('last_drift_check', TZ, nullable=True),
        sa.Column('last_backup_at', TZ, nullable=True),
        sa.Column('last_deploy_at', TZ, nullable=True),
        sa.Column('last_deploy_status', sa.String(16), nullable=False, server_default=''),
        sa.Column('last_deployed_version_id', sa.Integer(), nullable=True),
        sa.Column('managed_keys', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('baseline_unmanaged', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('created_at', TZ, nullable=False),
        sa.UniqueConstraint('project_id', 'firewall_id', name='uq_iac_device'),
    )
    op.create_table(
        'iac_plans',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('project_id', sa.Integer(), sa.ForeignKey('iac_projects.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('version_id', sa.Integer(), sa.ForeignKey('iac_versions.id', ondelete='SET NULL'), nullable=True),
        sa.Column('version_hash', sa.String(64), nullable=False, server_default=''),
        sa.Column('kind', sa.String(16), nullable=False, server_default='change'),
        sa.Column('recovery_backup_id', sa.Integer(), nullable=True),
        sa.Column('status', sa.String(24), nullable=False, server_default='draft', index=True),
        sa.Column('environment', sa.String(16), nullable=False, server_default='development'),
        sa.Column('targets', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('observed_hashes', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('ruleset_hash', sa.String(64), nullable=False, server_default=''),
        sa.Column('plan_hash', sa.String(64), nullable=False, server_default='', index=True),
        sa.Column('summary', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('findings', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('errors', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('blocking', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('destructive', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('stale_reason', sa.Text(), nullable=False, server_default=''),
        sa.Column('created_by', sa.String(64), nullable=False),
        sa.Column('created_at', TZ, nullable=False),
        sa.Column('updated_at', TZ, nullable=False),
    )
    op.create_table(
        'iac_plan_changes',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('plan_id', sa.Integer(), sa.ForeignKey('iac_plans.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('firewall_id', sa.Integer(), nullable=False, index=True),
        sa.Column('seq', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('resource_type', sa.String(32), nullable=False),
        sa.Column('resource_id', sa.String(255), nullable=False),
        sa.Column('action', sa.String(16), nullable=False),
        sa.Column('current', sa.JSON(), nullable=True),
        sa.Column('desired', sa.JSON(), nullable=True),
        sa.Column('fields', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('depends_on', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('risk', sa.String(16), nullable=False, server_default='low'),
        sa.Column('rule_id', sa.String(32), nullable=False, server_default=''),
        sa.Column('impact', sa.Text(), nullable=False, server_default=''),
        sa.Column('disruptive', sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_table(
        'iac_approvals',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('plan_id', sa.Integer(), sa.ForeignKey('iac_plans.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('username', sa.String(64), nullable=False),
        sa.Column('decision', sa.String(16), nullable=False),
        sa.Column('comment', sa.Text(), nullable=False, server_default=''),
        sa.Column('plan_hash', sa.String(64), nullable=False),
        sa.Column('acknowledged_destructive', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('created_at', TZ, nullable=False),
    )
    op.create_table(
        'iac_jobs',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('plan_id', sa.Integer(), sa.ForeignKey('iac_plans.id', ondelete='SET NULL'), nullable=True, index=True),
        sa.Column('project_id', sa.Integer(), nullable=True, index=True),
        sa.Column('kind', sa.String(16), nullable=False),
        sa.Column('status', sa.String(16), nullable=False, server_default='queued', index=True),
        sa.Column('plan_hash', sa.String(64), nullable=False, server_default=''),
        sa.Column('requested_by', sa.String(64), nullable=False),
        sa.Column('cancel_requested', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('current_operation', sa.Text(), nullable=False, server_default=''),
        sa.Column('progress', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('log', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('error', sa.Text(), nullable=False, server_default=''),
        sa.Column('created_at', TZ, nullable=False, index=True),
        sa.Column('started_at', TZ, nullable=True),
        sa.Column('finished_at', TZ, nullable=True),
    )
    op.create_table(
        'iac_job_devices',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('job_id', sa.Integer(), sa.ForeignKey('iac_jobs.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('firewall_id', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(16), nullable=False, server_default='pending'),
        sa.Column('backup_id', sa.Integer(), nullable=True),
        sa.Column('results', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('verification', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('health', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('error', sa.Text(), nullable=False, server_default=''),
        sa.Column('started_at', TZ, nullable=True),
        sa.Column('finished_at', TZ, nullable=True),
    )
    op.create_table(
        'iac_locks',
        sa.Column('firewall_id', sa.Integer(), primary_key=True),
        sa.Column('job_id', sa.Integer(), nullable=False),
        sa.Column('acquired_at', TZ, nullable=False),
        sa.Column('expires_at', TZ, nullable=False),
    )
    op.create_table(
        'iac_backups',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('firewall_id', sa.Integer(), sa.ForeignKey('firewalls.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('job_id', sa.Integer(), nullable=True, index=True),
        sa.Column('plan_id', sa.Integer(), nullable=True),
        sa.Column('kind', sa.String(16), nullable=False, server_default='pre_change'),
        sa.Column('snapshot', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('snapshot_sha256', sa.String(64), nullable=False),
        sa.Column('full_config_ciphertext', sa.Text(), nullable=True),
        sa.Column('full_config_sha256', sa.String(64), nullable=False, server_default=''),
        sa.Column('full_config_note', sa.Text(), nullable=False, server_default=''),
        sa.Column('validated', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('created_by', sa.String(64), nullable=False, server_default=''),
        sa.Column('created_at', TZ, nullable=False, index=True),
    )
    op.create_table(
        'iac_drift',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('device_id', sa.Integer(), sa.ForeignKey('iac_devices.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('firewall_id', sa.Integer(), nullable=False, index=True),
        sa.Column('project_id', sa.Integer(), nullable=False, index=True),
        sa.Column('checked_at', TZ, nullable=False, index=True),
        sa.Column('status', sa.String(16), nullable=False),
        sa.Column('version_id', sa.Integer(), nullable=True),
        sa.Column('observed_hash', sa.String(64), nullable=False, server_default=''),
        sa.Column('findings', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('counts', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('error', sa.Text(), nullable=False, server_default=''),
    )
    op.create_table(
        'iac_rules',
        sa.Column('rule_id', sa.String(32), primary_key=True),
        sa.Column('family', sa.String(16), nullable=False),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('severity', sa.String(16), nullable=False),
        sa.Column('blocks_deploy', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('params', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('remediation', sa.Text(), nullable=False, server_default=''),
    )
    op.create_table(
        'iac_exceptions',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('rule_id', sa.String(32), nullable=False, index=True),
        sa.Column('project_id', sa.Integer(), nullable=True),
        sa.Column('firewall_id', sa.Integer(), nullable=True),
        sa.Column('resource', sa.String(255), nullable=False, server_default='*'),
        sa.Column('owner', sa.String(128), nullable=False),
        sa.Column('justification', sa.Text(), nullable=False),
        sa.Column('expires_at', TZ, nullable=False),
        sa.Column('created_by', sa.String(64), nullable=False),
        sa.Column('created_at', TZ, nullable=False),
    )
    op.create_table(
        'iac_settings',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('data', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('updated_by', sa.String(64), nullable=False, server_default=''),
        sa.Column('updated_at', TZ, nullable=False),
    )
    op.create_table(
        'iac_audit',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('ts', TZ, nullable=False, index=True),
        sa.Column('username', sa.String(64), nullable=False),
        sa.Column('action', sa.String(64), nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=True, index=True),
        sa.Column('plan_id', sa.Integer(), nullable=True),
        sa.Column('job_id', sa.Integer(), nullable=True),
        sa.Column('target', sa.String(255), nullable=False, server_default=''),
        sa.Column('detail', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('client_ip', sa.String(64), nullable=False, server_default=''),
        sa.Column('prev_hash', sa.String(64), nullable=False, server_default=''),
        sa.Column('hash', sa.String(64), nullable=False),
    )


def downgrade() -> None:
    for t in ('iac_audit', 'iac_settings', 'iac_exceptions', 'iac_rules', 'iac_drift', 'iac_backups', 'iac_locks', 'iac_job_devices',
              'iac_jobs', 'iac_approvals', 'iac_plan_changes', 'iac_plans', 'iac_devices', 'iac_versions', 'iac_projects'):
        op.drop_table(t)
    op.drop_column('users', 'iac_roles')
