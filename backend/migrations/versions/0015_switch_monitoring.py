"""Switch monitoring (Cisco / Ruckus ICX over SNMP): credential profiles, authorised management networks, switches,
interfaces, VLANs, MAC table, events, poll history, discovery runs

Revision ID: 0015
Revises: 0014
Create Date: 2026-10-28 18:00:00.000000

Additive only: new tables. Time series live in ClickHouse (switch_metrics, switch_if_samples and hourly rollups).
"""
from alembic import op
import sqlalchemy as sa


revision = '0015'
down_revision = '0014'
branch_labels = None
depends_on = None
TZ = sa.DateTime(timezone=True)


def _now():
    return sa.Column('created_at', TZ, nullable=False, server_default=sa.func.now())


def upgrade() -> None:
    op.create_table(
        'switch_credentials',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(64), nullable=False, unique=True),
        sa.Column('version', sa.String(8), nullable=False, server_default='v3'),
        sa.Column('username', sa.String(64), nullable=False, server_default=''),
        sa.Column('auth_protocol', sa.String(16), nullable=False, server_default='sha'),
        sa.Column('priv_protocol', sa.String(16), nullable=False, server_default='aes128'),
        sa.Column('secret_ciphertext', sa.Text(), nullable=False, server_default=''),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('created_by', sa.String(64), nullable=False, server_default=''),
        _now(),
        sa.Column('updated_at', TZ, nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        'switch_networks',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('cidr', sa.String(64), nullable=False, unique=True),
        sa.Column('site', sa.String(128), nullable=False, server_default=''),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('allow_discovery', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('created_by', sa.String(64), nullable=False, server_default=''),
        _now(),
    )
    s = lambda n, size, d="": sa.Column(n, sa.String(size), nullable=False, server_default=d)  # noqa: E731
    op.create_table(
        'switches',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(128), nullable=False, unique=True),
        sa.Column('address', sa.String(64), nullable=False, unique=True),
        sa.Column('port', sa.Integer(), nullable=False, server_default='161'),
        sa.Column('credential_id', sa.Integer(), sa.ForeignKey('switch_credentials.id', ondelete='RESTRICT'), nullable=True),
        s('vendor', 16, 'unknown'), s('family', 64), s('model', 64), s('serial', 128), s('firmware', 128), s('os', 32),
        sa.Column('sys_descr', sa.Text(), nullable=False, server_default=''), s('sys_object_id', 128), s('sys_name', 255),
        s('location', 255), s('site', 128), s('building', 128), s('floor', 64), s('rack', 64), s('role', 32),
        sa.Column('notes', sa.Text(), nullable=False, server_default=''), s('monitoring', 16, 'active'),
        sa.Column('poll_interval_seconds', sa.Integer(), nullable=False, server_default='60'),
        sa.Column('group_intervals', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('thresholds', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('timeout_ms', sa.Integer(), nullable=False, server_default='3000'),
        sa.Column('retries', sa.Integer(), nullable=False, server_default='1'),
        s('state', 16, 'unknown'), sa.Column('state_since', TZ, nullable=True),
        sa.Column('fail_streak', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_poll_at', TZ, nullable=True), sa.Column('last_success_at', TZ, nullable=True),
        sa.Column('last_error', sa.Text(), nullable=False, server_default=''), s('last_error_kind', 16),
        sa.Column('poll_duration_ms', sa.Integer(), nullable=True), sa.Column('uptime_ticks', sa.BigInteger(), nullable=True),
        *[sa.Column(c, sa.Float(), nullable=True) for c in ('cpu_pct', 'mem_pct', 'temp_max_c', 'poe_budget_w', 'poe_used_w')],
        *[sa.Column(c, sa.Integer(), nullable=True) for c in ('if_total', 'if_up', 'if_errors')],
        sa.Column('coverage_pct', sa.Float(), nullable=True),
        *[sa.Column(c, sa.JSON(), nullable=False, server_default='{}') for c in ('capabilities', 'group_state', 'health')],
        sa.Column('lease_until', TZ, nullable=True),
        s('created_by', 64), _now(),
    )
    op.create_table(
        'switch_interfaces',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('switch_id', sa.Integer(), sa.ForeignKey('switches.id', ondelete='CASCADE'), nullable=False),
        sa.Column('ifindex', sa.BigInteger(), nullable=False),
        s('name', 128), s('descr', 255), s('alias', 255), sa.Column('if_type', sa.Integer(), nullable=True),
        sa.Column('mtu', sa.Integer(), nullable=True), sa.Column('speed_bps', sa.BigInteger(), nullable=True), s('speed_source', 64),
        s('admin', 16), s('oper', 24), s('duplex', 8), s('mac', 17), s('kind', 16), s('mode', 8),
        sa.Column('access_vlan', sa.Integer(), nullable=True), sa.Column('native_vlan', sa.Integer(), nullable=True),
        sa.Column('lag_ifindex', sa.BigInteger(), nullable=True), sa.Column('poe', sa.JSON(), nullable=True),
        *[sa.Column(c, sa.Float(), nullable=True) for c in ('rx_bps', 'tx_bps', 'rx_util', 'tx_util')],
        *[sa.Column(c, sa.BigInteger(), nullable=True) for c in ('in_errors_delta', 'out_errors_delta', 'crc_delta', 'discards_delta')],
        sa.Column('sample_flags', sa.Integer(), nullable=False, server_default='0'), s('sample_note', 255),
        sa.Column('counters', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('last_change_at', TZ, nullable=True), sa.Column('last_sample_at', TZ, nullable=True),
        sa.Column('present', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('first_seen', TZ, nullable=False, server_default=sa.func.now()), sa.Column('last_seen', TZ, nullable=True),
        sa.UniqueConstraint('switch_id', 'ifindex', name='uq_switch_if'),
    )
    op.create_index('ix_switch_interfaces_switch_id', 'switch_interfaces', ['switch_id'])
    op.create_table(
        'switch_vlans',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('switch_id', sa.Integer(), sa.ForeignKey('switches.id', ondelete='CASCADE'), nullable=False),
        sa.Column('vlan_id', sa.Integer(), nullable=False), s('name', 128), s('state', 16),
        sa.Column('tagged', sa.JSON(), nullable=False, server_default='[]'), sa.Column('untagged', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('present', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('first_seen', TZ, nullable=False, server_default=sa.func.now()), sa.Column('last_seen', TZ, nullable=True),
        sa.UniqueConstraint('switch_id', 'vlan_id', name='uq_switch_vlan'),
    )
    op.create_index('ix_switch_vlans_switch_id', 'switch_vlans', ['switch_id'])
    op.create_table(
        'switch_macs',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('switch_id', sa.Integer(), sa.ForeignKey('switches.id', ondelete='CASCADE'), nullable=False),
        s('mac', 17), sa.Column('vlan_id', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('ifindex', sa.BigInteger(), nullable=True), s('port_name', 128), s('status', 16),
        sa.Column('moves', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('present', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('first_seen', TZ, nullable=False, server_default=sa.func.now()), sa.Column('last_seen', TZ, nullable=True),
        sa.UniqueConstraint('switch_id', 'mac', 'vlan_id', name='uq_switch_mac'),
    )
    op.create_index('ix_switch_macs_switch_id', 'switch_macs', ['switch_id'])
    op.create_index('ix_switch_macs_mac', 'switch_macs', ['mac'])
    op.create_table(
        'switch_events',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('switch_id', sa.Integer(), sa.ForeignKey('switches.id', ondelete='CASCADE'), nullable=False),
        sa.Column('at', TZ, nullable=False), s('kind', 32), s('severity', 16, 'informational'), s('component', 255),
        sa.Column('detail', sa.Text(), nullable=False, server_default=''), sa.Column('data', sa.JSON(), nullable=False, server_default='{}'),
    )
    for c in ('switch_id', 'at', 'kind'):
        op.create_index(f'ix_switch_events_{c}', 'switch_events', [c])
    op.create_table(
        'switch_poll_runs',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('switch_id', sa.Integer(), sa.ForeignKey('switches.id', ondelete='CASCADE'), nullable=False),
        sa.Column('started_at', TZ, nullable=False), sa.Column('duration_ms', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('ok', sa.Boolean(), nullable=False, server_default=sa.false()), s('kind', 16, 'poll'),
        sa.Column('requests', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('groups', sa.JSON(), nullable=False, server_default='{}'), sa.Column('error', sa.Text(), nullable=False, server_default=''),
    )
    op.create_index('ix_switch_poll_runs_switch_id', 'switch_poll_runs', ['switch_id'])
    op.create_index('ix_switch_poll_runs_started_at', 'switch_poll_runs', ['started_at'])
    op.create_table(
        'switch_discovery_runs',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('network_id', sa.Integer(), sa.ForeignKey('switch_networks.id', ondelete='CASCADE'), nullable=False),
        s('cidr', 64),
        sa.Column('credential_id', sa.Integer(), sa.ForeignKey('switch_credentials.id', ondelete='CASCADE'), nullable=False),
        s('status', 16, 'queued'), s('requested_by', 64), _now(),
        sa.Column('started_at', TZ, nullable=True), sa.Column('finished_at', TZ, nullable=True),
        sa.Column('scanned', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('results', sa.JSON(), nullable=False, server_default='[]'), sa.Column('error', sa.Text(), nullable=False, server_default=''),
    )
    op.create_index('ix_switch_discovery_runs_network_id', 'switch_discovery_runs', ['network_id'])


def downgrade() -> None:
    for t in ('switch_discovery_runs', 'switch_poll_runs', 'switch_events', 'switch_macs', 'switch_vlans', 'switch_interfaces',
              'switches', 'switch_networks', 'switch_credentials'):
        op.drop_table(t)
