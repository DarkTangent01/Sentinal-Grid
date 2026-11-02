"""query indexes for hot read paths

Revision ID: 0027
Revises: 0026
Create Date: 2026-11-02 12:00:00.000000

Additive only (no data change). On PostgreSQL every index is built CONCURRENTLY outside a transaction, so a large
alerts / switch_events table stays readable and writable while it builds. If a concurrent build is interrupted
PostgreSQL leaves an INVALID index; re-running the upgrade drops and rebuilds it (IF NOT EXISTS would keep it).
Downgrade drops exactly these indexes.
"""
from alembic import op
import sqlalchemy as sa


revision = '0027'
down_revision = '0026'
branch_labels = None
depends_on = None

# (name, table, columns, postgresql_ops, postgresql_where)
INDEXES = [
    ("ix_alerts_dst_ip", "alerts", ["dst_ip"], None, None),
    ("ix_alerts_first_seen", "alerts", ["first_seen"], None, None),
    ("ix_alerts_status_last_seen", "alerts", ["status", "last_seen"], None, None),
    ("ix_alerts_rule_key_pattern", "alerts", ["rule_key"], {"rule_key": "varchar_pattern_ops"}, None),
    ("ix_alerts_group_key_pattern", "alerts", ["group_key"], {"group_key": "varchar_pattern_ops"}, None),
    ("ix_incidents_category_created", "incidents", ["category", "created_at"], None, None),
    ("ix_switch_events_switch_at", "switch_events", ["switch_id", "at"], None, None),
    ("ix_switch_events_switch_kind_at", "switch_events", ["switch_id", "kind", "at"], None, None),
    ("ix_switch_poll_runs_switch_started", "switch_poll_runs", ["switch_id", "started_at"], None, None),
    ("ix_switch_interfaces_present", "switch_interfaces", ["switch_id"], None, "present"),
    ("ix_tacacs_health_checks_server_at", "tacacs_health_checks", ["server_id", "at"], None, None),
    ("ix_wireless_events_ap_at", "wireless_events", ["ap_id", "at"], None, None),
]


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        for name, table, cols, _ops, _where in INDEXES:
            op.create_index(name, table, cols)
        return
    with op.get_context().autocommit_block():
        for name, table, cols, ops, where in INDEXES:
            op.execute(sa.text(f'DROP INDEX CONCURRENTLY IF EXISTS "{name}"'))  # clears an INVALID leftover build
            op.create_index(name, table, cols, postgresql_concurrently=True, postgresql_ops=ops or {},
                            postgresql_where=sa.text(where) if where else None)


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        for name, table, *_ in INDEXES:
            op.drop_index(name, table_name=table)
        return
    with op.get_context().autocommit_block():
        for name, table, *_ in INDEXES:
            op.drop_index(name, table_name=table, postgresql_concurrently=True, if_exists=True)
