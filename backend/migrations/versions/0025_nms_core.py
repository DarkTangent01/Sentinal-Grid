"""Sentinel NMS core: device dependencies (switches.parent_id), maintenance windows, service checks.

Revision ID: 0025
Revises: 0024
Create Date: 2026-11-02 12:00:00
"""
from alembic import op
import sqlalchemy as sa

revision = '0025'
down_revision = '0024'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("switches") as b:
        b.add_column(sa.Column("parent_id", sa.Integer(), nullable=True))
        b.create_foreign_key("fk_switches_parent", "switches", ["parent_id"], ["id"], ondelete="SET NULL")
        b.create_index("ix_switches_parent_id", ["parent_id"])
    op.create_table(
        "nms_maintenance",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("kind", sa.String(8), nullable=False, server_default="once"),
        sa.Column("starts_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ends_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("weekdays", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("start_time", sa.String(5), nullable=False, server_default=""),
        sa.Column("duration_minutes", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("timezone", sa.String(64), nullable=False, server_default="UTC"),
        sa.Column("all_devices", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("switch_ids", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("sites", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("service_ids", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by", sa.String(64), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "nms_services",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("kind", sa.String(8), nullable=False),
        sa.Column("target", sa.String(255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("expect", sa.String(64), nullable=False, server_default=""),
        sa.Column("match", sa.String(255), nullable=False, server_default=""),
        sa.Column("record", sa.String(8), nullable=False, server_default="A"),
        sa.Column("switch_id", sa.Integer(), sa.ForeignKey("switches.id", ondelete="SET NULL"), nullable=True, index=True),
        sa.Column("site", sa.String(128), nullable=False, server_default=""),
        sa.Column("interval_seconds", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("timeout_ms", sa.Integer(), nullable=False, server_default="5000"),
        sa.Column("latency_warn_ms", sa.Integer(), nullable=True),
        sa.Column("cert_warn_days", sa.Integer(), nullable=False, server_default="21"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("state", sa.String(10), nullable=False, server_default="unknown"),
        sa.Column("state_since", sa.DateTime(timezone=True), nullable=True),
        sa.Column("fail_streak", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_check_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_latency_ms", sa.Float(), nullable=True),
        sa.Column("last_message", sa.Text(), nullable=False, server_default=""),
        sa.Column("cert_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(64), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("nms_services")
    op.drop_table("nms_maintenance")
    with op.batch_alter_table("switches") as b:
        b.drop_index("ix_switches_parent_id")
        b.drop_constraint("fk_switches_parent", type_="foreignkey")
        b.drop_column("parent_id")
