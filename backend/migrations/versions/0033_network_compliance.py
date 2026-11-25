"""network compliance: runs, per-device results, exceptions

Revision ID: 0033
Revises: 0032
Create Date: 2026-11-14 15:00:00.000000

Additive only: three new tables. Downgrade drops them.
"""
from alembic import op
import sqlalchemy as sa


revision = '0033'
down_revision = '0032'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "net_compliance_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("trigger", sa.String(16), nullable=False),
        sa.Column("triggered_by", sa.String(64), nullable=False),
        sa.Column("catalog_version", sa.String(16), nullable=False),
        sa.Column("devices", sa.Integer(), nullable=False),
        sa.Column("totals", sa.JSON(), nullable=False),
        sa.Column("summary", sa.JSON(), nullable=False),
    )
    op.create_index("ix_net_compliance_runs_started_at", "net_compliance_runs", ["started_at"])
    op.create_table(
        "net_compliance_results",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("run_id", sa.Integer(), sa.ForeignKey("net_compliance_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("device_kind", sa.String(16), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("device_name", sa.String(128), nullable=False),
        sa.Column("device_type", sa.String(16), nullable=False),
        sa.Column("vendor", sa.String(16), nullable=False),
        sa.Column("site", sa.String(128), nullable=False),
        sa.Column("results", sa.JSON(), nullable=False),
    )
    op.create_index("ix_net_compliance_results_run_device", "net_compliance_results", ["run_id", "device_kind", "device_id"])
    op.create_table(
        "net_compliance_exceptions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("check_id", sa.String(16), nullable=False),
        sa.Column("device_kind", sa.String(16), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_net_compliance_exceptions_check_id", "net_compliance_exceptions", ["check_id"])


def downgrade() -> None:
    op.drop_table("net_compliance_exceptions")
    op.drop_table("net_compliance_results")
    op.drop_table("net_compliance_runs")
