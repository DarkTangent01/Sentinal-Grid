"""wireless rogue access points (controller rogue detection, read-only)

Revision ID: 0031
Revises: 0030
Create Date: 2026-11-15 13:00:00.000000

Additive only: one new table. Downgrade drops it.
"""
from alembic import op
import sqlalchemy as sa


revision = '0031'
down_revision = '0030'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "wireless_rogues",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("wlc_id", sa.Integer(), sa.ForeignKey("switches.id", ondelete="CASCADE"), nullable=False),
        sa.Column("mac", sa.String(17), nullable=False),
        sa.Column("ssid", sa.String(64), nullable=False, server_default=""),
        sa.Column("channel", sa.Integer(), nullable=True),
        sa.Column("rssi_dbm", sa.Float(), nullable=True),
        sa.Column("clients", sa.Integer(), nullable=True),
        sa.Column("detecting_aps", sa.Integer(), nullable=True),
        sa.Column("detecting_ap", sa.String(64), nullable=False, server_default=""),
        sa.Column("type", sa.String(16), nullable=False, server_default=""),
        sa.Column("on_network", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("state", sa.String(24), nullable=False, server_default=""),
        sa.Column("class_type", sa.String(24), nullable=False, server_default=""),
        sa.Column("spoofs_ssid", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("present", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("wlc_id", "mac", name="uq_wireless_rogue"),
    )
    op.create_index("ix_wireless_rogues_wlc_id", "wireless_rogues", ["wlc_id"])
    op.create_index("ix_wireless_rogues_present", "wireless_rogues", ["present"])


def downgrade() -> None:
    op.drop_table("wireless_rogues")
