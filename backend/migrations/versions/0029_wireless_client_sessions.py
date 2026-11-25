"""wireless client sessions (client connection history)

Revision ID: 0029
Revises: 0028
Create Date: 2026-11-14 12:00:00.000000

Additive only: a new table and one nullable column on wireless_clients (no rewrite, no data change). Downgrade drops
both. See app/wireless/history.py and docs/WIRELESS_CLIENT_ANALYTICS.md.
"""
from alembic import op
import sqlalchemy as sa


revision = '0029'
down_revision = '0028'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "wireless_client_sessions",
        sa.Column("id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), primary_key=True),
        sa.Column("wlc_id", sa.Integer(), sa.ForeignKey("switches.id", ondelete="CASCADE"), nullable=False),
        sa.Column("mac", sa.String(17), nullable=False),
        sa.Column("ip", sa.String(64), nullable=False, server_default=""),
        sa.Column("ssid", sa.String(64), nullable=False, server_default=""),
        sa.Column("vlan", sa.Integer(), nullable=True),
        sa.Column("band", sa.String(16), nullable=False, server_default=""),
        sa.Column("first_ap_id", sa.Integer(), nullable=True),
        sa.Column("last_ap_id", sa.Integer(), nullable=True),
        sa.Column("site", sa.String(128), nullable=False, server_default=""),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("start_source", sa.String(16), nullable=False, server_default="observed"),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("end_reason", sa.String(24), nullable=False, server_default=""),
        sa.Column("disconnect_reason", sa.String(64), nullable=False, server_default=""),
        sa.Column("roams", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("band_changes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("aps", sa.JSON(), nullable=False, server_default="[]"),
    )
    op.create_index("ix_wireless_client_sessions_mac", "wireless_client_sessions", ["mac"])
    op.create_index("ix_wireless_sessions_wlc_mac_start", "wireless_client_sessions", ["wlc_id", "mac", "started_at"])
    op.create_index("ix_wireless_sessions_started", "wireless_client_sessions", ["started_at"])
    op.create_index("ix_wireless_sessions_open", "wireless_client_sessions", ["wlc_id", "ended_at"])
    op.add_column("wireless_clients", sa.Column("session_id", sa.BigInteger(), nullable=True))


def downgrade() -> None:
    op.drop_column("wireless_clients", "session_id")
    op.drop_table("wireless_client_sessions")
