"""Multi-vendor SNMP framework: device fingerprint fields and overrides, polling backoff, SNMPv3 engine IDs, custom OID
profiles with version history, imported MIB modules and built-in metric switches.

Revision ID: 0026
Revises: 0025
Create Date: 2026-11-02 14:00:00
"""
from alembic import op
import sqlalchemy as sa

revision = '0026'
down_revision = '0025'
branch_labels = None
depends_on = None

SW_COLS = [("product_line", 64), ("device_type", 16), ("id_confidence", 16), ("vendor_override", 16), ("family_override", 64), ("engine_id", 80)]


def upgrade() -> None:
    with op.batch_alter_table("switches") as b:
        for name, n in SW_COLS:
            b.add_column(sa.Column(name, sa.String(n), nullable=False, server_default=""))
        b.add_column(sa.Column("backoff_until", sa.DateTime(timezone=True), nullable=True))
    with op.batch_alter_table("users") as b:
        b.add_column(sa.Column("sites", sa.JSON(), nullable=False, server_default=sa.text("'[]'")))
    op.create_table(
        "snmp_custom_oids",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(64), nullable=False, unique=True),
        sa.Column("oid", sa.String(255), nullable=False),
        sa.Column("method", sa.String(8), nullable=False, server_default="get"),
        sa.Column("value_type", sa.String(8), nullable=False, server_default="gauge"),
        sa.Column("unit", sa.String(16), nullable=False, server_default=""),
        sa.Column("scale", sa.Float(), nullable=False, server_default="1"),
        sa.Column("vendor", sa.String(16), nullable=False, server_default=""),
        sa.Column("product_line", sa.String(64), nullable=False, server_default=""),
        sa.Column("switch_ids", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_by", sa.String(64), nullable=False, server_default=""),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "snmp_profile_versions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kind", sa.String(8), nullable=False),
        sa.Column("ref_id", sa.Integer(), nullable=False, index=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("action", sa.String(16), nullable=False, server_default="update"),
        sa.Column("created_by", sa.String(64), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "snmp_mib_modules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("imports", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("unresolved", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("objects", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("imported_by", sa.String(64), nullable=False, server_default=""),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "snmp_metric_settings",
        sa.Column("key", sa.String(96), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("updated_by", sa.String(64), nullable=False, server_default=""),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    for t in ("snmp_metric_settings", "snmp_mib_modules", "snmp_profile_versions", "snmp_custom_oids"):
        op.drop_table(t)
    with op.batch_alter_table("users") as b:
        b.drop_column("sites")
    with op.batch_alter_table("switches") as b:
        b.drop_column("backoff_until")
        for name, _ in reversed(SW_COLS):
            b.drop_column(name)
