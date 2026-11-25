"""read-only SSH configuration backup

Revision ID: 0030
Revises: 0029
Create Date: 2026-11-15 12:00:00.000000

Additive only: two new tables and four nullable / defaulted columns on switches. Downgrade drops them.
"""
from alembic import op
import sqlalchemy as sa


revision = '0030'
down_revision = '0029'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "device_ssh_credentials",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(64), nullable=False, unique=True),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column("secret_ciphertext", sa.Text(), nullable=False, server_default=""),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_by", sa.String(64), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "device_config_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("switch_id", sa.Integer(), sa.ForeignKey("switches.id", ondelete="CASCADE"), nullable=False),
        sa.Column("taken_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("config_hash", sa.String(64), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("text", sa.Text(), nullable=False, server_default=""),
        sa.Column("added", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("removed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("diff", sa.Text(), nullable=False, server_default=""),
        sa.Column("trigger", sa.String(32), nullable=False, server_default="schedule"),
    )
    op.create_index("ix_device_config_snapshots_switch_taken", "device_config_snapshots", ["switch_id", "taken_at"])
    op.create_index("ix_device_config_snapshots_taken_at", "device_config_snapshots", ["taken_at"])
    with op.batch_alter_table("switches") as b:
        b.add_column(sa.Column("ssh_credential_id", sa.Integer(), sa.ForeignKey("device_ssh_credentials.id", ondelete="SET NULL",
                                                                                 name="fk_switches_ssh_credential"), nullable=True))
        b.add_column(sa.Column("ssh_host_key", sa.Text(), nullable=False, server_default=""))
        b.add_column(sa.Column("config_backup_at", sa.DateTime(timezone=True), nullable=True))
        b.add_column(sa.Column("config_backup_error", sa.Text(), nullable=False, server_default=""))


def downgrade() -> None:
    with op.batch_alter_table("switches") as b:
        b.drop_constraint("fk_switches_ssh_credential", type_="foreignkey")
        b.drop_column("config_backup_error")
        b.drop_column("config_backup_at")
        b.drop_column("ssh_host_key")
        b.drop_column("ssh_credential_id")
    op.drop_table("device_config_snapshots")
    op.drop_table("device_ssh_credentials")
