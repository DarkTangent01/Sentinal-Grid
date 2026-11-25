"""report runs keep a PDF copy

Revision ID: 0032
Revises: 0031
Create Date: 2026-11-15 14:00:00.000000

Additive only: one nullable column. Downgrade drops it.
"""
from alembic import op
import sqlalchemy as sa


revision = '0032'
down_revision = '0031'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("report_runs", sa.Column("pdf", sa.LargeBinary(), nullable=True))


def downgrade() -> None:
    op.drop_column("report_runs", "pdf")
