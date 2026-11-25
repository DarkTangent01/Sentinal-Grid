"""switches.wireless_lease_until

Revision ID: 0028
Revises: 0027
Create Date: 2026-11-13 12:00:00.000000

Additive only: one nullable column (no table rewrite on PostgreSQL, no data change). A wireless controller's large
wireless tables are polled as their own job, leased separately from the controller's quick metrics
(docs/performance/FINAL_REMEDIATION_REPORT.md, RC-13). Downgrade drops the column.
"""
from alembic import op
import sqlalchemy as sa


revision = '0028'
down_revision = '0027'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("switches", sa.Column("wireless_lease_until", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("switches", "wireless_lease_until")
