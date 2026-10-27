"""multi-vendor firewalls: vendor and log time zone

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-27 10:00:00.000000

Additive only: existing firewalls become vendor 'fortinet' with log time zone UTC (FortiOS logs carry their own offset).
"""
from alembic import op
import sqlalchemy as sa


revision = '0010'
down_revision = '0009'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('firewalls', schema=None) as batch_op:
        batch_op.add_column(sa.Column('vendor', sa.String(16), nullable=False, server_default='fortinet'))
        batch_op.add_column(sa.Column('log_tz', sa.String(64), nullable=False, server_default='UTC'))


def downgrade() -> None:
    with op.batch_alter_table('firewalls', schema=None) as batch_op:
        batch_op.drop_column('log_tz')
        batch_op.drop_column('vendor')
