"""session revocation: users.session_version

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-23 16:00:00.000000

Additive only: existing rows get 0, which matches tokens issued before this change (they carry no `ver` claim).
"""
from alembic import op
import sqlalchemy as sa


revision = '0005'
down_revision = '0004'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('session_version', sa.Integer(), nullable=False, server_default='0'))


def downgrade() -> None:
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('session_version')
