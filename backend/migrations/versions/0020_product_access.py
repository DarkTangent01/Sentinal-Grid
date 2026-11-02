"""Product access: users.products (Sentinel Grid "grid", Sentinel NMS "nms") and users.default_product.

Migration policy (docs/PRODUCTS.md): before the split every account could open every page, so every existing account
keeps both products. Administrators have every product implicitly regardless of the column. Accounts created after
this migration get only the products an administrator assigns (server default: none).

Revision ID: 0020
Revises: 0019
Create Date: 2026-11-01
"""
from alembic import op
import sqlalchemy as sa


revision = '0020'
down_revision = '0019'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('products', sa.JSON(), server_default=sa.text("'[]'"), nullable=False))
        batch_op.add_column(sa.Column('default_product', sa.String(length=8), nullable=True))
    op.execute("UPDATE users SET products = '[\"grid\", \"nms\"]'")


def downgrade() -> None:
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('default_product')
        batch_op.drop_column('products')
