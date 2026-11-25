"""Product separation: NMS keeps its own BGP critical-prefix list instead of reading the SIEM watchlist

Revision ID: 0037
Revises: 0036
Create Date: 2026-11-23 12:00:00.000000

Data copy only: the items of the IP watchlist named "bgp_critical_prefixes" (if it exists) are copied into
wan_settings.data["bgp_critical_prefixes"] (the first row, created if missing). The watchlist itself is left as it is.
Nothing is copied if NMS already has a list. Downgrade removes only the copied key.
"""
import json

import sqlalchemy as sa
from alembic import op

revision = '0037'
down_revision = '0036'
branch_labels = None
depends_on = None

KEY = "bgp_critical_prefixes"


def _load(v):
    if v is None:
        return {}
    return v if isinstance(v, dict) else json.loads(v)


def _j(conn) -> str:
    return "CAST(:d AS json)" if conn.dialect.name == "postgresql" else ":d"


def upgrade() -> None:
    conn = op.get_bind()
    wl = conn.execute(sa.text("SELECT id FROM watchlists WHERE name = :n"), {"n": KEY}).first()
    if wl is None:
        return
    items = [{"prefix": r[0], "label": r[1] or ""} for r in conn.execute(
        sa.text("SELECT value, label FROM watchlist_items WHERE watchlist_id = :i ORDER BY id"), {"i": wl[0]})]
    if not items:
        return
    row = conn.execute(sa.text("SELECT id, data FROM wan_settings ORDER BY id LIMIT 1")).first()
    if row is None:
        conn.execute(sa.text("INSERT INTO wan_settings (data, updated_by, updated_at) VALUES (" + _j(conn) + ", 'migration 0037', CURRENT_TIMESTAMP)"),
                     {"d": json.dumps({KEY: items})})
        return
    data = _load(row[1])
    if data.get(KEY):
        return
    data[KEY] = items
    conn.execute(sa.text("UPDATE wan_settings SET data = " + _j(conn) + " WHERE id = :i"), {"d": json.dumps(data), "i": row[0]})


def downgrade() -> None:
    conn = op.get_bind()
    for rid, d in conn.execute(sa.text("SELECT id, data FROM wan_settings")).all():
        data = _load(d)
        if KEY in data:
            data.pop(KEY)
            conn.execute(sa.text("UPDATE wan_settings SET data = " + _j(conn) + " WHERE id = :i"), {"d": json.dumps(data), "i": rid})
