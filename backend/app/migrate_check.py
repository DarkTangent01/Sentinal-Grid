"""Pre-deployment migration check (scripts/release.sh runs it with the new image before migrating).

Lists the Alembic revisions the database has not applied yet and refuses to continue when one of them is destructive,
unless the operator passed --allow-destructive. Sentinel deploys while the previous version keeps running, so every
migration must be expand-only (docs/deployment-architecture.md, "Database migrations"): add tables / columns / indexes,
backfill, and remove the old schema only in a later release, after no running version uses it.

Destructive (in upgrade()): op.drop_table, op.drop_column, op.rename_table, op.alter_column renaming a column or changing
its type, and op.execute with DROP / TRUNCATE / DELETE / RENAME SQL.

    python -m app.migrate_check                  exit 0: nothing pending or all expand-only
    python -m app.migrate_check --allow-destructive
exit 3: destructive revision pending (listed); exit 2: the database cannot be read.
"""
from __future__ import annotations

import ast
import asyncio
import os
import re
import sys

from alembic.config import Config
from alembic.script import ScriptDirectory

DESTRUCTIVE_OPS = {"drop_table", "drop_column", "rename_table"}
DESTRUCTIVE_SQL = re.compile(r"\b(DROP\s+(TABLE|COLUMN|SCHEMA|INDEX)|TRUNCATE|DELETE\s+FROM|RENAME\s+(TO|COLUMN))\b", re.I)


def findings(source: str) -> list[str]:
    """Destructive operations inside upgrade() of one revision module."""
    tree = ast.parse(source)
    up = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "upgrade"), None)
    if up is None:
        return []
    out = []
    for node in ast.walk(up):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        name = node.func.attr
        if name in DESTRUCTIVE_OPS:
            out.append(f"{name} (line {node.lineno})")
        elif name == "alter_column" and any(k.arg in ("new_column_name", "type_") for k in node.keywords):
            out.append(f"alter_column renaming or retyping (line {node.lineno})")
        elif name == "execute":
            text = " ".join(a.value for a in ast.walk(node) if isinstance(a, ast.Constant) and isinstance(a.value, str))
            if DESTRUCTIVE_SQL.search(text):
                out.append(f"execute: {DESTRUCTIVE_SQL.search(text).group(0)} (line {node.lineno})")
    return out


def script_dir() -> ScriptDirectory:
    base = os.path.join(os.path.dirname(__file__), "..")
    cfg = Config(os.path.join(base, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(base, "migrations"))
    return ScriptDirectory.from_config(cfg)


def pending(script: ScriptDirectory, current: str | None) -> list:
    return list(reversed(list(script.iterate_revisions(script.get_current_head(), current))))


async def current_revision() -> str | None:
    from sqlalchemy import text
    from .db.pg import get_engine
    async with get_engine().connect() as c:
        try:
            return (await c.execute(text("SELECT version_num FROM alembic_version"))).scalar()
        except Exception:
            return None                      # a new database: everything is pending


def main(argv: list[str]) -> int:
    allow = "--allow-destructive" in argv
    try:
        cur = asyncio.run(current_revision())
    except Exception as e:
        print(f"migrate-check: cannot read the database ({type(e).__name__})")
        return 2
    script = script_dir()
    revs = pending(script, cur)
    print(f"migrate-check: database at {cur or 'empty'}, head {script.get_current_head()}, {len(revs)} pending")
    bad = 0
    for r in revs:
        with open(r.path) as f:
            found = findings(f.read())
        print(f"  {r.revision}: {(r.doc or '').splitlines()[0][:90] if r.doc else ''}" + (f"  DESTRUCTIVE: {', '.join(found)}" if found else ""))
        bad += bool(found)
    if bad and not allow and cur is not None:     # an empty database: no running version uses the old schema
        print("migrate-check: refusing destructive migration(s): the running version may still use that schema. Split it "
              "(expand now, contract in a later release) or rerun with --allow-destructive after a backup.")
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
