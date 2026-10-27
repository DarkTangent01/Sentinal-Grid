"""Apply PostgreSQL (Alembic) and ClickHouse migrations, then seed defaults. Usage: python -m app.migrate"""
import asyncio
import logging
import os
import time

from alembic import command
from alembic.config import Config

from .bootstrap import seed
from .config import get_settings
from .db.ch import get_ch
from .db.ch_schema import migrate as ch_migrate
from .db.pg import session_factory
from .logging_setup import setup_logging

log = logging.getLogger("migrate")


def _retry(fn, what: str, attempts: int = 30):
    for i in range(attempts):
        try:
            return fn()
        except Exception as e:  # databases may still be starting
            log.warning("%s not ready (%s: %s), retry %d/%d", what, type(e).__name__, str(e)[:200], i + 1, attempts)
            time.sleep(2)
    raise RuntimeError(f"{what} unavailable")


async def _seed():
    async with session_factory()() as s:
        await seed(s)


def main():
    setup_logging(get_settings().log_level)
    cfg = Config(os.path.join(os.path.dirname(__file__), "..", "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(os.path.dirname(__file__), "..", "migrations"))
    _retry(lambda: command.upgrade(cfg, "head"), "postgres")
    applied = _retry(lambda: ch_migrate(get_ch()), "clickhouse")
    log.info("clickhouse migrations applied: %s", applied or "none pending")
    asyncio.run(_seed())


if __name__ == "__main__":
    main()
