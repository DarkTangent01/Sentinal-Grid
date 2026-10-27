import os
import sys
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet

_tmp = tempfile.mkdtemp(prefix="fsiem-test-")
os.environ.update({
    "SECRET_KEY": "test-secret-key-0123456789abcdef0123456789",
    "TOKEN_ENCRYPTION_KEY": Fernet.generate_key().decode(),
    "DATABASE_URL": f"sqlite+aiosqlite:///{_tmp}/pg.db",
    "CLICKHOUSE_MODE": "embedded",
    "CLICKHOUSE_EMBEDDED_PATH": f"{_tmp}/ch",
    "COOKIE_SECURE": "false",
    "ENVIRONMENT": "test",
    "LOGIN_RATE_LIMIT_PER_MINUTE": "1000",
})
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402

from app.db import pg  # noqa: E402
from app.db.ch import ClickHouse, set_ch  # noqa: E402
from app.db.ch_schema import migrate  # noqa: E402
from app.db.models import Base  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def ch():
    c = ClickHouse(mode="embedded", embedded_path=os.environ["CLICKHOUSE_EMBEDDED_PATH"])
    migrate(c)
    set_ch(c)
    return c


@pytest.fixture
def clean_ch(ch):
    ch.command("TRUNCATE TABLE events")
    ch.command("TRUNCATE TABLE events_minute")
    ch.command("TRUNCATE TABLE events_1m")
    ch.command("TRUNCATE TABLE src_hourly")
    ch.command("TRUNCATE TABLE bgp_events")
    ch.command("TRUNCATE TABLE bgp_samples")
    yield ch


@pytest_asyncio.fixture
async def db():
    engine = pg.init_engine(os.environ["DATABASE_URL"])
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.drop_all)
        await c.run_sync(Base.metadata.create_all)
    async with pg.session_factory()() as s:
        yield s
    await engine.dispose()


def fixture_lines():
    return [l for l in (FIXTURES / "fortigate_syslog.log").read_text().splitlines() if l and not l.startswith("#")]
