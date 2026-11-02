"""Synthetic-data API latency benchmark (SQLite + embedded ClickHouse, in-process ASGI; no production data).

Run from a backend tree:  cd backend && python tools/bench_api.py   (docs/PERFORMANCE_BENCHMARKS.md)
"""
import asyncio, os, statistics, sys, tempfile, time
tmp = tempfile.mkdtemp(prefix="bench-")
from cryptography.fernet import Fernet
os.environ.update({"SECRET_KEY": "bench-secret-key-0123456789abcdef0123456789", "TOKEN_ENCRYPTION_KEY": Fernet.generate_key().decode(),
                   "DATABASE_URL": f"sqlite+aiosqlite:///{tmp}/pg.db", "CLICKHOUSE_MODE": "embedded", "CLICKHOUSE_EMBEDDED_PATH": f"{tmp}/ch",
                   "COOKIE_SECURE": "false", "ENVIRONMENT": "test", "LOGIN_RATE_LIMIT_PER_MINUTE": "100000", "API_RATE_LIMIT_PER_MINUTE": "1000000",
                   "LOG_LEVEL": "WARNING"})
sys.path.insert(0, os.getcwd())
import httpx
from datetime import datetime, timedelta, timezone
from sqlalchemy import insert
from app.db import pg
from app.db.ch import ClickHouse, set_ch
from app.db.ch_schema import migrate
from app.db.models import Base, Switch, SwitchCredential, SwitchInterface, SwitchPollRun, TacHealthCheck, TacServer, User
from app.main import create_app
from app.security import hash_password

N_SW, N_IF, PER_DAY, N_TAC = 300, 48, 1440, 20

async def main():
    ch = ClickHouse(mode="embedded", embedded_path=os.environ["CLICKHOUSE_EMBEDDED_PATH"]); migrate(ch); set_ch(ch)
    eng = pg.init_engine(os.environ["DATABASE_URL"])
    async with eng.begin() as c:
        await c.run_sync(Base.metadata.create_all)
    now = datetime.now(timezone.utc)
    async with pg.session_factory()() as s:
        s.add(User(username="admin1", password_hash=hash_password("correct-horse-battery-staple"), role="admin"))
        cred = SwitchCredential(name="ro", version="v2c", secret_ciphertext=None); s.add(cred); await s.flush()
        await s.execute(insert(Switch), [{"name": f"SW{i:04d}", "address": f"10.{i // 250}.{i % 250}.1", "credential_id": cred.id, "site": f"S{i % 10}",
                                          "capabilities": {}, "group_state": {}, "health": {}, "thresholds": {}} for i in range(N_SW)])
        await s.execute(insert(SwitchInterface), [{"switch_id": i + 1, "ifindex": j, "name": f"Gi{j}", "rx_util": (i * j) % 100, "tx_util": (i + j) % 100,
                                                   "in_errors_delta": j % 7, "crc_delta": 0, "present": True} for i in range(N_SW) for j in range(N_IF)])
        rows = [{"switch_id": i + 1, "kind": "poll", "ok": k % 17 != 0, "duration_ms": 200 + k % 900, "error": None if k % 17 else "timeout",
                 "started_at": now - timedelta(minutes=k)} for i in range(N_SW) for k in range(PER_DAY)]
        for x in range(0, len(rows), 20000):
            await s.execute(insert(SwitchPollRun), rows[x:x + 20000])
        await s.execute(insert(TacServer), [{"name": f"tac{i}", "kind": "external", "management_address": f"10.9.0.{i}"} for i in range(N_TAC)])
        await s.execute(insert(TacHealthCheck), [{"server_id": i + 1, "status": "up" if k % 9 else "down", "at": now - timedelta(minutes=k)}
                                                 for i in range(N_TAC) for k in range(PER_DAY)])
        await s.commit()
    app = create_app()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test", timeout=300) as c:
        r = await c.post("/api/auth/login", json={"username": "admin1", "password": "correct-horse-battery-staple"}); assert r.status_code == 200, r.text
        for name, url in [("GET /api/snmp/polling-health?range=24h", "/api/snmp/polling-health?range=24h"),
                          ("GET /api/switches/interfaces?sort=util&limit=100", "/api/switches/interfaces?sort=util&limit=100"),
                          ("GET /api/switches/interfaces?errors_only=true&sort=errors", "/api/switches/interfaces?errors_only=true&sort=errors"),
                          ("GET /api/tacacs/health", "/api/tacacs/health")]:
            ts = []
            for i in range(31):
                t = time.perf_counter(); rr = await c.get(url); dt = time.perf_counter() - t
                assert rr.status_code == 200, (url, rr.status_code, rr.text[:200])
                if i: ts.append(dt * 1000)  # first call warms caches
            ts.sort()
            print(f"{name:58s} p50 {statistics.median(ts):8.1f} ms  p95 {ts[int(len(ts) * .95) - 1]:8.1f} ms  bytes {len(rr.content)}")
asyncio.run(main())
