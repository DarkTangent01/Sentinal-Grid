"""Simulated NMS load tests (no real devices; docs/nms/PERFORMANCE_BENCHMARKS.md): the polling engine with in-memory
SNMP agents, gateway bulk diagnostics and terminal sessions against a local asyncssh device simulator, and command
classification throughput. Uses a throw-away SQLite database and embedded ClickHouse in a temporary directory.

    python tools/nms_bench.py classifier
    python tools/nms_bench.py polling 1000
    python tools/nms_bench.py bulk 500 10 0.05        # devices, concurrency, simulated device latency per command (s)
    python tools/nms_bench.py sessions 50
"""
import asyncio, json, os, resource, statistics, sys, tempfile, time
from datetime import datetime, timedelta, timezone
B = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [B, f"{B}/tests"]
from cryptography.fernet import Fernet
tmp = tempfile.mkdtemp(prefix="nmsbench-")
os.environ.update({"SECRET_KEY": "bench-" + "k" * 40, "TOKEN_ENCRYPTION_KEY": Fernet.generate_key().decode(), "DATABASE_URL": f"sqlite+aiosqlite:///{tmp}/b.db",
                   "CLICKHOUSE_MODE": "embedded", "CLICKHOUSE_EMBEDDED_PATH": f"{tmp}/ch", "ENVIRONMENT": "test", "LOG_LEVEL": "WARNING",
                   "ACCESS_MAX_SESSIONS": "500", "ACCESS_MAX_SESSIONS_PER_USER": "500", "ACCESS_MAX_SESSIONS_PER_DEVICE": "5"})
import logging; logging.disable(logging.INFO)
from app.db import pg
from app.db.models import Base

def rss_mb():  # peak resident set size of this process (macOS reports bytes)
    r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return round(r / (1024 * 1024 if sys.platform == "darwin" else 1024), 1)

def pct(xs, p):
    xs = sorted(xs); return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))] if xs else None

async def fresh_db():
    eng = pg.init_engine(os.environ["DATABASE_URL"])
    async with eng.begin() as c:
        await c.run_sync(Base.metadata.drop_all); await c.run_sync(Base.metadata.create_all)

async def polling(n: int):
    from app.db.ch import ClickHouse, set_ch
    from app.db.ch_schema import migrate
    from app.db.models import Switch, SwitchCredential, SwitchNetwork
    from app.switches import poller as P
    from snmp_sim import FakeClient
    from switch_fixtures import cisco_c9300
    ch = ClickHouse(mode="embedded", embedded_path=os.environ["CLICKHOUSE_EMBEDDED_PATH"]); migrate(ch); set_ch(ch)
    await fresh_db()
    async with pg.session_factory()() as s:
        s.add(SwitchNetwork(cidr="10.0.0.0/8")); cred = SwitchCredential(name="c", version="v3", username="u"); s.add(cred); await s.flush()
        for i in range(n):
            s.add(Switch(name=f"sw{i}", address=f"10.{i // 250}.{i % 250}.1", vendor="cisco", credential_id=cred.id, monitoring="active",
                         capabilities={}, group_state={}, health={}, thresholds={}))
        await s.commit()
    ids = list(range(1, n + 1))
    out = {"devices": n, "interfaces_per_device": 52}
    T0 = datetime(2026, 11, 20, 10, tzinfo=timezone.utc)
    for cycle, step in ((1, 0), (2, 1)):
        t0 = time.perf_counter(); c0 = time.process_time()
        clients = {i: FakeClient(*[cisco_c9300(step)[0]], contexts=cisco_c9300(step)[1]) for i in ids}
        r = await P.run_due(ch, pg.session_factory(), now=T0 + timedelta(seconds=120 * (cycle - 1)), clients=clients)
        out[f"cycle{cycle}_s"] = round(time.perf_counter() - t0, 1); out[f"cycle{cycle}_cpu_s"] = round(time.process_time() - c0, 1)
        out[f"cycle{cycle}_polled"] = r.get("polled"); out[f"cycle{cycle}_failed"] = r.get("failed")
    out["per_device_ms_cycle2"] = round(1000 * out["cycle2_s"] / n, 1)
    out["peak_rss_mb"] = rss_mb()
    print(json.dumps(out))

async def device_server(delay: float):
    import asyncssh
    class Srv(asyncssh.SSHServer):
        def begin_auth(self, u): return True
        def password_auth_supported(self): return True
        def validate_password(self, u, p): return p == "pw-123456"
    async def handle(proc):
        if proc.command is not None:
            await asyncio.sleep(delay); proc.stdout.write("Cisco IOS XE Software, Version 17.9.4a\n" * 20); proc.exit(0); return
        proc.stdout.write("\r\nSW#")
        while True:
            try: line = await proc.stdin.readline()
            except (asyncssh.BreakReceived, asyncssh.SignalReceived): proc.stdout.write("^C\r\nSW#"); continue
            except asyncssh.TerminalSizeChanged: continue
            except Exception: break
            if not line or line.strip() == "exit": break
            proc.stdout.write("\r\nok\r\nSW#")
        proc.exit(0)
    srv = await asyncssh.create_server(Srv, "127.0.0.1", 0, server_host_keys=[asyncssh.generate_private_key("ssh-ed25519")], process_factory=handle)
    port = srv.sockets[0].getsockname()[1]
    from app.access import gateway as G
    async def dial(host, port_, host_key, **kw):
        return await asyncssh.connect("127.0.0.1", port=port, known_hosts=None, **kw)
    G._dial = dial
    return srv

async def seed_devices(n: int):
    from app.access import vault
    from app.db.models import DeviceSshCredential, Switch, SwitchNetwork, User
    await fresh_db()
    async with pg.session_factory()() as s:
        s.add(SwitchNetwork(cidr="10.0.0.0/8"))
        c = DeviceSshCredential(name="c", kind="ssh", username="u", secret_ciphertext=vault.seal("ssh", {"password": "pw-123456"})); s.add(c); await s.flush()
        for i in range(n):
            s.add(Switch(name=f"sw{i:04d}", address=f"10.{i // 250}.{i % 250}.1", vendor="cisco", family="Catalyst", os="IOS-XE", ssh_credential_id=c.id,
                         monitoring="active", capabilities={}, group_state={}, health={}, thresholds={}))
        u = User(username="eng", password_hash="x", role="analyst", products=["nms"], nms_roles=["network_engineer"]); s.add(u)
        await s.commit()
        return u.id

async def bulk(n: int, conc: int, delay: float):
    from app.access import diagnostics as DG
    from app.db.models import NmsDiagJob, NmsDiagResult, User
    from sqlalchemy import select
    srv = await device_server(delay)
    uid = await seed_devices(n)
    async with pg.session_factory()() as s:
        user = await s.get(User, uid)
    t0 = time.perf_counter()
    jid = await DG.create_job(user, list(range(1, n + 1)), ["ios.version", "ios.cpu"], [], kind="bulk", concurrency=conc, timeout=60)
    await DG.run_job(jid, user, ["ios.version", "ios.cpu"], [])
    took = time.perf_counter() - t0
    async with pg.session_factory()() as s:
        j = await s.get(NmsDiagJob, jid)
        durs = [r.duration_ms for r in (await s.execute(select(NmsDiagResult).where(NmsDiagResult.job_id == jid))).scalars() if r.duration_ms is not None]
    srv.close()
    print(json.dumps({"devices": n, "concurrency": conc, "device_delay_ms_per_command": int(delay * 1000), "status": j.status, "ok": j.completed - j.failed,
                      "failed": j.failed, "wall_s": round(took, 1), "devices_per_s": round(n / took, 1), "p50_ms": pct(durs, 50), "p95_ms": pct(durs, 95),
                      "p99_ms": pct(durs, 99), "peak_rss_mb": rss_mb()}))

class FakeWS:
    def __init__(self, cookies):
        self.cookies, self.headers, self.client = cookies, {"origin": "https://nms.example", "host": "nms.example"}, None
        self.inbox, self.sent, self.closed = asyncio.Queue(), [], None
    async def accept(self): pass
    async def close(self, code=1000): self.closed = code; await self.inbox.put(None)
    async def send_text(self, t): self.sent.append(json.loads(t))
    async def receive_text(self):
        m = await self.inbox.get()
        if m is None:
            from fastapi import WebSocketDisconnect; raise WebSocketDisconnect()
        return json.dumps(m)

async def sessions(n: int):
    import hashlib, secrets, uuid
    from app.access import terminal
    from app.db.models import NmsAccessSession, User
    from app.security import create_session_token
    srv = await device_server(0.0)
    uid = await seed_devices(n)
    tok, _ = create_session_token(uid, "analyst", 0)
    wss, tickets = [], []
    async with pg.session_factory()() as s:
        for i in range(n):
            t = secrets.token_urlsafe(32); sid = str(uuid.uuid4())
            s.add(NmsAccessSession(id=sid, user_id=uid, username="eng", switch_id=i + 1, device_name=f"sw{i}", state="pending",
                                   ticket_hash=hashlib.sha256(t.encode()).hexdigest(), ticket_expires_at=datetime.now(timezone.utc) + timedelta(minutes=5)))
            tickets.append((sid, t))
        await s.commit()
    rss0 = rss_mb()
    t0 = time.perf_counter()
    tasks = []
    for sid, t in tickets:
        ws = FakeWS({"siem_session": tok}); wss.append(ws)
        await ws.inbox.put({"t": "auth", "session": sid, "ticket": t})
        tasks.append(asyncio.create_task(terminal.handle(ws)))
    connect = []
    for ws in wss:
        t1 = time.perf_counter()
        while not any(m.get("t") == "status" for m in ws.sent):
            if time.perf_counter() - t0 > 120: break
            await asyncio.sleep(0.01)
        connect.append((time.perf_counter() - t0) * 1000)
    up = sum(1 for ws in wss if any(m.get("t") == "status" for m in ws.sent))
    all_up = time.perf_counter() - t0
    t2 = time.perf_counter()
    for ws in wss: await ws.inbox.put({"t": "i", "d": "show version\r"})
    lat = []
    for ws in wss:
        while "ok" not in "".join(m.get("d", "") for m in ws.sent if m.get("t") == "o"):
            if time.perf_counter() - t2 > 60: break
            await asyncio.sleep(0.005)
        lat.append((time.perf_counter() - t2) * 1000)
    rss1 = rss_mb()
    for ws in wss: await ws.inbox.put({"t": "close"})
    await asyncio.wait_for(asyncio.gather(*tasks), 120)
    srv.close()
    print(json.dumps({"sessions": n, "connected": up, "all_connected_s": round(all_up, 1), "connect_p95_ms": round(pct(connect, 95)),
                      "command_echo_p50_ms": round(pct(lat, 50)), "command_echo_p95_ms": round(pct(lat, 95)),
                      "peak_rss_mb_before": rss0, "peak_rss_mb_after": rss1, "approx_mb_per_session": round((rss1 - rss0) / n, 2)}))

def classifier():
    from app.access.commands import LineGuard, classify
    cmds = ["show running-config", "sh ip int br", "conf t", "show run | inc host", "get system status", "reload", "clear counters",
            "diagnose sys top 1 20 1", "/system resource print", "show version; reload"] * 10000
    t0 = time.perf_counter(); [classify(c) for c in cmds]; took = time.perf_counter() - t0
    g = LineGuard(); data = "show version\r" * 10000
    t1 = time.perf_counter(); g.feed(data); took2 = time.perf_counter() - t1
    print(json.dumps({"classify_per_s": round(len(cmds) / took), "guard_lines_per_s": round(10000 / took2)}))

if __name__ == "__main__":
    what = sys.argv[1]
    if what == "classifier": classifier()
    elif what == "polling": asyncio.run(polling(int(sys.argv[2])))
    elif what == "bulk": asyncio.run(bulk(int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])))
    elif what == "sessions": asyncio.run(sessions(int(sys.argv[2])))
