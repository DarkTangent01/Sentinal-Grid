"""Regression tests for the 2026-11 performance/reliability batch (see docs/IMPLEMENTATION_CHANGELOG.md)."""
import os

from app.config import get_settings
from app.db import pg

from .test_api import api  # noqa: F401  (fixture)


def _pool(url: str, **kw):
    engine = pg.init_engine(url, **kw)
    try:
        return engine.sync_engine.pool
    finally:
        pg.init_engine(os.environ["DATABASE_URL"])  # restore the test database for later tests


def test_pool_defaults_fit_the_connection_budget():
    st = get_settings()
    pool = _pool("postgresql+asyncpg://u:p@127.0.0.1:1/db")  # no connection is opened until first use
    assert pool.size() == st.db_pool_size == 4
    assert pool._max_overflow == st.db_max_overflow == 4
    assert pool._recycle == st.db_pool_recycle_seconds and pool._timeout == st.db_pool_timeout_seconds


def test_pool_override_for_worker_and_parsers():
    pool = _pool("postgresql+asyncpg://u:p@127.0.0.1:1/db", pool_size=1, max_overflow=1)
    assert pool.size() == 1 and pool._max_overflow == 1


def test_connection_budget_stays_under_postgres_default():
    """api x2 + worker + syslog receiver + 4 parsers + traps must stay below max_connections=100 (migrate exits first)."""
    from app.worker import worker_pool_need
    st = get_settings()
    per = st.db_pool_size + st.db_max_overflow
    worker = max(10 + st.db_max_overflow, worker_pool_need(st))
    total = 2 * per + worker + (per + 4 * 2) + per
    assert worker_pool_need(st) >= 20 + st.switch_max_concurrent_polls  # every concurrent poll can get a session
    assert total < 100, total


# ------------------------------------------------------------------ ClickHouse client pool
class _FakeCH:
    live = 0
    peak = 0
    created = 0
    lock = __import__("threading").Lock()

    def __init__(self, **kw):
        type(self).created += 1

    def query(self, sql, parameters=None):
        import time
        cls = type(self)
        with cls.lock:
            cls.live += 1
            cls.peak = max(cls.peak, cls.live)
        time.sleep(0.2)
        with cls.lock:
            cls.live -= 1

        class R:
            column_names = ["x"]
            result_rows = [(1,)]
        return R()


async def test_clickhouse_queries_run_concurrently_up_to_pool_size(monkeypatch):
    import asyncio
    import time
    import clickhouse_connect
    from app.db.ch import ClickHouse
    _FakeCH.live = _FakeCH.peak = _FakeCH.created = 0
    monkeypatch.setattr(clickhouse_connect, "get_client", lambda **kw: _FakeCH(**kw))
    monkeypatch.setenv("CLICKHOUSE_POOL_SIZE", "4")
    get_settings.cache_clear()
    try:
        ch = ClickHouse(mode="server")
        t0 = time.monotonic()
        res = await asyncio.gather(*(ch.aquery("SELECT 1 AS x") for _ in range(8)))
        took = time.monotonic() - t0
    finally:
        monkeypatch.delenv("CLICKHOUSE_POOL_SIZE")
        get_settings.cache_clear()
    assert res == [[{"x": 1}]] * 8
    assert _FakeCH.peak == 4             # the old single locked client never exceeded 1
    assert _FakeCH.created == 4          # clients are reused, not created per query
    assert took < 0.75                   # 8 x 0.2 s in 2 waves, vs 1.6 s serialised


# ------------------------------------------------------------------ migration 0027 (query indexes)
def test_migration_0027_upgrade_downgrade_roundtrip(tmp_path, monkeypatch):
    """Applies the full chain on a fresh SQLite file, then 0027 down and up again; indexes appear/disappear."""
    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    url = f"sqlite+aiosqlite:///{tmp_path}/mig.db"
    monkeypatch.setenv("DATABASE_URL", url)
    get_settings.cache_clear()
    try:
        cfg = Config(str(root / "alembic.ini"))
        cfg.set_main_option("script_location", str(root / "migrations"))

        def indexes():
            eng = sa.create_engine(f"sqlite:///{tmp_path}/mig.db")
            with eng.connect() as c:
                return {r[0] for r in c.execute(sa.text("SELECT name FROM sqlite_master WHERE type='index'"))}

        command.upgrade(cfg, "head")
        assert {"ix_alerts_dst_ip", "ix_switch_events_switch_at", "ix_wireless_events_ap_at"} <= indexes()
        command.downgrade(cfg, "0026")
        assert not {"ix_alerts_dst_ip", "ix_switch_events_switch_at"} & indexes()
        command.upgrade(cfg, "head")
        assert "ix_tacacs_health_checks_server_at" in indexes()
    finally:
        monkeypatch.setenv("DATABASE_URL", os.environ["DATABASE_URL"])
        get_settings.cache_clear()


# ------------------------------------------------------------------ ingestion: bounded buffer, retry, dead letter
class _FlakyCH:
    """Fails every insert while `down`; always rejects chunks containing a 'poison' event."""
    def __init__(self):
        self.down = False
        self.rows: list[dict] = []

    async def ainsert(self, table, rows, columns):
        self.insert(table, rows, columns)

    def insert(self, table, rows, columns):
        if self.down:
            raise ConnectionError("clickhouse down")
        if any(r.get("_poison") for r in rows):
            raise ValueError("Too many partitions for single INSERT block")
        self.rows.extend(rows)


def _sink(ch, monkeypatch, tmp_path, batch=10, cap=50):
    from app.ingest.pipeline import DeviceRegistry, EventSink
    monkeypatch.setenv("SYSLOG_BUFFER_MAX_EVENTS", str(cap))
    monkeypatch.setenv("INGEST_DEADLETTER_DIR", str(tmp_path / "dl"))
    get_settings.cache_clear()
    sink = EventSink(ch, DeviceRegistry(), batch_size=batch)
    sink.stats_hook = lambda st: None  # no Postgres in these unit tests
    return sink


def _add(sink, n, start=0, poison=False):
    from .test_storage_analytics import FW, traffic
    for i in range(start, start + n):
        ev = sink.add_fields(traffic(i, session=i), source="syslog", raw=None, firewall=FW)
        if ev is not None and poison:
            ev["_poison"] = True


async def test_clickhouse_outage_keeps_events_in_order_and_bounded(monkeypatch, tmp_path):
    ch = _FlakyCH()
    sink = _sink(ch, monkeypatch, tmp_path)
    ch.down = True
    _add(sink, 30)
    for _ in range(5):                      # an outage never dead-letters: nothing is inserting at all
        assert await sink.flush() == 0
    assert sink.pending == 30 and sink.counters["dead_lettered"] == 0 and sink.counters["insert_failures"] == 15
    _add(sink, 30, start=30)                # cap is 50: the last 10 are refused and counted, not silently lost
    assert sink.saturated and sink.pending == 50 and sink.counters["dropped_buffer_full"] == 10
    ch.down = False
    assert await sink.flush() == 50
    assert [r["session_id"] for r in ch.rows] == list(range(50)) and sink.pending == 0
    get_settings.cache_clear()


async def test_poison_chunk_is_dead_lettered_and_replayable(monkeypatch, tmp_path):
    from app.ingest import deadletter
    ch = _FlakyCH()
    sink = _sink(ch, monkeypatch, tmp_path)
    _add(sink, 10, poison=True)             # exactly one chunk ClickHouse will keep rejecting
    _add(sink, 10, start=10)
    assert await sink.flush() == 10         # the good chunk still lands
    for i in range(2):
        _add(sink, 10, start=20 + 10 * i)
        assert await sink.flush() == 10     # ingestion keeps flowing behind the bad chunk
    assert sink.counters["dead_lettered"] == 10 and sink.pending == 0
    files = deadletter.files()
    assert len(files) == 1
    spooled = deadletter.read(files[0])
    assert len(spooled) == 10 and isinstance(spooled[0]["event_time"], type(ch.rows[0]["event_time"]))
    for ev in spooled:
        ev.pop("_poison")                   # "fix the cause", then replay
    deadletter.write(spooled)
    files[0].unlink()
    assert deadletter.replay(ch) == (10, 0) and not deadletter.files()
    assert len(ch.rows) == 40
    get_settings.cache_clear()


# ------------------------------------------------------------------ alert engine: batched latest-alert lookup
async def test_upsert_detections_batches_lookup_and_handles_repeat_groups(db):
    from datetime import datetime, timezone
    from sqlalchemy import event, select
    from app.alerts.engine import Detection, ensure_default_rules, upsert_detections
    from app.db.models import Alert, AlertRule
    await ensure_default_rules(db)
    rule = (await db.execute(select(AlertRule).where(AlertRule.key == "port_scan"))).scalar_one()
    now = datetime.now(timezone.utc)

    def det(g):
        return Detection(group_key=g, src_ip="10.0.0.1", dst_ip=None, first_seen=now, last_seen=now, count=5,
                         explanation="x", evidence={}, event_filter={}, firewall_ids=[1], sites=["Lab"])
    selects = []
    eng = db.bind.sync_engine if hasattr(db.bind, "sync_engine") else db.get_bind()
    listener = lambda *a: selects.append(a[2]) if a[2].lstrip().upper().startswith("SELECT") and "alerts" in a[2] else None  # noqa: E731
    event.listen(eng, "before_cursor_execute", listener)
    try:
        # 50 groups plus a repeated group in the same run (must update, not insert a duplicate open_seq)
        st = await upsert_detections(db, rule, [det(f"g{i}") for i in range(50)] + [det("g0")], now)
    finally:
        event.remove(eng, "before_cursor_execute", listener)
    assert st["created"] == 50 and st["updated"] == 1
    alert_selects = [q for q in selects if "open_seq" in q]
    assert len(alert_selects) == 1, alert_selects     # was one SELECT per detection (51)
    assert len((await db.execute(select(Alert))).scalars().all()) == 50
    st2 = await upsert_detections(db, rule, [det("g1")], now)
    assert st2 == {**st2, "created": 0, "updated": 1}


# ------------------------------------------------------------------ /api/snmp/polling-health aggregates in SQL
async def test_polling_health_aggregates_runs_in_sql(api, db, ch):  # noqa: F811
    from datetime import datetime, timedelta, timezone
    from app.db.models import SwitchPollRun
    from .test_iac import As
    from .test_switches import _seed
    admin = await As.login(api, "admin1")
    sw, _ = await _seed(db)
    now = datetime.now(timezone.utc)
    runs = [(True, 100, None), (True, 300, None), (False, 9000, "timeout after 9s"), (False, 50, "request timed out"),
            (False, 10, "auth failure: wrong key"), (False, None, None)]
    for i, (ok, dur, err) in enumerate(runs):
        db.add(SwitchPollRun(switch_id=sw.id, kind="poll", ok=ok, duration_ms=dur, error=err, started_at=now - timedelta(minutes=i + 1)))
    db.add(SwitchPollRun(switch_id=sw.id, kind="poll", ok=True, duration_ms=1, started_at=now - timedelta(days=3)))  # out of range
    db.add(SwitchPollRun(switch_id=sw.id, kind="discovery", ok=True, duration_ms=1, started_at=now))                 # not a poll
    await db.commit()
    r = (await admin.get("/api/snmp/polling-health", params={"range": "24h"})).json()
    d = next(x for x in r["devices"] if x["switch_id"] == sw.id)
    assert d["polls"] == 6 and d["success_pct"] == 33.3 and d["failures"] == 4
    assert d["timeouts"] == 2 and d["auth_failures"] == 1
    assert d["avg_duration_ms"] == round((100 + 300 + 9000 + 50 + 10 + 0) / 6) and d["max_duration_ms"] == 9000
    assert r["summary"]["polls"] == 6 and r["summary"]["timeouts"] == 2


# ------------------------------------------------------------------ /api/switches/interfaces pages in SQL
async def test_fleet_interfaces_sort_filter_page_in_sql(api, db):  # noqa: F811
    from sqlalchemy import select
    from app.db.models import Switch, SwitchInterface, User
    from .test_iac import As
    from .test_switches import _seed
    admin = await As.login(api, "admin1")
    sw, cred = await _seed(db)
    other = Switch(name="AAA-SW", address="192.0.2.11", credential_id=cred.id, site="OTHER", capabilities={}, group_state={}, health={}, thresholds={})
    db.add(other)
    await db.flush()
    spec = [  # (switch, ifindex, rx_util, tx_util, in_err, crc, present)
        (sw, 1, 10.0, 90.0, 0, 0, True), (sw, 2, 50.0, 5.0, 3, 0, True), (sw, 3, None, None, 0, 7, True),
        (sw, 4, 99.0, 99.0, 0, 0, False), (other, 1, 70.0, 0.0, 0, 0, True), (other, 2, 20.0, 30.0, 1, 1, True)]
    for w, ix, rx, tx, ie, crc, present in spec:
        db.add(SwitchInterface(switch_id=w.id, ifindex=ix, name=f"Gi{ix}", rx_util=rx, tx_util=tx, in_errors_delta=ie, crc_delta=crc, present=present))
    await db.commit()

    def ids(r):
        return [(x["switch"], x["ifindex"]) for x in r["items"]]
    r = (await admin.get("/api/switches/interfaces", params={"sort": "util"})).json()
    assert r["total"] == 5                                             # not-present interface excluded
    assert ids(r) == [(sw.name, 1), (other.name, 1), (sw.name, 2), (other.name, 2), (sw.name, 3)]
    r = (await admin.get("/api/switches/interfaces", params={"sort": "errors", "errors_only": True})).json()
    assert r["total"] == 3 and ids(r) == [(sw.name, 3), (sw.name, 2), (other.name, 2)]
    p1 = (await admin.get("/api/switches/interfaces", params={"sort": "name", "limit": 2})).json()
    p2 = (await admin.get("/api/switches/interfaces", params={"sort": "name", "limit": 2, "offset": 2})).json()
    assert p1["total"] == 5 and ids(p1) == [("AAA-SW", 1), ("AAA-SW", 2)] and ids(p2) == [(sw.name, 1), (sw.name, 2)]
    assert p1["items"][0]["site"] == "OTHER"
    me = (await db.execute(select(User).where(User.username == "analyst1"))).scalars().one()
    assert (await admin.c.patch(f"/api/users/{me.id}", headers=admin.h, json={"sites": ["WH1"]})).status_code == 200
    analyst = await As.login(api, "analyst1")
    r = (await analyst.get("/api/switches/interfaces")).json()
    assert r["total"] == 3 and {x["switch"] for x in r["items"]} == {sw.name}   # site scope still enforced


# ------------------------------------------------------------------ firewall polling backoff
def test_firewall_backoff_schedule():
    from app.worker import firewall_backoff
    f, d = firewall_backoff(0, "unreachable", 60)
    assert (f, d) == (1, 0)                                  # 1st failure: normal cadence (confirm the outage)
    f, d = firewall_backoff(f, "unreachable", 60)
    assert d == 60                                           # 2nd: starts backing off
    for _ in range(10):
        f, d = firewall_backoff(f, "unreachable", 60)
    assert d == 900                                          # capped at 15 minutes
    assert firewall_backoff(f, "ok", 60) == (0, 0)           # recovery resets immediately
    assert firewall_backoff(0, "auth_error", 60)[1] == 60    # bad credentials: back off from the first failure
    assert firewall_backoff(3, "error", 60) == (0, 0)        # other API errors are not treated as an outage


# ------------------------------------------------------------------ threat-intel CIDR lookup
def test_ti_cidr_lookup_matches_most_specific_block_bruteforce():
    import ipaddress
    import random
    from app.enrich.ti import IndicatorSet
    rnd = random.Random(7)
    rows = [("10.0.0.0/8", "cidr", "feed", "wide"), ("10.0.0.0/8", "cidr", "feed2", "dup")]
    for i in range(3000):
        base = rnd.choice([10, 45, 100, 185, 203])
        plen = rnd.choice([12, 16, 20, 24, 28, 30])
        net = ipaddress.ip_network(f"{base}.{rnd.randrange(256)}.{rnd.randrange(256)}.{rnd.randrange(256)}/{plen}", strict=False)
        rows.append((str(net), "cidr", "feed", f"c{i}"))
    ts = IndicatorSet(rows)
    nets = [ipaddress.ip_network(r[0]) for r in rows]

    def brute(ip):
        a = ipaddress.ip_address(ip)
        best = None
        for n, r in zip(nets, rows):
            if a in n and (best is None or n.prefixlen >= best[0].prefixlen):
                best = (n, r)
        return best
    for _ in range(1500):
        ip = f"{rnd.choice([10, 45, 100, 185, 203, 8])}.{rnd.randrange(256)}.{rnd.randrange(256)}.{rnd.randrange(256)}"
        got, want = ts.match_ip(ip), brute(ip)
        if want is None:
            assert got is None, ip
        else:  # same most-specific network (ties between identical blocks may name either feed)
            assert got is not None and ipaddress.ip_network(got.indicator).prefixlen == want[0].prefixlen, ip
            assert ipaddress.ip_address(ip) in ipaddress.ip_network(got.indicator)
    assert ts.match_ip("11.0.0.1") is None and ts.match_ip("") is None and ts.match_ip("::1") is None


# ------------------------------------------------------------------ observability: request ids, access log, metrics
async def test_request_id_access_log_and_metrics(api, caplog):  # noqa: F811
    import logging
    from .test_api import login
    r = await api.get("/api/health")
    rid = r.headers["x-request-id"]
    assert len(rid) == 32
    assert (await api.get("/api/health", headers={"X-Request-ID": "trace-abc-123456"})).headers["x-request-id"] == "trace-abc-123456"
    forged = "x\nFAKE LOG LINE"  # unsafe ids are replaced, so a caller cannot inject log content
    assert (await api.get("/api/health", headers={"X-Request-ID": forged})).headers["x-request-id"] != forged
    with caplog.at_level(logging.INFO, logger="api.access"):
        h = await login(api, "analyst1")
        await api.get("/api/switches/987654")
    lines = [rec for rec in caplog.records if rec.name == "api.access"]
    assert any(rec.getMessage().startswith("GET /api/switches/{sid} 404") for rec in lines)  # template, not the raw id
    assert all(getattr(rec, "request_id", "") for rec in lines)
    assert (await api.get("/api/metrics")).status_code == 403                                # analysts: no
    await login(api, "admin1")
    m = (await api.get("/api/metrics")).text
    assert 'api_requests_total{method="GET",route="/api/switches/{sid}",status="4xx"}' in m
    assert "987654" not in m and 'api_request_duration_seconds_bucket{method="GET",route="/api/health",le="+Inf"}' in m
    assert h  # login helper returned csrf headers


# ------------------------------------------------------------------ TACACS health: one aggregate, not one query per server
async def test_tacacs_health_availability_aggregate(api, db):  # noqa: F811
    from datetime import datetime, timedelta, timezone
    from app.db.models import TacHealthCheck, TacServer
    from .test_api import login
    now = datetime.now(timezone.utc)
    a = TacServer(name="tac-a", kind="external", management_address="10.1.1.1")
    b = TacServer(name="tac-b", kind="external", management_address="10.1.1.2")
    c = TacServer(name="tac-c", kind="external", management_address="10.1.1.3")
    db.add_all([a, b, c])
    await db.flush()
    for i, st in enumerate(["up", "up", "up", "down"]):
        db.add(TacHealthCheck(server_id=a.id, status=st, at=now - timedelta(minutes=i)))
    db.add(TacHealthCheck(server_id=b.id, status="down", at=now))
    db.add(TacHealthCheck(server_id=b.id, status="up", at=now - timedelta(days=2)))   # outside 24 h
    db.add(TacHealthCheck(server_id=c.id, status="up", at=now - timedelta(days=2)))
    await db.commit()
    await login(api, "analyst1")
    r = (await api.get("/api/tacacs/health")).json()
    got = {x["name"]: x["availability_24h"] for x in r["servers"]}
    assert got == {"tac-a": 75.0, "tac-b": 0.0, "tac-c": None}


# ------------------------------------------------------------------ SNMP trap dedup map is bounded
def test_trap_dedup_map_stays_bounded_under_unique_key_storm():
    from app import snmp_traps as T
    d = T.Dedup()
    for i in range(T.DEDUP_MAX_KEYS * 3):            # all unique, all inside one dedup window
        assert d.hit(("10.0.0.1", f"oid{i}"), 1000.0) is False
    assert len(d.seen) <= T.DEDUP_MAX_KEYS
    assert d.hit(("10.0.0.1", f"oid{T.DEDUP_MAX_KEYS * 3 - 1}"), 1001.0) is True   # recent keys still deduplicate


# ------------------------------------------------------------------ switch polls use their real start time
async def test_queued_switch_poll_uses_its_own_start_time(db, monkeypatch):
    import asyncio
    from datetime import datetime, timezone
    from app.db import pg as _pg
    from app.switches import poller as P
    from .test_switches import _seed
    sw, cred = await _seed(db)
    seen = []

    async def fake_poll(s, ch, sw_, cred_, *, client=None, now=None, **kw):
        seen.append(now)
        await asyncio.sleep(0.3)
        return {"ok": True}
    monkeypatch.setattr(P, "poll_switch", fake_poll)
    monkeypatch.setenv("SWITCH_MAX_CONCURRENT_POLLS", "1")
    get_settings.cache_clear()
    try:
        other = type(sw)(name="SW2", address="192.0.2.12", credential_id=cred.id, site="WH1", capabilities={}, group_state={}, health={}, thresholds={})
        db.add(other)
        await db.commit()
        t0 = datetime.now(timezone.utc)
        await P.run_due(None, _pg.session_factory())   # worker mode: no explicit `now`
    finally:
        monkeypatch.delenv("SWITCH_MAX_CONCURRENT_POLLS")
        get_settings.cache_clear()
    assert len(seen) == 2 and all(t >= t0 for t in seen)
    assert abs((seen[1] - seen[0]).total_seconds()) >= 0.25   # the queued switch was stamped when it started
