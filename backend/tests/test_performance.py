"""Regression and load tests for the 2026-11-10 performance remediation (docs/performance/).

Each test names the root cause it guards (INITIAL_AUDIT.md RC-n). The load tests use the real scheduler and
database with simulated SNMP polls, so they measure scheduling behaviour, not network or device speed."""
import asyncio
import logging
import time
from datetime import datetime, timedelta, timezone

import pytest

from app.config import get_settings


# ------------------------------------------------------------------ RC-1: SNMP polling in its own process
def test_worker_roles_keep_snmp_polling_out_of_the_core_process():
    from app.worker import loop_plan, worker_roles
    core, snmp, both = worker_roles("core"), worker_roles("snmp"), worker_roles(None)
    assert both == {"core", "snmp"} and worker_roles("all") == both              # default: today's single process
    assert "switch_polling" not in loop_plan(core, 0) and "alert_evaluation" in loop_plan(core, 0)
    assert loop_plan(snmp, 0) == ["loop_monitor", "switch_polling"]               # nothing else competes for its core
    assert loop_plan(snmp, 3) == ["loop_monitor", "switch_polling"]               # pollers share devices via the lease
    assert "switch_polling" in loop_plan(both, 0) and "switch_polling" not in loop_plan(both, 1)
    assert "alert_evaluation" not in loop_plan(core, 1)                           # alerting stays on shard 0
    with pytest.raises(SystemExit):
        worker_roles("snmp,typo")


async def test_loop_monitor_reports_a_starved_event_loop(caplog):
    from app.worker import loop_monitor
    stop = asyncio.Event()
    caplog.set_level(logging.INFO, logger="worker")
    task = asyncio.create_task(loop_monitor(stop, interval=0.02, report_every=5, warn_lag=0.1))
    await asyncio.sleep(0.05)
    time.sleep(0.3)                     # CPU-bound work blocking the loop, as SNMP decoding did
    await asyncio.sleep(0.2)
    stop.set()
    await task
    lag = [r for r in caplog.records if "event loop lag" in r.getMessage()]
    assert lag and any(r.levelno == logging.WARNING for r in lag)


@pytest.mark.parametrize("devices", [100, 500, 1000])
async def test_scheduler_bounds_concurrency_and_isolates_slow_devices(db, monkeypatch, devices):
    """One unreachable and one very slow device among N: concurrency stays at the configured bound, every other
    device is polled, the slow one is cut off at its budget, and nothing waits for it."""
    from app.db import pg as _pg
    from app.switches import poller as P
    from .test_switches import _seed
    sw, cred = await _seed(db)
    db.add_all([type(sw)(name=f"SW{i}", address=f"10.{i // 250}.{i % 250}.10", credential_id=cred.id, site="WH1", capabilities={},
                         group_state={}, health={}, thresholds={}) for i in range(devices - 1)])
    await db.commit()
    slow, dead = "SW1", "SW2"
    active = peak = 0
    finished: dict[str, float] = {}

    async def fake_poll(s, ch, sw_, cred_, *, client=None, now=None, **kw):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        try:
            if sw_.name == slow:
                await asyncio.sleep(30)                       # far beyond the poll budget
            if sw_.name == dead:
                raise ConnectionError("no SNMP response")    # unreachable
            await asyncio.sleep(0.005)
            finished[sw_.name] = time.monotonic()
            return {"ok": True}
        finally:
            active -= 1
    monkeypatch.setattr(P, "poll_switch", fake_poll)
    monkeypatch.setenv("SWITCH_MAX_CONCURRENT_POLLS", "16")
    monkeypatch.setenv("SWITCH_POLL_TIMEOUT_SECONDS", "1")
    get_settings.cache_clear()
    try:
        t0 = time.monotonic()
        res = await asyncio.wait_for(P.run_due(None, _pg.session_factory(), wait=True), 120)
        took = time.monotonic() - t0
    finally:
        get_settings.cache_clear()
    assert res["polled"] == devices and res["failed"] == 2                      # the slow one timed out, the dead one failed
    assert peak <= 16                                                           # bounded, never one task per device at once
    assert len(finished) == devices - 2
    # the healthy devices did not wait for the slow one: all of them were done well before its budget ran out
    assert max(finished.values()) - t0 < 1.0 + devices * 0.005 / 16 + 5
    assert took < 1.0 + devices * 0.005 / 16 + 10
    from sqlalchemy import select
    async with _pg.session_factory()() as s:
        rows = {x.name: x for x in (await s.execute(select(type(sw)))).scalars()}
    assert rows[slow].last_error_kind == "timeout" and "exceeded 1s" in rows[slow].last_error
    assert all(r.lease_until is None for r in rows.values())                    # no device left claimed


# ------------------------------------------------------------------ RC-2: first-seen baselines from hourly rollups
def _flow(t, src, dst, dport, country, action="accept", sid=0):
    from app.ingest.normalize import normalize
    from .test_storage_analytics import FW
    return normalize({"type": "traffic", "subtype": "forward", "devid": FW["serial"], "eventtime": str(int(t.timestamp() * 1e9) + sid),
                      "logid": "0000000013", "srcip": src, "srcport": str(40000 + sid % 1000), "dstip": dst, "dstport": str(dport), "proto": "6",
                      "action": action, "sessionid": str(sid), "dstcountry": country, "sentbyte": "10", "rcvdbyte": "20"},
                     source="syslog", firewall=FW)


async def test_first_seen_rules_give_the_same_result_from_the_rollup(clean_ch, monkeypatch):
    from app.alerts import siem as E
    from app.db.ch_schema import EVENT_COLUMNS
    now = datetime.now(timezone.utc).replace(microsecond=0)
    evs, sid = [], 0
    for h in range(1, 24 * 4, 5):                                           # four days of history, hourly-ish, odd minutes
        t = now - timedelta(hours=h, minutes=h % 50)
        for src, dport, country in (("10.0.0.5", 8443, "Germany"), ("10.0.0.6", 22, "France"), ("10.0.0.5", 3389, "Japan")):
            sid += 1
            evs.append(_flow(t, src, "198.51.100.9", dport, country, sid=sid))
    for i in range(8):                                                      # the current window: a new country and new ports
        sid += 1
        evs.append(_flow(now - timedelta(minutes=3, seconds=i), "10.0.0.5", "198.51.100.9", 9999, "Brazil", sid=sid))
        sid += 1
        evs.append(_flow(now - timedelta(minutes=4, seconds=i), "10.0.0.6", "198.51.100.9", 2222, "France", sid=sid))
        sid += 1
        evs.append(_flow(now - timedelta(minutes=5, seconds=i), "10.0.0.5", "198.51.100.9", 8443, "Germany", sid=sid))
    clean_ch.insert("events", evs, EVENT_COLUMNS)
    clean_ch.insert("events_minute", [{"minute": now - timedelta(days=5), "category": "traffic", "firewall_id": 1, "source": "syslog", "events": 1}],
                    ["minute", "category", "firewall_id", "source", "events"])
    assert clean_ch.query("SELECT count() AS n FROM traffic_port_hourly")[0]["n"] > 0
    pc = {"window_minutes": 15, "baseline_days": 3, "learning_days": 1, "max_per_run": 10}
    pp = {"window_minutes": 15, "baseline_days": 3, "learning_days": 1, "min_events": 5, "ignore_ports": [80, 443], "max_per_run": 25}

    async def both(fn, p):
        out = {}
        for flag in ("true", "false"):
            monkeypatch.setenv("ALERT_BASELINE_FROM_ROLLUP", flag)
            get_settings.cache_clear()
            out[flag] = sorted((d.group_key, d.count) for d in await fn(clean_ch, now, p))
        get_settings.cache_clear()
        return out
    c = await both(E.rule_new_country, pc)
    assert c["true"] == c["false"] and [k for k, _ in c["true"]] == ["Brazil"]
    p = await both(E.rule_new_port, pp)
    assert p["true"] == p["false"] and {k for k, _ in p["true"]} == {"10.0.0.5|9999", "10.0.0.6|2222"}


async def test_learning_check_reads_the_minute_rollup(clean_ch):
    from app.alerts.siem import _learning_ok
    now = datetime.now(timezone.utc)
    assert not await _learning_ok(clean_ch, 3, now)
    clean_ch.insert("events_minute", [{"minute": now - timedelta(days=4), "category": "traffic", "firewall_id": 1, "source": "syslog", "events": 5}],
                    ["minute", "category", "firewall_id", "source", "events"])
    assert await _learning_ok(clean_ch, 3, now) and not await _learning_ok(clean_ch, 5, now)


# ------------------------------------------------------------------ RC-3: identity baseline built per day
async def test_identity_baseline_per_day_equals_the_full_baseline_and_caches_days(monkeypatch):
    from app import identity as I
    I._DAY_BASELINES.clear()
    now = datetime(2026, 11, 10, 9, 30, tzinfo=timezone.utc)
    events = []
    for d in range(9):
        for k, (u, c, ip, dev, res) in enumerate((("alice", "India", "203.0.113.5", "LAP-1", "success"), ("bob", "India", "198.51.100.7", "", "success"),
                                                   ("alice", "Germany", "192.0.2.9", "LAP-2", "failure"))):
            t = now - timedelta(days=d, hours=k * 5 + 1)
            events.append({"t": t, "key": u, "user": u, "result": res, "country": c, "src_ip": ip, "device": dev, "local_hour": t.hour})
    calls: list[tuple] = []

    async def fake_auth_events(ch, t0, t1, fw_ids=None, user=None, limit=200_000):
        calls.append((t0, t1))
        return [e for e in events if t0 <= e["t"] < t1]
    monkeypatch.setattr(I, "auth_events", fake_auth_events)
    b0, b1 = now - timedelta(days=7, hours=3), now - timedelta(minutes=15)
    full = I.baseline([e for e in events if b0 <= e["t"] < b1])
    ch = object()                       # one ClickHouse handle: the per-day cache is keyed by it
    got = await I.cached_baseline(ch, b0, b1, now=now)
    assert got == full
    first = len(calls)
    again = await I.cached_baseline(ch, b0, b1, now=now)
    assert again == full and len(calls) == first + 2   # only the two partial edge days are queried again
    I._DAY_BASELINES.clear()


# ------------------------------------------------------------------ RC-4: syslog memory stays bounded
async def test_syslog_buffer_cap_backpressure_and_memory_release(monkeypatch, tmp_path):
    from app.ingest import pipeline as PL
    from .test_modernization import _FlakyCH, _add
    monkeypatch.delenv("SYSLOG_BUFFER_MAX_EVENTS", raising=False)
    monkeypatch.setenv("INGEST_DEADLETTER_DIR", str(tmp_path / "dl"))
    get_settings.cache_clear()
    released = []
    monkeypatch.setattr(PL, "release_memory", lambda: released.append(1))
    ch = _FlakyCH()
    sink = PL.EventSink(ch, PL.DeviceRegistry(), batch_size=10)
    sink.stats_hook = lambda st: None
    assert sink.buffer_max == 30 and sink._cap == get_settings().syslog_dedupe_window   # 3 x batch (was 10 x)
    ch.down = True
    _add(sink, 25)
    assert await sink.flush() == 0 and not sink.saturated
    _add(sink, 10, start=25)
    assert sink.saturated and sink.pending == 30          # the parser stops reading; TCP / the relay hold the rest
    ch.down = False
    assert await sink.flush() == 30 and sink.pending == 0
    assert released == [1] and sink.counters["rss_mib"] >= 0  # the drained backlog's memory was handed back
    assert [r["session_id"] for r in ch.rows] == list(range(30))
    get_settings.cache_clear()


async def test_syslog_burst_with_malformed_lines_keeps_memory_bounded(monkeypatch, tmp_path):
    """200k lines, a third malformed, through the parser sink: the buffer never exceeds its cap and nothing is
    silently lost (every line is inserted, a duplicate or a counted parse error)."""
    from app.ingest import pipeline as PL
    from .test_modernization import _FlakyCH
    from .test_storage_analytics import FW
    monkeypatch.setenv("INGEST_DEADLETTER_DIR", str(tmp_path / "dl"))
    get_settings.cache_clear()
    ch = _FlakyCH()
    sink = PL.EventSink(ch, PL.DeviceRegistry(), batch_size=2000)
    sink.stats_hook = lambda st: None
    sink.allow_unknown = True
    peak = 0
    n = 60_000
    for i in range(n):
        if i % 3 == 0:
            sink.add_line("<14>garbage \x00\x01 not a fortigate line " + "x" * (i % 50), peer_ip="10.1.0.1")
        else:
            sink.add_line(f'date=2026-11-10 time=10:00:{i % 60:02d} devid="{FW["serial"]}" type="traffic" subtype="forward" logid="0000000013" '
                          f'srcip=10.0.{i % 200}.{i % 250} dstip=203.0.113.{i % 250} dstport={i % 6000} proto=6 action="close" sessionid={i} '
                          f'eventtime={1793700000000000000 + i}', peer_ip="10.1.0.1")
        peak = max(peak, sink.pending)
        if sink.should_flush():
            await sink.flush()
    await sink.flush()
    c = sink.counters
    assert peak <= sink.buffer_max and sink.pending == 0
    accounted = sum(c[k] for k in ("inserted", "duplicates", "parse_errors", "unknown_device", "source_mismatch", "dropped_buffer_full", "dead_lettered"))
    assert c["received"] == n and accounted == n and c["dropped_buffer_full"] == 0
    assert c["parse_errors"] == n // 3 and c["inserted"] == n - n // 3 and len(ch.rows) == c["inserted"]
    get_settings.cache_clear()


# ------------------------------------------------------------------ RC-5: per-query ClickHouse limits
def test_every_server_query_carries_time_and_memory_limits(monkeypatch):
    from app.db.ch import query_limits
    get_settings.cache_clear()
    lim = query_limits(get_settings())
    assert lim["max_execution_time"] == 60 and lim["max_memory_usage"] == 2 * 1024 ** 3
    assert lim["max_bytes_before_external_group_by"] == lim["max_bytes_before_external_sort"] == 1024 ** 3   # spill, don't fail
    monkeypatch.setenv("CLICKHOUSE_QUERY_MAX_MEMORY", "0")
    get_settings.cache_clear()
    assert query_limits(get_settings()) == {"max_execution_time": 60}
    get_settings.cache_clear()


# ------------------------------------------------------------------ RC-7: staleness uses the configured interval
def test_staleness_uses_the_configured_interval_and_the_poll_budget():
    from app.db.models import Switch
    from app.switches.alerts import _fresh, poll_interval, stale_after
    get_settings.cache_clear()
    st = get_settings()
    wlc = Switch(name="WLC-ZOMATO-1", poll_interval_seconds=30, role="wlc")
    sw = Switch(name="SW", poll_interval_seconds=30, role="access")
    assert poll_interval(wlc) == 30 and poll_interval(Switch(poll_interval_seconds=10)) == 30   # was max(60, …): reported 60
    assert stale_after(wlc) == 3 * 30 + st.switch_wlc_poll_timeout_seconds + 60
    assert stale_after(sw) == 3 * 30 + st.switch_poll_timeout_seconds + 60
    assert stale_after(sw, {"stale_intervals": 5, "grace_seconds": 0}) == 5 * 30 + st.switch_poll_timeout_seconds
    now = datetime.now(timezone.utc)
    wlc.last_success_at = now - timedelta(seconds=st.switch_wlc_poll_timeout_seconds)   # one long but healthy poll ago
    assert _fresh(wlc, now)
    wlc.last_success_at = now - timedelta(seconds=stale_after(wlc) + 1)
    assert not _fresh(wlc, now)


# ------------------------------------------------------------------ worker after the split: incident recompute
def _alert(i, inc_id, rule, sev, *, crit="", mitre=None, t=None, src="10.9.9.9"):
    from app.db.models import Alert
    t = t or datetime(2026, 11, 1, tzinfo=timezone.utc) + timedelta(minutes=i)
    return Alert(rule_key=rule, name=f"{rule} #{i}", severity=sev, status="new", group_key=f"{rule}|{i}", src_ip=src, firewall_ids=[1], sites=["Lab"],
                 first_seen=t, last_seen=t + timedelta(minutes=1), event_count=1, evidence={"x": "y" * 50}, event_filter={}, incident_id=inc_id,
                 asset_criticality=crit, mitre=mitre)


async def test_incident_recompute_from_db_equals_the_full_recompute(db):
    from sqlalchemy import select
    from app.db.models import Alert, Incident
    from app.incidents import compute, compute_from_db
    inc = Incident(title="t", entity_type="ip", entity="10.9.9.9", status="open", created_at=datetime(2026, 11, 1, tzinfo=timezone.utc),
                   evidence=[], tasks=[], linked=[])
    db.add(inc)
    await db.flush()
    rules = [("port_scan", "medium", None), ("beaconing", "high", {"tactic": "TA0011", "techniques": ["T1071"]}), ("dns_tunnel", "low", None)]
    db.add_all([_alert(i, inc.id, *rules[i % 3][:2], crit=("high" if i == 7 else ""), mitre=rules[i % 3][2]) for i in range(300)])
    await db.commit()
    members = (await db.execute(select(Alert).where(Alert.incident_id == inc.id).order_by(Alert.id))).scalars().all()
    ref = Incident(title="t", entity_type="ip", entity="10.9.9.9", status="open", created_at=inc.created_at, evidence=[], tasks=[], linked=[])
    compute(ref, members)
    await compute_from_db(db, inc)
    for f in ("severity", "tactics", "techniques", "rule_keys", "alert_count", "score", "asset_criticality", "title", "sla_ack_due"):
        assert getattr(inc, f) == getattr(ref, f), f
    assert inc.first_seen == ref.first_seen and inc.last_seen == ref.last_seen


async def test_correlation_does_not_reload_a_large_incident_per_alert(db):
    """Regression (production profile after the split): an incident with 22,470 alerts was loaded in full for every
    touched alert. Now each touched incident costs one grouped query per pass, whatever its size."""
    from sqlalchemy import event, select
    from app.db.models import Alert, Incident
    from app.incidents import correlate_alerts
    now = datetime.now(timezone.utc)
    inc = Incident(title="big", entity_type="ip", entity="10.9.9.9", status="open", created_at=now - timedelta(days=30), last_seen=now,
                   evidence=[], tasks=[], linked=[], category="security")
    db.add(inc)
    await db.flush()
    db.add_all([_alert(i, inc.id, "port_scan", "medium", t=now - timedelta(days=20, minutes=-i)) for i in range(3000)])
    await db.commit()
    touched = [_alert(10_000 + i, inc.id, "port_scan", "medium", t=now - timedelta(minutes=5)) for i in range(60)]
    db.add_all(touched)
    await db.commit()
    stmts = []
    sync_engine = db.bind.sync_engine if hasattr(db.bind, "sync_engine") else db.get_bind().sync_engine

    def count(conn, cursor, statement, *a):
        stmts.append(statement)
    event.listen(sync_engine, "before_cursor_execute", count)
    try:
        t0 = time.perf_counter()
        res = await correlate_alerts(db, touched, now)
        took = time.perf_counter() - t0
    finally:
        event.remove(sync_engine, "before_cursor_execute", count)
    full_member_loads = [x for x in stmts if "FROM alerts" in x and "WHERE alerts.incident_id" in x and "count(" not in x and "LIMIT" not in x]
    assert not full_member_loads                    # no per-alert load of every member row
    assert len(stmts) < 60 + 20                     # one lookup per touched alert at most, plus a constant
    assert [k for _, k in res] == ["updated"] and inc.alert_count == 3060 and took < 5
    assert (await db.execute(select(Alert).where(Alert.incident_id == inc.id))).scalars().first() is not None


async def test_a_poller_claims_only_its_free_slots_so_replicas_share_devices(db, monkeypatch):
    """Regression: claim() leased every due switch to whichever poller woke first, so extra replicas stayed idle."""
    from app.db import pg as _pg
    from app.switches import poller as P
    from .test_switches import _seed
    sw, cred = await _seed(db)
    db.add_all([type(sw)(name=f"R{i}", address=f"10.50.0.{i + 10}", credential_id=cred.id, site="WH1", capabilities={}, group_state={}, health={},
                         thresholds={}) for i in range(9)])
    await db.commit()
    now = datetime.now(timezone.utc)
    async with _pg.session_factory()() as s:
        a = await P.claim(s, now, 300, limit=4)
    async with _pg.session_factory()() as s:
        b = await P.claim(s, now, 300, limit=4)          # a second replica gets different devices
    async with _pg.session_factory()() as s:
        c = await P.claim(s, now, 300, limit=4)
    assert len(a) == 4 and len(b) == 4 and len(c) == 2 and not set(a) & set(b) and not (set(a) | set(b)) & set(c)


async def test_worker_mode_is_a_refilling_pool_and_a_slow_device_holds_one_slot(db, monkeypatch):
    from app.db import pg as _pg
    from app.switches import poller as P
    from .test_switches import _seed
    sw, cred = await _seed(db)
    db.add_all([type(sw)(name=f"Q{i}", address=f"10.60.0.{i + 10}", credential_id=cred.id, site="WH1", capabilities={}, group_state={}, health={},
                         thresholds={}) for i in range(11)])
    await db.commit()
    gate, started = asyncio.Event(), []

    async def fake_poll(s, ch, sw_, cred_, *, client=None, now=None, **kw):
        started.append(sw_.name)
        if sw_.name == "WH1-ACC-SW01":
            await gate.wait()                     # the slow device
        else:
            await asyncio.sleep(0.01)
        sw_.last_poll_at = now                    # as poll_switch does: not due again until its interval passes
        return {"ok": True}
    monkeypatch.setattr(P, "poll_switch", fake_poll)
    monkeypatch.setenv("SWITCH_MAX_CONCURRENT_POLLS", "4")
    get_settings.cache_clear()
    try:
        r = await P.run_due(None, _pg.session_factory())            # worker mode: returns at once
        assert r["started"] == 4
        for _ in range(20):                                           # the loop's ticks
            await asyncio.sleep(0.05)
            await P.run_due(None, _pg.session_factory())
        assert len(set(started)) == 12 and len(started) == 12         # the other 11 went through 3 free slots, once each
        assert len(P._inflight) == 1                                  # only the slow device still holds a slot
    finally:
        gate.set()
        await asyncio.gather(*list(P._background), return_exceptions=True)
        get_settings.cache_clear()
    assert not P._inflight


async def test_controller_poll_walks_its_large_wireless_tables_concurrently(monkeypatch):
    """Regression (WLC-ZOMATO-1 stale after the split): a controller poll took the sum of its wireless walks (about
    260 s), so even its quick metrics refreshed every ~5 minutes. The large tables now overlap; the rest keep order."""
    from app.switches import poller as P
    order: list[str] = []

    def fake(name, secs):
        async def f(ctx):
            order.append(name)
            await asyncio.sleep(secs)
            return {}
        return f
    heavy = {g: fake(g, 0.4) for g in P.PARALLEL_GROUPS}
    light = {g: fake(g, 0.01) for g in ("wireless_ap", "wireless_radio", "wireless_wlan")}
    monkeypatch.setattr(P, "W_COLLECTORS", {**heavy, **light})
    monkeypatch.setattr(P.C, "collectors", lambda vendor: {})
    ctx = type("Ctx", (), {"vendor": "cisco", "prev": {}, "outcome": None})()
    get_settings.cache_clear()
    t0 = time.monotonic()
    data, report, ran = await P.run_groups(ctx, list(heavy) + list(light), wireless_group_timeout=30)
    took = time.monotonic() - t0
    assert ran == set(heavy) | set(light) and all(r["ok"] for r in report.values())
    assert took < 0.4 * 2                                   # concurrent: about one walk, not four (1.6 s)
    assert order.index("wireless_radio") < min(order.index(g) for g in heavy)   # dependencies still first
    monkeypatch.setenv("SWITCH_WIRELESS_GROUP_CONCURRENCY", "1")
    get_settings.cache_clear()
    t0 = time.monotonic()
    await P.run_groups(ctx, list(heavy) + list(light), wireless_group_timeout=30)
    assert time.monotonic() - t0 >= 0.4 * 4                 # 1 = the previous sequential behaviour
    get_settings.cache_clear()


async def test_shutdown_hands_in_flight_devices_back_at_once(db, monkeypatch):
    """Regression (WLC-ZOMATO-1 stale ~16 min after each deploy): a poller stopped mid-poll left the device leased for
    its whole budget, so no replica could poll it."""
    from sqlalchemy import select
    from app.db import pg as _pg
    from app.switches import poller as P
    from .test_switches import _seed
    sw, cred = await _seed(db)
    gate = asyncio.Event()

    async def hung_poll(s, ch, sw_, cred_, *, client=None, now=None, **kw):
        await gate.wait()
    monkeypatch.setattr(P, "poll_switch", hung_poll)
    r = await P.run_due(None, _pg.session_factory())
    assert r["started"] == 1
    await asyncio.sleep(0.05)
    async with _pg.session_factory()() as s:
        assert (await s.execute(select(type(sw).lease_until).where(type(sw).id == sw.id))).scalar() is not None
    released = await P.release_on_shutdown(_pg.session_factory(), grace=2)
    assert released == [sw.id] and not P._inflight and not P._background
    async with _pg.session_factory()() as s:
        assert (await s.execute(select(type(sw).lease_until).where(type(sw).id == sw.id))).scalar() is None
        assert await P.claim(s, datetime.now(timezone.utc), 300) == [sw.id]   # another replica can take it now
