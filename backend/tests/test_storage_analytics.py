"""Pipeline, dedupe, persistence, aggregation accuracy and retention against embedded ClickHouse."""
from datetime import datetime, timedelta, timezone

from app.analytics import queries as Q
from app.analytics.filters import EventFilter
from app.ingest.normalize import normalize
from app.ingest.pipeline import DeviceRegistry, EventSink
from app.retention import ensure_default_policies, run_retention
from app.db.models import RetentionRun

from .conftest import fixture_lines

FW = {"id": 1, "name": "FGT-TEST-01", "site": "Lab", "serial": "FGTEST0000000001", "host": "10.1.0.1"}


def registry():
    r = DeviceRegistry()
    r.load([FW])
    return r


def traffic(i, *, src="10.0.0.1", dst="203.0.113.1", dport=443, action="close", sent=100, rcvd=200, ts=None, session=None):
    ts = ts or datetime.now(timezone.utc) - timedelta(minutes=1)
    return {"type": "traffic", "subtype": "forward", "devid": FW["serial"], "eventtime": str(int(ts.timestamp() * 1e9) + i),
            "logid": "0000000013", "srcip": src, "srcport": str(30000 + i), "dstip": dst, "dstport": str(dport), "proto": "6",
            "action": action, "sessionid": str(session if session is not None else i), "sentbyte": str(sent), "rcvdbyte": str(rcvd)}


async def test_pipeline_dedupe_and_persist(clean_ch, db):
    sink = EventSink(clean_ch, registry())
    for line in fixture_lines() + fixture_lines():  # every line twice
        sink.add_line(line, source="syslog", peer_ip="10.1.0.1")
    assert sink.counters["duplicates"] == 5
    assert await sink.flush() == 5
    rows = clean_ch.query("SELECT category, count() AS n FROM events GROUP BY category ORDER BY category")
    assert {r["category"]: r["n"] for r in rows} == {"dns": 1, "system": 1, "traffic": 2, "web": 1}
    # re-ingesting after a restart (empty in-memory cache) is still collapsed by ReplacingMergeTree FINAL
    sink2 = EventSink(clean_ch, registry())
    for line in fixture_lines():
        sink2.add_line(line, source="syslog")
    await sink2.flush()
    assert clean_ch.query("SELECT count() AS n FROM events FINAL")[0]["n"] == 5


async def test_unknown_device_dropped(clean_ch, db):
    sink = EventSink(clean_ch, DeviceRegistry())
    assert sink.add_line(fixture_lines()[0], source="syslog", peer_ip="192.0.2.99") is None
    assert sink.counters["unknown_device"] == 1


async def _load(ch, records):
    evs = [normalize(r, source="syslog", firewall=FW) for r in records]
    from app.db.ch_schema import EVENT_COLUMNS
    ch.insert("events", evs, EVENT_COLUMNS)


async def test_aggregation_accuracy(clean_ch):
    recs = []
    recs += [traffic(i, src="10.0.0.1", dst="203.0.113.1", dport=443, sent=100, rcvd=200) for i in range(10)]
    recs += [traffic(100 + i, src="10.0.0.2", dst="203.0.113.2", dport=22, action="deny", sent=0, rcvd=0) for i in range(4)]
    recs += [traffic(200 + i, src="10.0.0.1", dst="203.0.113.3", dport=80, sent=50, rcvd=50) for i in range(3)]
    await _load(clean_ch, recs)
    f = EventFilter(range="1h")
    k = await Q.kpis(clean_ch, f)
    assert k["traffic_events"] == 17 and k["sessions"] == 17
    assert k["unique_src"] == 2 and k["unique_dst"] == 3
    assert k["bytes_total"] == 10 * 300 + 3 * 100
    assert k["allowed_events"] == 13 and k["denied_events"] == 4

    srcs = await Q.top_sources(clean_ch, f, "count", 10)
    assert srcs[0]["src_ip"] == "10.0.0.1" and srcs[0]["events"] == 13 and srcs[0]["uniq_peer"] == 2
    assert srcs[0]["bytes_sent"] == 1150
    by_denied = await Q.top_sources(clean_ch, f, "denied", 10)
    assert by_denied[0]["src_ip"] == "10.0.0.2" and by_denied[0]["denied"] == 4

    ports = {(p["dst_port"], p["proto_name"]): p for p in await Q.top_ports(clean_ch, f, "count", 10)}
    assert ports[(443, "TCP")]["events"] == 10 and ports[(22, "TCP")]["denied"] == 4
    assert ports[(443, "TCP")]["service"] is None  # not logged -> not inferred from port

    dsts = await Q.top_destinations(clean_ch, f, "bytes", 10)
    assert dsts[0]["dst_ip"] == "203.0.113.1" and dsts[0]["bytes_total"] == 3000

    f2 = EventFilter(range="1h", src_ip="10.0.0.0/31", dst_port=80)
    page = await Q.list_events(clean_ch, f2, 1, 2)
    assert page["total"] == 3 and len(page["items"]) == 2

    inv = await Q.investigate_ip(clean_ch, EventFilter(range="1h"), "10.0.0.2")
    assert inv["summary"]["denied"] == 4 and inv["top_ports"][0]["key"] == 22


async def test_time_window_excludes_old(clean_ch):
    old = datetime.now(timezone.utc) - timedelta(hours=3)
    await _load(clean_ch, [traffic(1, ts=old), traffic(2)])
    assert (await Q.kpis(clean_ch, EventFilter(range="1h")))["traffic_events"] == 1
    assert (await Q.kpis(clean_ch, EventFilter(range="24h")))["traffic_events"] == 2


async def test_dns_and_web_summaries(clean_ch):
    from app.ingest.parser import parse_kv
    lines = fixture_lines()
    recs = [parse_kv(lines[2]), parse_kv(lines[3])]
    for r in recs:
        r["eventtime"] = str(int((datetime.now(timezone.utc) - timedelta(minutes=2)).timestamp() * 1e9))
    await _load(clean_ch, recs)
    d = await Q.dns_summary(clean_ch, EventFilter(range="1h"))
    assert d["totals"]["queries"] == 1 and d["top_domains"][0]["key"] == "www.example.com"
    w = await Q.web_summary(clean_ch, EventFilter(range="1h"))
    assert w["totals"]["blocked"] == 1 and w["totals"]["path_only"] == 1 and w["totals"]["full_urls"] == 0


async def test_retention_drops_and_logs(clean_ch, db):
    await ensure_default_policies(db)
    await _load(clean_ch, [traffic(1, ts=datetime.now(timezone.utc) - timedelta(days=40)), traffic(2)])
    res = await run_retention(clean_ch, db)
    t = next(r for r in res if r["category"] == "traffic")
    assert t["rows"] == 1 and len(t["dropped"]) == 1
    assert clean_ch.query("SELECT count() AS n FROM events")[0]["n"] == 1
    assert clean_ch.query("SELECT sum(events) AS n FROM events_1m")[0]["n"] == 1  # rollup expired too
    from sqlalchemy import select
    runs = (await db.execute(select(RetentionRun))).scalars().all()
    assert len(runs) == 1 and runs[0].status == "ok"


async def test_cidr_filter_with_events_lacking_ips(clean_ch):
    sys_ev = {"type": "event", "subtype": "system", "devid": FW["serial"], "logid": "0100032001", "msg": "no ip here",
              "eventtime": str(int((datetime.now(timezone.utc) - timedelta(minutes=1)).timestamp() * 1e9))}
    await _load(clean_ch, [traffic(1, src="10.0.0.7"), traffic(2, src="2001:db8::7"), sys_ev])
    page = await Q.list_events(clean_ch, EventFilter(range="1h", src_ip="10.0.0.0/24"), 1, 50)
    assert page["total"] == 1
    page = await Q.list_events(clean_ch, EventFilter(range="1h", ip="2001:db8::/64"), 1, 50)
    assert page["total"] == 1


async def test_outbound_volume_rule(clean_ch, db):
    from app.alerts.engine import ensure_default_rules, run_rules
    from app.db.models import AlertRule
    from sqlalchemy import select
    await ensure_default_rules(db)
    for r in (await db.execute(select(AlertRule))).scalars():
        r.enabled = r.key == "outbound_volume"
        if r.enabled:
            r.params = {**r.params, "min_sent_bytes": 1000}
    await db.commit()
    await _load(clean_ch, [traffic(i, src="10.5.5.5", dst="203.0.113.9", sent=600) for i in range(3)]
                + [traffic(50 + i, src="10.5.5.6", dst="10.9.9.9", sent=5000) for i in range(3)])  # internal->internal ignored
    res = await run_rules(clean_ch, db)
    assert res["outbound_volume"]["created"] == 1


async def test_timeseries_zero_fills_whole_window_and_totals_match(clean_ch):
    """Regression: sparse data used to return only populated buckets, which the UI drew as one full-width bar."""
    now = datetime.now(timezone.utc)
    await _load(clean_ch, [traffic(i, ts=now - timedelta(minutes=5)) for i in range(4)]
                + [traffic(10 + i, ts=now - timedelta(hours=5), action="deny") for i in range(3)])
    f = EventFilter(range="24h")
    ts = await Q.traffic_timeseries(clean_ch, f)
    pts = ts["points"]
    assert ts["bucket_seconds"] == 900 and len(pts) >= 96  # every 15-min bucket of 24 h is present
    times = [p["t"] for p in pts]
    assert times == sorted(times)  # chronological
    assert sum(p["events"] for p in pts) == 7
    assert sum(p["allowed"] for p in pts) == 4 and sum(p["denied"] for p in pts) == 3
    k = await Q.kpis(clean_ch, f)
    assert k["allowed_events"] == 4 and k["denied_events"] == 3  # chart totals agree with KPIs
    assert ts["data_start"] is not None


async def test_web_timeseries_blocked_allowed_match_totals(clean_ch):
    from app.ingest.parser import parse_kv
    now_ns = int((datetime.now(timezone.utc) - timedelta(minutes=3)).timestamp() * 1e9)
    blocked = parse_kv(fixture_lines()[3])
    recs = []
    for i in range(5):
        r = dict(blocked, eventtime=str(now_ns + i), sessionid=str(5000 + i))
        if i >= 2:
            r["action"] = "passthrough"
        recs.append(r)
    await _load(clean_ch, recs)
    w = await Q.web_summary(clean_ch, EventFilter(range="7d"))
    pts = w["timeseries"]["points"]
    assert len(pts) > 1  # a time series across the window, never a single summary bar
    assert sum(p["blocked"] for p in pts) == w["totals"]["blocked"] == 2
    assert sum(p["allowed"] for p in pts) == w["totals"]["allowed"] == 3
    assert sum(c["events"] for c in w["categories"]) == w["totals"]["events"]


async def test_coverage_reports_collected_categories(clean_ch):
    await _load(clean_ch, [traffic(1)])
    cov = await Q.coverage(clean_ch)
    assert set(cov) == {"traffic"} and cov["traffic"]["events"] == 1 and "syslog" in cov["traffic"]["sources"]


async def test_rollup_hybrid_matches_raw_exactly(clean_ch):
    """Rollup (whole minutes) + raw (partial edge minutes) must equal a pure raw count, including events in the
    first and last partial minute of the window."""
    from app.analytics.queries import rollup_eligible
    end = datetime.now(timezone.utc).replace(second=30, microsecond=0)
    start = end - timedelta(hours=2)
    recs = [traffic(1, ts=start + timedelta(seconds=5)),              # first partial minute
            traffic(2, ts=start - timedelta(seconds=5)),              # outside window
            traffic(3, ts=end - timedelta(seconds=10), action="deny"),  # last partial minute
            traffic(4, ts=end + timedelta(seconds=5))]                # outside window
    recs += [traffic(10 + i, ts=start + timedelta(minutes=5 + i), sent=100) for i in range(50)]
    await _load(clean_ch, recs)
    f = EventFilter(start=start, end=end)
    assert rollup_eligible(f)
    k = await Q.kpis(clean_ch, f)
    raw = clean_ch.query("SELECT count() AS n, countIf(action IN ('deny','block')) AS d, sum(sent_bytes+rcvd_bytes) AS b "
                         "FROM events WHERE event_time >= {a:DateTime64(3)} AND event_time < {z:DateTime64(3)}",
                         {"a": start, "z": end})[0]
    assert k["traffic_events"] == raw["n"] == 52 and k["denied_events"] == raw["d"] == 1 and k["bytes_total"] == raw["b"]
    ts = await Q.traffic_timeseries(clean_ch, f)
    assert sum(p["events"] for p in ts["points"]) == 52 and sum(p["denied"] for p in ts["points"]) == 1


async def test_non_rollup_filters_still_exact(clean_ch):
    from app.analytics.queries import rollup_eligible
    await _load(clean_ch, [traffic(i, src="10.7.7.7") for i in range(3)] + [traffic(9, src="10.8.8.8")])
    f = EventFilter(range="1h", src_ip="10.7.7.7")
    assert not rollup_eligible(f)
    assert (await Q.kpis(clean_ch, f))["traffic_events"] == 3


async def test_rollup_backfill_migration():
    from app.db.ch_schema import EVENT_COLUMNS, MIGRATIONS
    from app.db.ch_schema import migrate as run
    # the embedded engine allows one session per process, so reuse the session fixture's database via a new DB name
    from app.db.ch import get_ch
    ch = get_ch()
    ch.command("CREATE DATABASE IF NOT EXISTS mig_test")
    ch.command("USE mig_test")
    try:
        for v, _, stmts in MIGRATIONS:  # schema before the rollup existed
            if v < 4:
                for st in stmts:
                    ch.command(st)
        old_cols = EVENT_COLUMNS[:EVENT_COLUMNS.index("raw") + 1]  # columns that existed before v5
        evs = [normalize(traffic(i), source="syslog", firewall=FW) for i in range(7)]
        ch.insert("events", evs, old_cols)
        ch.command("CREATE TABLE schema_migrations (version UInt32, name String, applied_at DateTime DEFAULT now()) ENGINE = MergeTree ORDER BY version")
        ch.command("INSERT INTO schema_migrations (version, name) VALUES (1,'a'),(2,'b'),(3,'c')")
        assert run(ch) == [4, 5, 6, 7, 8]
        assert ch.query("SELECT sum(events) AS n FROM events_1m")[0]["n"] == 7  # backfilled exactly once
        ch.insert("events", [normalize(traffic(100), source="syslog", firewall=FW)], EVENT_COLUMNS)
        assert ch.query("SELECT sum(events) AS n FROM events_1m")[0]["n"] == 8  # new inserts flow through the view
    finally:
        ch.command("DROP DATABASE IF EXISTS mig_test")
        ch.command("USE siem")
