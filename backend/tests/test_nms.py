"""Sentinel NMS core: standard host / sensor MIB collection (generic devices, vendor fallback), storage persistence,
device dependencies, maintenance windows, service checks (TCP / HTTP / DNS / TLS maths), network analytics
(availability, capacity forecast, 95th percentile, top-N, health score, inventory, alert analytics) and the API.

All SNMP data below is a LABELLED SYNTHETIC FIXTURE (net-snmp style agent; RFC 5737 addresses); no device is contacted.
Service checks run against 127.0.0.1 listeners and httpx mock transports only."""
import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from sqlalchemy import select

from app.db.models import Alert, AlertRule, NmsMaintenance, NmsService, Switch, SwitchInterface
from app.nms import analytics as A
from app.nms import maintenance as MW
from app.nms import services as SV
from app.switches import collect as C
from app.switches import poller as P
from app.switches.registry import Outcome

from .snmp_sim import FakeClient
from .switch_fixtures import OID, TT, _iface, cisco_c9300
from .test_api import api, login  # noqa: F401
from .test_iac import As
from .test_switches import _CH, _seed

HR = "1.3.6.1.2.1.25"


def linux_host(load=(12, 30), disk_used=600) -> dict:
    """LABELLED SYNTHETIC FIXTURE: a net-snmp agent on a Linux appliance (2 CPUs, 8 GiB RAM, one 1000-unit disk, one
    ENTITY-SENSOR temperature, one voltage and one fan)."""
    t = {"1.3.6.1.2.1.1.1.0": "Linux nms-appliance 6.1.0 #1 SMP x86_64", "1.3.6.1.2.1.1.2.0": (OID, "1.3.6.1.4.1.8072.3.2.10"),
         "1.3.6.1.2.1.1.3.0": (TT, 360000), "1.3.6.1.2.1.1.5.0": "nms-appliance", "1.3.6.1.2.1.1.6.0": "Lab rack 2"}
    _iface(t, 1, "lo", "lo", 24, 10, 1)
    _iface(t, 2, "eth0", "eth0", 6, 1000, 1, in_oct=10_000, out_oct=20_000)
    t.update({f"{HR}.3.3.1.2.196608": load[0], f"{HR}.3.3.1.2.196609": load[1], f"{HR}.3.3.1.1.196608": (OID, "0.0"),
              f"{HR}.3.3.1.1.196609": (OID, "0.0")})
    for idx, typ, descr, units, size, used in ((1, 2, "Physical memory", 1024, 8_388_608, 4_194_304), (3, 3, "Virtual memory", 1024, 10_000_000, 5_000_000),
                                               (31, 4, "/", 4096, 1000, disk_used), (36, 4, "/var/log", 4096, 2000, 100)):
        t.update({f"{HR}.2.3.1.2.{idx}": (OID, f"{HR}.2.1.{typ}"), f"{HR}.2.3.1.3.{idx}": descr, f"{HR}.2.3.1.4.{idx}": units,
                  f"{HR}.2.3.1.5.{idx}": size, f"{HR}.2.3.1.6.{idx}": used})
    U = "1.3.6.1.4.1.2021"
    t.update({f"{U}.4.5.0": 8_000_000, f"{U}.4.6.0": 2_000_000, f"{U}.4.14.0": 500_000, f"{U}.4.15.0": 1_500_000,
              f"{U}.10.1.3.1": "0.52", f"{U}.10.1.3.2": "0.40", f"{U}.10.1.3.3": "0.31", f"{U}.11.11.0": 80})
    S = "1.3.6.1.2.1.99.1.1.1"
    for idx, typ, scale, prec, val in ((10, 8, 9, 1, 425), (11, 4, 8, 0, 12050), (12, 10, 9, 0, 5400)):
        t.update({f"{S}.1.{idx}": typ, f"{S}.2.{idx}": scale, f"{S}.3.{idx}": prec, f"{S}.4.{idx}": val, f"{S}.5.{idx}": 1})
    return t


async def _collect(client, vendor="generic"):
    ctx = C.Ctx(client=client, vendor=vendor, outcome=Outcome())
    data, report, ran = await P.run_groups(ctx, P.ORDER)
    return ctx, data, report


@pytest.fixture
def nms_ch(ch):
    for t in ("switch_metrics", "switch_metrics_hourly", "switch_if_samples", "switch_if_hourly", "service_results"):
        ch.command(f"TRUNCATE TABLE {t}")
    yield ch


# ------------------------------------------------------------------ standard MIB collection
async def test_generic_device_cpu_memory_storage_sensors():
    ctx, d, rep = await _collect(FakeClient(linux_host()))
    assert ctx.vendor == "generic" and all(r["ok"] for r in rep.values())
    assert d["cpu"]["pct"] == 21.0 and d["cpu"]["source"].startswith("HOST-RESOURCES")   # average of 12 and 30
    assert d["cpu"]["load"] == {"1m": 0.52, "5m": 0.40, "15m": 0.31}
    m = d["memory"]
    assert m["source"].startswith("UCD-SNMP") and m["pct"] == 50.0                         # avail 2 + buffers 0.5 + cached 1.5 of 8 GB
    vols = {v["name"]: v for v in d["storage"]}
    assert set(vols) == {"/", "/var/log"}                                                 # RAM / virtual memory are not storage
    assert vols["/"]["pct"] == 60.0 and vols["/"]["size_bytes"] == 4096 * 1000
    env = d["environment"]
    assert env["temperatures"] == [{"name": "sensor 10", "celsius": 42.5, "threshold": None, "state": "ok"}]
    sens = {x["kind"]: x for x in env["sensors"]}
    assert sens["voltage"]["value"] == 12.05 and sens["voltage"]["unit"] == "V DC" and sens["fan"]["value"] == 5400
    for k in ("switch_cpu_utilization_percent", "switch_memory_utilization_percent", "switch_storage_used_percent", "switch_load_average",
              "switch_temperature_celsius", "switch_sensor_value"):
        assert ctx.outcome.results[k]["result"] == "ok", k


async def test_generic_without_host_mibs_is_missing_not_zero():
    t = linux_host()
    t = {k: v for k, v in t.items() if not k.startswith((HR, "1.3.6.1.4.1.2021", "1.3.6.1.2.1.99"))}
    ctx, d, rep = await _collect(FakeClient(t))
    assert d["cpu"] is None and d["memory"] is None and d["storage"] == [] and d["environment"] is None
    for k in ("switch_cpu_utilization_percent", "switch_memory_utilization_percent", "switch_storage_used_percent", "switch_temperature_celsius"):
        assert ctx.outcome.results[k]["result"] == "missing", k


async def test_ucd_idle_and_hr_ram_fallbacks():
    t = linux_host()
    t = {k: v for k, v in t.items() if not k.startswith(f"{HR}.3.3") and not k.startswith("1.3.6.1.4.1.2021.4.")}
    _, d, _ = await _collect(FakeClient(t))
    assert d["cpu"]["pct"] == 20.0 and d["cpu"]["source"] == "UCD-SNMP-MIB ssCpuIdle"
    assert d["memory"]["source"] == "HOST-RESOURCES-MIB hrStorageRam" and d["memory"]["pct"] == 50.0


async def test_vendor_adapter_falls_back_to_standard_mibs():
    t, ctxs = cisco_c9300(0)
    t = {k: v for k, v in t.items() if not k.startswith("1.3.6.1.4.1.9.9.109.1.1.1.1") and not k.startswith("1.3.6.1.4.1.9.9.48")
         and not k.startswith("1.3.6.1.4.1.9.9.221")}
    t.update({f"{HR}.3.3.1.2.1": 35, f"{HR}.2.3.1.2.1": (OID, f"{HR}.2.1.2"), f"{HR}.2.3.1.3.1": "RAM", f"{HR}.2.3.1.4.1": 1024,
              f"{HR}.2.3.1.5.1": 1000, f"{HR}.2.3.1.6.1": 250})
    ctx, d, _ = await _collect(FakeClient(t, contexts=ctxs))
    assert ctx.vendor == "cisco"
    assert d["cpu"]["pct"] == 35.0 and d["memory"]["pct"] == 25.0
    assert ctx.outcome.results["switch_cpu_utilization_percent"]["result"] == "ok"


async def test_poll_persists_storage_load_and_sensor_metrics(db):
    sw, cred = await _seed(db)
    ch = _CH()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    res = await P.poll_switch(db, ch, sw, cred, client=FakeClient(linux_host()), now=now, force=True)
    assert res["ok"] and sw.vendor == "generic" and sw.cpu_pct == 21.0 and sw.mem_pct == 50.0
    assert [v["name"] for v in sw.health["storage"]] == ["/", "/var/log"]
    got = {(m["metric"], m["component"]): m["value"] for m in ch.rows["switch_metrics"]}
    assert got[("switch_storage_used_percent", "/")] == 60.0 and got[("switch_load_average", "1m")] == 0.52
    assert got[("switch_sensor_value", "voltage:sensor 11")] == 12.05
    assert sw.capabilities["switch_storage_used_percent"]["last_result"] == "ok"


# ------------------------------------------------------------------ pure analytics helpers
def test_linear_fit_and_forecast():
    a, b, r2 = A.linear_fit([(0, 10), (1, 12), (2, 14), (3, 16)])
    assert (round(a, 6), round(b, 6), round(r2, 6)) == (10, 2, 1)
    f = A.forecast([(d, 50 + d) for d in range(10)], 80)
    assert f["slope_per_day"] == 1.0 and f["days_left"] == 21.0 and f["confidence"] == "high"
    assert A.forecast([(d, 60 - d) for d in range(10)], 80)["days_left"] is None          # falling trend: never
    assert A.forecast([(d, 85) for d in range(10)], 80)["days_left"] == 0                 # already over
    assert A.forecast([(0, 50), (1, 60)], 80)["confidence"] == "insufficient_data"
    assert A.forecast([(d, 10 + 0.01 * d) for d in range(10)], 80, horizon_days=365)["days_left"] is None   # beyond the horizon
    assert A.p95(list(range(1, 101))) == 95 and A.p95([]) is None


def test_health_score_is_explainable():
    sw = Switch(name="a", address="192.0.2.1", monitoring="active", state="up", cpu_pct=95, mem_pct=40, coverage_pct=90,
                last_success_at=datetime.now(timezone.utc), poll_interval_seconds=60,
                health={"environment": {"psus": [{"name": "PSU2", "state": "critical"}], "fans": [], "temperatures": []},
                        "storage": [{"name": "flash:", "pct": 95}]})
    h = A.health_score(sw, open_alerts=["high", "low"], if_errors=2)
    assert h["score"] == 100 - 20 - 20 - 10 - 10 - 10 and h["grade"] == "critical"
    assert any("PSU2" in r for r in h["reasons"]) and any("flash:" in r for r in h["reasons"])
    assert A.health_score(Switch(name="b", address="x", monitoring="active", state="down"))["score"] == 0
    assert A.health_score(Switch(name="c", address="y", monitoring="paused", state="up"))["score"] is None


# ------------------------------------------------------------------ maintenance windows
def test_maintenance_occurrences_and_scope():
    once = NmsMaintenance(name="x", kind="once", enabled=True, starts_at=datetime(2026, 11, 1, 10, tzinfo=timezone.utc),
                          ends_at=datetime(2026, 11, 1, 12, tzinfo=timezone.utc), switch_ids=[3], sites=["WH1"], service_ids=[], all_devices=False)
    assert MW.occurrence(once, datetime(2026, 11, 1, 11, tzinfo=timezone.utc))
    assert MW.occurrence(once, datetime(2026, 11, 1, 12, tzinfo=timezone.utc)) is None
    # weekly, Sunday 23:00 IST for 3 h: crosses midnight into Monday
    wk = NmsMaintenance(name="y", kind="weekly", enabled=True, weekdays=[6], start_time="23:00", duration_minutes=180, timezone="Asia/Kolkata",
                        switch_ids=[], sites=[], service_ids=[], all_devices=True)
    sun = datetime(2026, 11, 1, 17, 45, tzinfo=timezone.utc)       # Sunday 23:15 IST
    mon = datetime(2026, 11, 1, 20, 0, tzinfo=timezone.utc)        # Monday 01:30 IST
    after = datetime(2026, 11, 1, 21, 0, tzinfo=timezone.utc)      # Monday 02:30 IST
    assert MW.occurrence(wk, sun) and MW.occurrence(wk, mon) and MW.occurrence(wk, after) is None
    assert MW.covers(once, switch_id=3) and MW.covers(once, sites=["wh1"]) and not MW.covers(once, switch_id=4, site="WH2")
    once.enabled = False
    assert MW.occurrence(once, datetime(2026, 11, 1, 11, tzinfo=timezone.utc)) is None
    with pytest.raises(ValueError):
        MW.zone("Mars/Olympus")


async def test_maintenance_holds_back_alerts_and_dependency_suppresses_children(db, ch):
    from app.alerts.engine import ensure_default_rules, run_rules
    core, cred = await _seed(db)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    acc = Switch(name="WH1-ACC-SW02", address="192.0.2.11", credential_id=cred.id, site="WH1", parent_id=core.id, capabilities={},
                 group_state={}, health={}, thresholds={})
    db.add(acc)
    await db.flush()
    for sw in (core, acc):
        sw.state, sw.state_since, sw.fail_streak = "down", now - timedelta(minutes=10), 5
    await ensure_default_rules(db)
    for r in (await db.execute(select(AlertRule))).scalars():
        r.enabled = r.key == "switch_unreachable"
    db.add(NmsMaintenance(name="core swap", kind="once", starts_at=now - timedelta(hours=1), ends_at=now + timedelta(hours=1),
                          switch_ids=[core.id], sites=[], service_ids=[], all_devices=False, enabled=True))
    await db.commit()
    res = await run_rules(ch, db, now=now, correlate=False)
    assert res["switch_unreachable"]["maintenance"] == 1 and res["switch_unreachable"]["created"] == 0
    assert (await db.execute(select(Alert))).scalars().all() == []
    # window over: one alert for the root cause, listing the device behind it; no separate alert for the child
    res = await run_rules(ch, db, now=now + timedelta(hours=2), correlate=False)
    alerts = (await db.execute(select(Alert))).scalars().all()
    assert len(alerts) == 1 and alerts[0].evidence["switch_id"] == core.id
    assert alerts[0].evidence["dependent_devices"] == ["WH1-ACC-SW02"] and "downstream" in alerts[0].explanation
    # parent recovers, child still down → child alerted on its own, parent resolved
    core.state = "up"
    await db.commit()
    await run_rules(ch, db, now=now + timedelta(hours=2, minutes=1), correlate=False)
    rows = {a.evidence["switch_id"]: a for a in (await db.execute(select(Alert))).scalars()}
    assert rows[acc.id].status == "new" and rows[core.id].status == "resolved"


# ------------------------------------------------------------------ service checks
def _svc(**kw):
    base = dict(id=1, name="svc", kind="tcp", target="127.0.0.1", port=1, expect="", match="", record="A", timeout_ms=2000, latency_warn_ms=None,
                cert_warn_days=21, interval_seconds=60, enabled=True, state="unknown", fail_streak=0)
    base.update(kw)
    return NmsService(**base)


async def test_tcp_check_ok_refused_and_slow():
    srv = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    try:
        r = await SV.run_check(_svc(port=port))
        assert r.state == "ok" and r.latency_ms is not None
        r = await SV.run_check(_svc(port=port, latency_warn_ms=1))
        assert r.state in ("ok", "warning")   # loopback can be under 1 ms
    finally:
        srv.close()
        await srv.wait_closed()
    r = await SV.run_check(_svc(port=port))
    assert r.state == "critical" and r.latency_ms is None                # refused: latency unknown, not 0


async def test_http_check_status_and_content():
    def handler(req):
        return httpx.Response(200 if req.url.path == "/ok" else 503, text="status: healthy")
    tr = httpx.MockTransport(handler)
    r = await SV.run_check(_svc(kind="http", target="https://app.example.test/ok", port=None, match="healthy"), http_transport=tr)
    assert r.state == "ok" and "HTTP 200" in r.message
    r = await SV.run_check(_svc(kind="http", target="https://app.example.test/ok", port=None, match="ready"), http_transport=tr)
    assert r.state == "critical" and "expected text" in r.message
    r = await SV.run_check(_svc(kind="http", target="https://app.example.test/down", port=None), http_transport=tr)
    assert r.state == "critical" and "HTTP 503" in r.message
    r = await SV.run_check(_svc(kind="http", target="https://app.example.test/down", port=None, expect="200,500-503"), http_transport=tr)
    assert r.state == "ok"


async def test_dns_check_and_validation():
    r = await SV.run_check(_svc(kind="dns", target="localhost", port=None, match="127.0.0.1"))
    assert r.state == "ok" and "127.0.0.1" in r.message
    r = await SV.run_check(_svc(kind="dns", target="localhost", port=None, match="192.0.2.99"))
    assert r.state == "critical"
    for args in (("http", "ftp://x", None, "", "A"), ("http", "https://u:p@x/", None, "", "A"), ("tcp", "x", None, "", "A"),
                 ("dns", "a b", None, "", "A"), ("http", "https://x/", None, "abc", "A"), ("dns", "x", None, "", "MX")):
        with pytest.raises(ValueError):
            SV.validate(*args)
    assert SV.parse_expect("200, 300-302") == [(200, 200), (300, 302)]


def test_cert_expiry_states():
    now = datetime(2026, 11, 2, tzinfo=timezone.utc)
    assert SV.cert_state(now + timedelta(days=90), now, 21)[0] == "ok"
    assert SV.cert_state(now + timedelta(days=10), now, 21)[0] == "warning"
    assert SV.cert_state(now - timedelta(days=1), now, 21)[0] == "critical"


async def test_service_alerts_and_cert_expiry_rule(db):
    from app.nms.alerts import rule_nms_cert_expiry, rule_nms_service_down
    now = datetime.now(timezone.utc)
    db.add_all([NmsService(name="api", kind="tcp", target="192.0.2.5", port=443, state="critical", state_since=now - timedelta(minutes=5),
                           fail_streak=3, last_check_at=now, last_message="refused", enabled=True, interval_seconds=60, site="WH1"),
                NmsService(name="flaky", kind="tcp", target="192.0.2.6", port=443, state="critical", state_since=now, fail_streak=1,
                           last_check_at=now, enabled=True, interval_seconds=60),
                NmsService(name="portal-cert", kind="tls", target="portal.example.test", port=443, state="warning", state_since=now,
                           fail_streak=0, last_check_at=now, enabled=True, interval_seconds=3600, cert_warn_days=21,
                           cert_expires_at=now + timedelta(days=5))])
    await db.commit()
    down = await rule_nms_service_down(None, now, {"min_failures": 2})
    assert [d.evidence["service"] for d in down] == ["api"] and down[0].sites == ["WH1"]
    certs = await rule_nms_cert_expiry(None, now, {"critical_days": 7})
    assert len(certs) == 1 and certs[0].severity == "high" and certs[0].evidence["days_left"] < 7


# ------------------------------------------------------------------ analytics over stored data
async def test_availability_capacity_top_and_p95(db, nms_ch):
    sw, cred = await _seed(db)
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    db.add(SwitchInterface(switch_id=sw.id, ifindex=1, name="Te1/1/1", kind="physical", speed_bps=10_000_000_000, oper="up", admin="up", present=True))
    sw.state = "up"
    await db.commit()
    # 10 days: up 99 % of samples; uplink peak utilisation growing 2 %/day from 50 %
    up_rows, if_rows, samples = [], [], []
    for d in range(10):
        for h in range(0, 24, 6):
            t = (now - timedelta(days=10 - d)).replace(hour=h)   # four samples inside each calendar day
            up_rows += [{"ts": t, "switch_id": sw.id, "metric": "switch_up", "component": "", "value": 1.0} for _ in range(99)]
            up_rows.append({"ts": t, "switch_id": sw.id, "metric": "switch_up", "component": "", "value": 0.0})
            util = 50 + 2 * d
            if_rows.append({"ts": t, "switch_id": sw.id, "ifindex": 1, "interval_s": 60.0, "rx_bps": util * 1e8, "tx_bps": 1e8,
                            "rx_util": float(util), "tx_util": 1.0, "rx_pps": None, "tx_pps": None, "in_errors": 0, "out_errors": 0,
                            "in_discards": 0, "out_discards": 0, "crc": 0, "oper": 1, "admin": 1, "flags": 0})
            up_rows.append({"ts": t, "switch_id": sw.id, "metric": "switch_cpu_utilization_percent", "component": "CPU 0", "value": 40.0 + 4 * d})
    await nms_ch.ainsert("switch_metrics", up_rows, P.METRIC_COLS)
    await nms_ch.ainsert("switch_if_samples", if_rows, P.IF_COLS)
    av = await A.availability(db, nms_ch, range_="30d", sla=99.9)
    dev = av["devices"][0]
    assert dev["availability_pct"] == 99.0 and dev["sla_met"] is False and av["summary"]["sla_breaches"] == 1
    cap = await A.capacity(db, nms_ch, days=30, threshold_if=80, threshold_dev=90)
    it = cap["interfaces"][0]
    assert it["name"] == "Te1/1/1" and it["slope_per_day"] == 2.0 and 0 < it["days_left"] <= 15
    cpu = [x for x in cap["devices"] if x["metric"] == "CPU %"][0]
    assert cpu["slope_per_day"] == 4.0 and cpu["days_left"] is not None
    top = await A.top_interfaces(db, nms_ch, range_="30d", by="peak_util", limit=5)
    assert top["items"][0]["value"] == 68.0
    p = await A.top_interfaces(db, nms_ch, range_="30d", by="p95", limit=5)
    assert p["items"][0]["rx_p95_bps"] >= 6.6e9 and p["items"][0]["p95_util_pct"] is not None
    td = await A.top_devices(db, nms_ch, range_="30d", by="cpu", limit=5)
    assert td["items"][0]["peak"] == 76.0
    # a device with no samples: availability unknown, not 0
    db.add(Switch(name="NEW", address="192.0.2.50", credential_id=cred.id, capabilities={}, group_state={}, health={}, thresholds={}))
    await db.commit()
    av = await A.availability(db, nms_ch, range_="30d", sla=99.9)
    new = [x for x in av["devices"] if x["name"] == "NEW"][0]
    assert new["availability_pct"] is None and new["sla_met"] is None and av["summary"]["unmeasured"] == 1


async def test_inventory_firmware_drift_and_unused_ports(db):
    _, cred = await _seed(db)
    old = datetime.now(timezone.utc) - timedelta(days=90)
    for i, fw in enumerate(["17.9.4", "17.9.4", "17.6.1"]):
        db.add(Switch(name=f"S{i}", address=f"192.0.2.{20 + i}", credential_id=cred.id, vendor="cisco", model="C9300-48P", firmware=fw,
                      state="up", uptime_ticks=400 * 86400 * 100 if i == 0 else 100, capabilities={}, group_state={}, health={}, thresholds={}))
    await db.flush()
    sid = (await db.execute(select(Switch).where(Switch.name == "S0"))).scalars().one().id
    db.add_all([SwitchInterface(switch_id=sid, ifindex=1, name="Gi1/0/1", kind="physical", oper="down", admin="up", last_change_at=old, present=True),
                SwitchInterface(switch_id=sid, ifindex=2, name="Gi1/0/2", kind="physical", oper="up", admin="up", speed_bps=1e9, present=True)])
    await db.commit()
    inv = await A.inventory(db, unused_days=30)
    drift = inv["firmware_drift"][0]
    assert drift["most_common"] == "17.9.4" and [o["name"] for o in drift["outliers"]] == ["S2"]
    assert inv["summary"]["ports_unused"] == 1 and inv["unused_ports"][0]["name"] == "Gi1/0/1"
    assert inv["summary"]["long_uptime_devices"] == 1 and {"speed": "1G", "count": 1} in inv["port_speeds"]


# ------------------------------------------------------------------ API
async def test_nms_api_rbac_services_maintenance_dependencies_analytics(api, db, nms_ch):  # noqa: F811
    admin = await As.login(api, "admin1")
    analyst = await As.login(api, "analyst1")
    body = {"name": "Portal HTTPS", "kind": "http", "target": "https://portal.example.test/health", "expect": "200", "interval_seconds": 60}
    assert (await analyst.post("/api/nms/services", json=body)).status_code == 403
    assert (await admin.post("/api/nms/services", json={**body, "target": "ftp://x"})).status_code == 422
    assert (await admin.post("/api/nms/services", json={**body, "kind": "tcp", "target": "x"})).status_code == 422   # no port
    r = await admin.post("/api/nms/services", json=body)
    assert r.status_code == 201
    sid = r.json()["id"]
    assert (await admin.post("/api/nms/services", json=body)).status_code == 409
    lst = (await analyst.get("/api/nms/services")).json()
    assert lst["total"] == 1 and lst["items"][0]["state"] == "unknown"
    h = await analyst.get(f"/api/nms/services/{sid}/history", params={"range": "24h"})
    assert h.status_code == 200 and h.json()["availability_pct"] is None
    # maintenance
    mw = {"name": "Weekly patching", "kind": "weekly", "weekdays": [6], "start_time": "23:00", "duration_minutes": 120, "timezone": "Asia/Kolkata",
          "sites": ["WH1"]}
    assert (await admin.post("/api/nms/maintenance", json={**mw, "start_time": "25:00"})).status_code == 422
    assert (await admin.post("/api/nms/maintenance", json={**mw, "timezone": "Nowhere/Zone"})).status_code == 422
    assert (await admin.post("/api/nms/maintenance", json={**mw, "sites": []})).status_code == 422
    assert (await analyst.post("/api/nms/maintenance", json=mw)).status_code == 403
    assert (await admin.post("/api/nms/maintenance", json=mw)).status_code == 201
    assert (await analyst.get("/api/nms/maintenance")).json()["items"][0]["name"] == "Weekly patching"
    # dependencies: no self / loops
    sw, cred = await _seed(db)
    b = Switch(name="B", address="192.0.2.12", credential_id=cred.id, capabilities={}, group_state={}, health={}, thresholds={})
    db.add(b)
    await db.commit()
    assert (await admin.put(f"/api/nms/dependencies/{b.id}", json={"parent_id": sw.id})).status_code == 200
    assert (await admin.put(f"/api/nms/dependencies/{sw.id}", json={"parent_id": b.id})).status_code == 422
    assert (await admin.put(f"/api/nms/dependencies/{sw.id}", json={"parent_id": sw.id})).status_code == 422
    assert (await analyst.put(f"/api/nms/dependencies/{sw.id}", json={"parent_id": None})).status_code == 403
    deps = {x["name"]: x for x in (await analyst.get("/api/nms/dependencies")).json()["items"]}
    assert deps["B"]["parent"] == sw.name and deps[sw.name]["children"] == 1
    # analytics endpoints answer for an analyst with NMS access
    for path, params in (("availability", {"range": "7d"}), ("capacity", {"days": 14}), ("top/interfaces", {"by": "p95"}),
                         ("top/devices", {"by": "memory"}), ("health", {}), ("inventory", {}), ("alerts", {"range": "7d"}), ("filters", {})):
        r = await analyst.get(f"/api/nms/analytics/{path}", params=params)
        assert r.status_code == 200, (path, r.text)
    assert (await analyst.get("/api/nms/analytics/top/interfaces", params={"by": "bogus"})).status_code == 422


def test_products_route_nms_paths_and_rules():
    from app.products import alert_product, required_product
    assert required_product("/api/nms/analytics/health") == "nms"
    assert alert_product("nms_service_down") == "nms" and alert_product("switch_storage_high") == "nms"


def test_registry_lists_standard_metrics_for_generic_devices():
    from app.switches.registry import GROUPS, metrics_for
    keys = {m.key for m in metrics_for("generic")}
    assert {"switch_cpu_utilization_percent", "switch_memory_utilization_percent", "switch_storage_used_percent", "switch_load_average",
            "switch_sensor_value"} <= keys
    assert GROUPS["storage"]["interval"] == 300
