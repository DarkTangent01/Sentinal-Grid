"""Generic SNMP device monitoring: device-type detection, monitoring templates, onboarding outcomes, tiered utilisation
alerts, capacity mismatch, interface bandwidth history (series / statistics / 95th percentile / totals / comparison),
5-minute rollup, retention, global interface filters and export, UPS / printer health. Counter maths (wrap, reset,
restart, gaps, 32-bit fallback) is covered in test_switches.py."""
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.db.models import MonitoringTemplate, Switch, SwitchInterface
from app.switches import bandwidth as B
from app.switches import poller as P
from app.switches import rates as R
from app.switches import templates as T
from app.switches.fingerprints import identify

from .snmp_sim import FakeClient
from .test_api import api, login  # noqa: F401
from .test_iac import As
from .test_switches import _seed


# ------------------------------------------------------------------ detection
def test_device_type_detection_beyond_switches():
    cases = {
        ("1.3.6.1.4.1.8072.3.2.10", "Linux web01 5.15.0-91-generic #101-Ubuntu SMP x86_64"): ("linux", "net-snmp"),
        ("1.3.6.1.4.1.311.1.1.3.1.2", "Hardware: Intel64 Family 6 - Software: Windows Version 6.3 (Build 17763)"): ("windows", "Microsoft"),
        ("1.3.6.1.4.1.318.1.3.27", "APC Web/SNMP Management Card (MB:v4.1.0 PF:v6.8.2)"): ("ups", "APC (Schneider Electric)"),
        ("1.3.6.1.4.1.11.2.3.9.1", "HP ETHERNET MULTI-ENVIRONMENT,ROM none,JETDIRECT,JD153"): ("printer", "HP / HPE"),
        ("1.3.6.1.4.1.6876.4.1", "VMware ESXi 7.0.3 build-20036589"): ("hypervisor", "VMware"),
        ("1.3.6.1.4.1.3375.2.1.3.4.43", "BIG-IP Virtual Edition"): ("load_balancer", "F5"),
        ("1.3.6.1.4.1.6574.1", "Linux DiskStation 4.4.180+"): ("linux", "Synology"),
        ("1.3.6.1.4.1.99999.1", "unknown box"): ("other", ""),
    }
    for (oid, descr), (typ, maker) in cases.items():
        r = identify(oid, descr)
        assert (r["device_type"], r["manufacturer"]) == (typ, maker), (oid, r)
        assert r["vendor"] in ("generic", "cisco", "fortinet", "juniper", "ruckus")       # adapters only for known vendors
    assert identify("1.3.6.1.4.1.9.1.2494", "Cisco IOS Software, Catalyst L3 Switch Software")["device_type"] == "switch"


# ------------------------------------------------------------------ templates
async def test_templates_seed_once_apply_and_resolve(db):
    await T.ensure_builtin(db)
    await T.ensure_builtin(db)
    keys = set((await db.execute(select(MonitoringTemplate.key))).scalars())
    assert {"generic", "switch", "router", "firewall", "wlc", "ap", "linux", "windows", "ups", "printer"} <= keys
    assert (await db.execute(select(MonitoringTemplate))).scalars().all().__len__() == len(T.BUILTIN)
    sw, _ = await _seed(db)
    ups = await T.template_for_type(db, "ups")
    sw.device_type = "ups"
    await T.apply(db, sw, ups)
    iv = P.intervals_of(sw)
    assert iv["ups"] == 60 and iv["mac_table"] == 0 and "printer" not in iv       # template; printer group only for printers
    sw.group_intervals = {"ups": 300}
    assert P.intervals_of(sw)["ups"] == 300                                         # device override wins
    sw.device_type, sw.template_config, sw.group_intervals = "switch", {}, {}
    assert "ups" not in P.intervals_of(sw)
    # interface thresholds: interface → device → template → rule → default
    sw.template_config = {"thresholds": {"util_high_pct": 80}}
    assert T.interface_threshold({}, sw, {}, "util_high_pct") == 80
    sw.thresholds = {"util_high_pct": 75}
    assert T.interface_threshold({"util_high_pct": 60}, sw, {}, "util_high_pct") == 60
    assert T.interface_threshold({}, sw, {}, "util_crit_pct") == 95
    # editing a template refreshes every device that uses it
    lin = await T.template_for_type(db, "linux")
    await T.apply(db, sw, lin)
    await db.commit()
    lin.thresholds = {**lin.thresholds, "cpu_pct": 50}
    assert await T.propagate(db, lin) == 1
    assert sw.template_config["thresholds"]["cpu_pct"] == 50
    assert T.interface_excluded(sw, 24, "lo") and not T.interface_excluded(sw, 6, "eth0")


# ------------------------------------------------------------------ onboarding
async def _admin_with_profile(api, db):  # noqa: F811
    admin = await As.login(api, "admin1")
    cred = {"name": "ro-v3", "version": "v3", "username": "siem-ro", "auth_protocol": "sha", "priv_protocol": "aes128",
            "auth_key": "auth-pass-123", "priv_key": "priv-pass-456"}
    cid = (await admin.post("/api/switches/admin/credentials", json=cred)).json()["id"]
    assert (await admin.post("/api/switches/admin/networks", json={"cidr": "192.0.2.0/24", "site": "WH1"})).status_code == 201
    return admin, cid


async def test_onboarding_outcomes_and_no_success_without_snmp(api, db, monkeypatch):  # noqa: F811
    from app import icmp
    admin, cid = await _admin_with_profile(api, db)
    analyst = await As.login(api, "analyst1")
    body = {"name": "UPS-01", "address": "192.0.2.50", "credential_id": cid, "site": "WH1", "tags": ["power", " power ", "dc1"]}
    assert (await analyst.post("/api/devices/onboard", json=body)).status_code == 403

    async def ping_ok(addr, **k):
        return icmp.ProbeResult(sent=2, received=2, rtts=[1.2, 1.4])

    async def ping_dead(addr, **k):
        return icmp.ProbeResult(sent=2, received=0, rtts=[])
    monkeypatch.setattr(icmp, "ping", ping_ok)

    async def probe_auth(*a, **k):
        return {"ok": False, "stage": "connect", "kind": "auth", "error": "authentication failure"}
    monkeypatch.setattr(P, "probe", probe_auth)
    r = (await admin.post("/api/devices/onboard", json=body)).json()
    assert r["ok"] is False and r["outcome"] == "auth_failed" and "authentication" in r["message"]
    assert (await db.execute(select(Switch))).scalars().all() == []                  # nothing saved

    async def probe_timeout(*a, **k):
        return {"ok": False, "stage": "connect", "kind": "timeout", "error": "no response"}
    monkeypatch.setattr(P, "probe", probe_timeout)
    assert (await admin.post("/api/devices/onboard", json=body)).json()["outcome"] == "snmp_no_response"
    monkeypatch.setattr(icmp, "ping", ping_dead)
    assert (await admin.post("/api/devices/onboard", json=body)).json()["outcome"] == "unreachable"
    monkeypatch.setattr(icmp, "ping", ping_ok)

    assert (await admin.post("/api/devices/onboard", json={**body, "address": "10.9.9.9"})).json()["outcome"] == "invalid"   # outside networks

    async def probe_ok(*a, **k):
        return {"ok": True, "duration_ms": 40, "identity": {"vendor": "generic", "manufacturer": "APC (Schneider Electric)", "device_type": "ups",
                                                            "model": "SMT1500", "os": "", "firmware": "6.8.2"},
                "system": {"sys_name": "ups-01", "sys_descr": "APC Web/SNMP Management Card", "sys_object_id": "1.3.6.1.4.1.318.1.3.27",
                           "location": "DC1", "uptime_s": 86400 * 3},
                "groups": {"interfaces": {"status": "ok"}}, "capabilities": [{"key": "device_ups_battery_charge_percent", "status": "healthy"}],
                "preview": {"interfaces": 2, "interfaces_up": 1, "hc_counters": 0}}
    monkeypatch.setattr(P, "probe", probe_ok)
    r = await admin.post("/api/devices/onboard", json=body)
    j = r.json()
    assert j["ok"] is True and j["outcome"] == "added" and [s["key"] for s in j["steps"]][:4] == ["validate", "config", "icmp", "snmp"]
    assert "auth-pass" not in r.text and "priv-pass" not in r.text
    sw = await db.get(Switch, j["id"])
    await db.refresh(sw)
    assert sw.device_type == "ups" and sw.template_config["name"] == "UPS" and sw.tags == ["dc1", "power"] and sw.monitoring == "active"
    assert (await admin.post("/api/devices/onboard", json={**body, "name": "UPS-02"})).json()["outcome"] == "duplicate"

    async def probe_no_ifs(*a, **k):
        x = await probe_ok()
        x["preview"] = {"interfaces": 0}
        return x
    monkeypatch.setattr(P, "probe", probe_no_ifs)
    j = (await admin.post("/api/devices/onboard", json={**body, "name": "PRN-1", "address": "192.0.2.51", "device_type": "printer"})).json()
    assert j["ok"] is True and j["outcome"] == "partial"
    prn = await db.get(Switch, j["id"])
    await db.refresh(prn)
    assert prn.device_type == "printer" and prn.device_type_override == "printer" and prn.template_config["name"] == "Printer"
    # manual classification and template through PATCH
    r = await admin.patch(f"/api/devices/{prn.id}", json={"device_type": "iot", "clear_template": True})
    assert r.status_code == 200 and r.json()["template_id"] is None


# ------------------------------------------------------------------ bandwidth history
def _row(sid, ifx, ts, rx, tx, util=None, flags=0, interval=60.0, oper=1, tx_util=None):
    return {"ts": ts, "switch_id": sid, "ifindex": ifx, "interval_s": interval, "rx_bps": rx, "tx_bps": tx, "rx_util": util,
            "tx_util": util if tx_util is None else tx_util,
            "rx_pps": None, "tx_pps": None, "in_errors": 0, "out_errors": 0, "in_discards": 0, "out_discards": 0, "crc": 0, "oper": oper, "admin": 1,
            "flags": flags}


async def test_bandwidth_series_stats_rollup_and_comparison(db, ch):
    ch.command("TRUNCATE TABLE switch_if_samples")
    ch.command("TRUNCATE TABLE switch_if_5m")
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    t0 = now - timedelta(hours=2)
    rows = [_row(1, 5, t0 + timedelta(minutes=i), rx=1e6 * (i + 1), tx=5e5, util=0.1) for i in range(100)]
    rows.append(_row(1, 5, t0 + timedelta(minutes=100), rx=9e12, tx=9e12, flags=R.RESET))     # a reset sample never counts
    await ch.ainsert("switch_if_samples", rows, P.IF_COLS)
    ret = B.RETENTION_DEFAULTS
    s = await B.stats(ch, 1, 5, t0, now, ret)
    assert s["source"] == "raw" and s["rated_samples"] == 100
    assert s["rx"]["min"] == 1e6 and s["rx"]["max"] == 1e8 and abs(s["rx"]["avg"] - 50.5e6) < 1
    assert abs(s["rx"]["bytes"] - sum(1e6 * (i + 1) * 60 / 8 for i in range(100))) < 10          # rate × interval, not a guess
    assert s["tx"]["bytes"] == 5e5 * 60 * 100 / 8
    assert s["rx"]["p95"] is not None and 80e6 < s["rx"]["p95"] <= 1e8                          # 95th pct of 5-minute averages
    ser = await B.series(ch, 1, 5, t0, now, ret)
    assert ser["source"] == "raw" and all(p["rx_bps"] < 1e12 for p in ser["points"])
    # the 5-minute rollup is fed by the materialised view and agrees with the raw figures
    five = await B.stats(ch, 1, 5, now - timedelta(days=3), now, ret)
    assert five["source"] == "5m" and five["rated_samples"] == 100 and abs(five["rx"]["bytes"] - s["rx"]["bytes"]) < 10
    assert five["rx"]["max"] == 1e8 and five["rx"]["min"] == 1e6
    # no data → no numbers (never zeros)
    empty = await B.stats(ch, 1, 6, t0, now, ret)
    assert empty["rated_samples"] == 0 and empty["rx"]["avg"] is None and empty["rx"]["bytes"] is None
    assert B.compare_window("previous", t0, now) == (t0 - (now - t0), t0)
    assert B.source_for(now - timedelta(days=200), now, ret) == "hourly"


async def test_retention_is_validated_and_applied(db, ch):
    import pytest
    with pytest.raises(ValueError):
        B.validate_retention({"raw_days": 100, "five_min_days": 30, "hourly_days": 400})
    with pytest.raises(ValueError):
        B.validate_retention({"raw_days": 0})
    v = await B.set_retention(db, ch, {"raw_days": 14, "five_min_days": 60, "hourly_days": 365}, "admin1")
    assert v == {"raw_days": 14, "five_min_days": 60, "hourly_days": 365} and await B.retention(db) == v
    ddl = ch.query("SELECT create_table_query AS q FROM system.tables WHERE database = currentDatabase() AND name = 'switch_if_5m'")[0]["q"]
    assert "toIntervalDay(60)" in ddl
    await B.set_retention(db, ch, B.RETENTION_DEFAULTS, "admin1")


# ------------------------------------------------------------------ alerts
async def test_utilisation_levels_per_interface_and_capacity_mismatch(db, ch):
    from app.switches.alerts import rule_switch_if_capacity_mismatch, rule_switch_if_utilization
    sw, _ = await _seed(db)
    sw.last_success_at = datetime.now(timezone.utc)
    db.add_all([SwitchInterface(switch_id=sw.id, ifindex=1, name="Gi1/0/1", kind="physical", if_type=6, counters={}),
                SwitchInterface(switch_id=sw.id, ifindex=2, name="Gi1/0/2", kind="physical", if_type=6, counters={}, thresholds={"util_warn_pct": 40}),
                SwitchInterface(switch_id=sw.id, ifindex=3, name="Gi1/0/3", kind="physical", if_type=6, counters={}, monitored=False),
                SwitchInterface(switch_id=sw.id, ifindex=4, name="Gi1/0/4", kind="physical", if_type=6, oper="up", speed_bps=100_000_000,
                                counters={"max_speed_bps": 1_000_000_000})])
    await db.commit()
    ch.command("TRUNCATE TABLE switch_if_samples")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    rows = []
    for i in range(3):
        ts = now - timedelta(minutes=3 - i)
        rows += [_row(sw.id, 1, ts, 8.8e8, 1e6, util=88.0, tx_util=0.1), _row(sw.id, 2, ts, 4.5e8, 1e6, util=45.0, tx_util=0.1),
                 _row(sw.id, 3, ts, 9.9e8, 1e6, util=99.0, tx_util=0.1)]
    rows.append(_row(sw.id, 1, now - timedelta(seconds=10), 1e9, 1e6, util=100.0, flags=R.GAP))   # flagged: ignored
    await ch.ainsert("switch_if_samples", rows, P.IF_COLS)
    dets = {d.group_key: d for d in await rule_switch_if_utilization(ch, now, {"min_samples": 3, "window_minutes": 15})}
    assert set(dets) == {f"{sw.id}:1:rx", f"{sw.id}:2:rx"}                                  # unmonitored interface 3 skipped
    assert dets[f"{sw.id}:1:rx"].severity == "medium" and dets[f"{sw.id}:1:rx"].evidence["level"] == "high"
    assert dets[f"{sw.id}:2:rx"].severity == "low" and dets[f"{sw.id}:2:rx"].evidence["threshold"] == 40
    cm = await rule_switch_if_capacity_mismatch(ch, now, {"min_ratio": 2})
    assert [d.group_key for d in cm] == [f"{sw.id}:4"] and "100 Mbit/s" in cm[0].explanation


# ------------------------------------------------------------------ global interfaces, patch, export
async def test_global_interfaces_quick_filters_patch_and_export(api, db, ch):  # noqa: F811
    ch.command("TRUNCATE TABLE switch_if_samples")
    ch.command("TRUNCATE TABLE switch_if_5m")
    admin, cid = await _admin_with_profile(api, db)
    analyst = await As.login(api, "analyst1")
    sw = Switch(name="CORE-1", address="192.0.2.1", credential_id=cid, site="WH1", device_type="router", capabilities={}, group_state={}, health={})
    db.add(sw)
    await db.flush()
    now = datetime.now(timezone.utc)
    db.add_all([SwitchInterface(switch_id=sw.id, ifindex=1, name="Te1/1", kind="physical", admin="up", oper="up", rx_util=92.0, tx_util=3.0,
                                speed_bps=10_000_000_000, rx_bps=9.2e9, tx_bps=3e8, last_sample_at=now, counters={}),
                SwitchInterface(switch_id=sw.id, ifindex=2, name="Te1/2", kind="physical", admin="up", oper="down", counters={}, last_sample_at=now,
                                last_change_at=now),
                SwitchInterface(switch_id=sw.id, ifindex=3, name="Po1", kind="lag", admin="up", oper="up", rx_util=10.0, counters={}, last_sample_at=now,
                                in_errors_delta=5),
                SwitchInterface(switch_id=sw.id, ifindex=4, name="Gi0/0", kind="physical", admin="up", oper="up", counters={}, last_sample_at=None)])
    await db.commit()
    g = lambda **p: analyst.get("/api/devices/interfaces", params=p)  # noqa: E731
    assert [x["name"] for x in (await g(quick="high_util")).json()["items"]] == ["Te1/1"]
    assert [x["name"] for x in (await g(quick="down")).json()["items"]] == ["Te1/2"]
    assert [x["name"] for x in (await g(quick="errors")).json()["items"]] == ["Po1"]
    assert [x["name"] for x in (await g(quick="no_data")).json()["items"]] == ["Gi0/0"]
    assert {x["name"] for x in (await g(layer="logical")).json()["items"]} == {"Po1"}
    assert (await g(device_type="router")).json()["total"] == 4 and (await g(device_type="ups")).json()["total"] == 0
    assert (await analyst.patch(f"/api/devices/{sw.id}/interfaces/1", json={"monitored": False})).status_code == 403
    r = await admin.patch(f"/api/devices/{sw.id}/interfaces/1", json={"monitored": False, "thresholds": {"util_high_pct": 90}})
    assert r.status_code == 200 and r.json() == {"monitored": False, "thresholds": {"util_high_pct": 90}}
    assert (await admin.patch(f"/api/devices/{sw.id}/interfaces/1", json={"thresholds": {"util_high_pct": 150}})).status_code == 422
    assert [x["name"] for x in (await g(quick="unmonitored")).json()["items"]] == ["Te1/1"]
    csv = await analyst.get("/api/devices/interfaces/export.csv", params={"quick": "down"})
    assert csv.status_code == 200 and "Te1/2" in csv.text and "Te1/1" not in csv.text
    b = await analyst.get(f"/api/devices/{sw.id}/interfaces/1/bandwidth", params={"range": "1h", "compare": "previous"})
    assert b.status_code == 200 and b.json()["stats"]["rated_samples"] == 0 and "compare" in b.json()
    assert (await analyst.get(f"/api/devices/{sw.id}/interfaces/1/bandwidth", params={"start": now.isoformat()})).status_code == 422
    assert (await analyst.get("/api/devices/templates")).json()["items"]
    assert (await analyst.put("/api/devices/retention", json=B.RETENTION_DEFAULTS)).status_code == 403


# ------------------------------------------------------------------ UPS / printer collectors
async def test_ups_and_printer_health_from_standard_mibs():
    from app.switches import collect as C
    from app.switches import power
    from app.switches.registry import Outcome
    U = "1.3.6.1.2.1.33.1"
    table = {f"{U}.1.1.0": b"APC", f"{U}.1.2.0": b"Smart-UPS 1500", f"{U}.2.1.0": 2, f"{U}.2.3.0": 42, f"{U}.2.4.0": 97, f"{U}.4.1.0": 3,
             f"{U}.4.4.1.2.1": 230, f"{U}.4.4.1.5.1": 31, f"{U}.3.3.1.3.1": 229}
    ctx = C.Ctx(client=FakeClient(table), vendor="generic", outcome=Outcome())
    u = (await power.collect_ups(ctx))["ups"]
    assert u["charge_pct"] == 97 and u["runtime_minutes"] == 42 and u["load_pct"] == 31 and u["battery_status"] == "normal" and u["on_battery"] is False
    # a device without UPS-MIB: unsupported, not zero
    ctx2 = C.Ctx(client=FakeClient({}), vendor="generic", outcome=Outcome())
    assert (await power.collect_ups(ctx2))["ups"] is None
    P_ = "1.3.6.1.2.1.43.11.1.1"
    prt = {f"{P_}.6.1.1": b"Black Toner", f"{P_}.8.1.1": 10000, f"{P_}.9.1.1": 2500, f"{P_}.6.1.2": b"Waste", f"{P_}.8.1.2": -2, f"{P_}.9.1.2": -3,
           "1.3.6.1.2.1.25.3.5.1.1.1": 3, "1.3.6.1.2.1.25.3.5.1.2.1": bytes([0b00100000]), "1.3.6.1.2.1.43.10.2.1.4.1.1": 123456}
    ctx3 = C.Ctx(client=FakeClient(prt), vendor="generic", outcome=Outcome())
    p = (await power.collect_printer(ctx3))["printer"]
    assert p["status"] == "idle" and p["errors"] == ["low toner"] and p["page_count"] == 123456
    assert p["supplies"][0]["pct"] == 25.0 and p["supplies"][1]["pct"] is None and p["supplies"][1]["state"] == "some remaining"
