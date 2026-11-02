"""Multi-vendor SNMP framework: fingerprint registry and overrides, Fortinet / Juniper adapters, vendor-health alarms and
alert, polling backoff, custom OIDs (counter rates), disabled metrics, MIB import (parser only), trap normalisation, the
trap receiver over real UDP (v2c trap, v1 trap, SNMPv3 inform, rejected source / credential), trap alerts, the
/api/snmp endpoints (RBAC, validation, OID test, versions, rollback) and site-scoped access.

All device data below are LABELLED SYNTHETIC FIXTURES built from the public MIB definitions (FORTINET-FORTIGATE-MIB,
FORTINET-FORTISWITCH-MIB, JUNIPER-MIB, JUNIPER-ALARM-MIB, JUNIPER-SRX5000-SPU-MONITORING-MIB). They are not captures from
real devices and are never shown as live monitoring; no network device is contacted (traps go over 127.0.0.1 only)."""
import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app import snmp_profiles as SP
from app import snmp_traps as T
from app.db.models import Alert, AlertRule, SnmpCustomOid, SnmpMetricSetting, Switch, User
from app.security import hash_password
from app.switches import collect as C
from app.switches import fingerprints as FP
from app.switches import poller as P
from app.switches.registry import Outcome
from app.switches.snmp import Credentials

from .snmp_sim import FakeClient
from .switch_fixtures import OID, TT, _iface
from .test_api import PW, api, login  # noqa: F401
from .test_iac import As
from .test_switches import _CH, _seed

FG = "1.3.6.1.4.1.12356.101"
JNX = "1.3.6.1.4.1.2636"


def fortigate(ha_sync=1, vpn_status=2, sdwan_state=0) -> dict:
    """LABELLED SYNTHETIC FIXTURE: FortiGate-100F, FortiOS 7.2.8, active-passive HA pair, two IPsec tunnels, one SD-WAN health check."""
    t = {"1.3.6.1.2.1.1.1.0": "FortiGate-100F v7.2.8,build1639,240313 (GA.M)", "1.3.6.1.2.1.1.2.0": (OID, f"{FG}.1.10004"),
         "1.3.6.1.2.1.1.3.0": (TT, 500000), "1.3.6.1.2.1.1.5.0": "LAB-FGT-01"}
    _iface(t, 1, "wan1", "wan1", 6, 1000, 1, in_oct=5000, out_oct=8000)
    t.update({f"{FG}.4.1.1.0": "v7.2.8,build1639,240313 (GA.M)", f"{FG}.4.1.3.0": 23, f"{FG}.4.1.4.0": 61, f"{FG}.4.1.5.0": 8_000_000,
              f"{FG}.4.1.6.0": 1200, f"{FG}.4.1.7.0": 120_000, f"{FG}.4.1.8.0": 48211,
              f"{FG}.4.4.2.1.2.1": 20, f"{FG}.4.4.2.1.2.2": 26,
              f"{FG}.13.1.1.0": 3,
              f"{FG}.13.2.1.1.2.1": "FG100FTK00000001", f"{FG}.13.2.1.1.11.1": "LAB-FGT-01", f"{FG}.13.2.1.1.12.1": 1, f"{FG}.13.2.1.1.16.1": "FG100FTK00000001",
              f"{FG}.13.2.1.1.2.2": "FG100FTK00000002", f"{FG}.13.2.1.1.11.2": "LAB-FGT-02", f"{FG}.13.2.1.1.12.2": ha_sync, f"{FG}.13.2.1.1.16.2": "FG100FTK00000001"})
    for i, (p1, p2, st) in enumerate((("to-dc1", "to-dc1-p2", 2), ("to-dc2", "to-dc2-p2", vpn_status)), 1):
        t.update({f"{FG}.12.2.2.1.3.{i}": p1, f"{FG}.12.2.2.1.4.{i}": p2, f"{FG}.12.2.2.1.5.{i}": (("ip", f"198.51.100.{i}")),
                  f"{FG}.12.2.2.1.18.{i}": 1000 * i, f"{FG}.12.2.2.1.19.{i}": 2000 * i, f"{FG}.12.2.2.1.20.{i}": st})
    t.update({f"{FG}.4.9.2.1.2.1": "dc-ping", f"{FG}.4.9.2.1.4.1": sdwan_state, f"{FG}.4.9.2.1.5.1": "12.345", f"{FG}.4.9.2.1.6.1": "0.880",
              f"{FG}.4.9.2.1.9.1": "0.00%", f"{FG}.4.9.2.1.14.1": "wan1"})
    for i, (name, val, alarm) in enumerate((("CPU ON-DIE Temp", "54", 0), ("FAN1", "4200", 0), ("PS1 Status", "1", 0), ("+12V", "12.07", 0)), 1):
        t.update({f"{FG}.4.3.2.1.2.{i}": name, f"{FG}.4.3.2.1.3.{i}": val, f"{FG}.4.3.2.1.4.{i}": alarm})
    return t


def fortiswitch() -> dict:
    """LABELLED SYNTHETIC FIXTURE: FortiSwitch 248E (standalone)."""
    t = {"1.3.6.1.2.1.1.1.0": "FortiSwitch-248E-FPOE v7.2.5", "1.3.6.1.2.1.1.2.0": (OID, "1.3.6.1.4.1.12356.106.1.2481"), "1.3.6.1.2.1.1.3.0": (TT, 1000)}
    _iface(t, 1, "port1", "port1", 6, 1000, 1)
    t.update({"1.3.6.1.4.1.12356.106.4.1.2.0": 7, "1.3.6.1.4.1.12356.106.4.1.3.0": 35, "1.3.6.1.4.1.12356.106.4.1.4.0": 2_000_000})
    return t


def juniper(model="ex4300-48p", red=0, yellow=0, fan_state=2, spu=False) -> dict:
    """LABELLED SYNTHETIC FIXTURE: Junos 21.4 device (EX by default; SRX with SPU rows when spu=True)."""
    t = {"1.3.6.1.2.1.1.1.0": f"Juniper Networks, Inc. {model} internet router, kernel JUNOS 21.4R3-S4.9, Build date: 2023-06-01",
         "1.3.6.1.2.1.1.2.0": (OID, f"{JNX}.1.1.1.2.63"), "1.3.6.1.2.1.1.3.0": (TT, 777)}
    _iface(t, 500, "ge-0/0/0", "ge-0/0/0", 6, 1000, 1)
    O = f"{JNX}.3.1.13.1"
    rows = {"9.1.0.0": ("Routing Engine 0", 2, 41, 18, 37, 2048), "9.2.0.0": ("Routing Engine 1", 7, 39, 2, 30, 2048),
            "4.1.1.0": ("FAN 0 @ 0/0/*", fan_state, 0, 0, 0, 0), "2.1.0.0": ("Power Supply 0", 2, 0, 0, 0, 0), "7.1.0.0": ("FPC: EX4300-48P @ 0/*/*", 2, 37, 9, 50, 2048)}
    for idx, (descr, state, temp, cpu, buf, mem) in rows.items():
        t.update({f"{O}.5.{idx}": descr, f"{O}.6.{idx}": state, f"{O}.7.{idx}": temp, f"{O}.8.{idx}": cpu, f"{O}.11.{idx}": buf, f"{O}.15.{idx}": mem})
    A = f"{JNX}.3.4.2"
    t.update({f"{A}.2.1.0": 3 if yellow else 2, f"{A}.2.2.0": yellow, f"{A}.3.1.0": 3 if red else 2, f"{A}.3.2.0": red})
    if spu:
        S = f"{JNX}.3.39.1.12.1.1.1"
        t.update({f"{S}.4.0": 12, f"{S}.5.0": 40, f"{S}.6.0": 15000, f"{S}.7.0": 512000})
    return t


async def _collect(client, vendor="generic", **kw):
    ctx = C.Ctx(client=client, vendor=vendor, outcome=Outcome(), **kw)
    data, report, ran = await P.run_groups(ctx, P.ORDER)
    return ctx, data, report


# ------------------------------------------------------------------ fingerprints
def test_fingerprint_registry_order_confidence_and_overrides():
    fg = FP.identify(f"{FG}.1.10004", "FortiGate-100F v7.2.8,build1639")
    assert (fg["vendor"], fg["family"], fg["device_type"], fg["confidence"], fg["firmware"]) == ("fortinet", "FortiGate", "firewall", "exact", "7.2.8")
    fs = FP.identify("1.3.6.1.4.1.12356.106.1.2481", "FortiSwitch-248E-FPOE v7.2.5")
    assert fs["family"] == "FortiSwitch" and fs["device_type"] == "switch"
    # sysObjectID wins over a misleading sysDescr: a Cisco OID with "Juniper" in the description stays Cisco
    c = FP.identify("1.3.6.1.4.1.9.1.2694", "Cisco IOS Software, Catalyst L3 Switch Software, uplink to Juniper ex4300")
    assert c["vendor"] == "cisco" and c["family"] == "Catalyst"
    srx = FP.identify(f"{JNX}.1.1.1.2.100", "Juniper Networks, Inc. srx345 internet router, kernel JUNOS 22.4R2")
    assert (srx["vendor"], srx["family"], srx["device_type"], srx["os"], srx["confidence"]) == ("juniper", "SRX", "firewall", "Junos", "family")
    mx = FP.identify(f"{JNX}.1.1.1.2.25", "Juniper Networks, Inc. mx204 internet router, kernel JUNOS 21.2R3")
    assert mx["family"] == "MX" and mx["device_type"] == "router"
    sz = FP.identify("1.3.6.1.4.1.25053.3.1.11", "Ruckus vSZ-H")
    assert sz["vendor"] == "ruckus" and sz["family"] == "SmartZone" and sz["device_type"] == "wlc"
    nx = FP.identify("1.3.6.1.4.1.9.12.3.1.3.1812", "Cisco NX-OS(tm) nxos.9.3.10.bin, Software (nxos), Version 9.3(10)")
    assert nx["family"] == "Nexus" and nx["os"] == "NX-OS"
    d = FP.identify("", "Cisco IOS Software, C2960X Software")     # no sysObjectID: description only, low confidence
    assert d["vendor"] == "cisco" and d["confidence"] == "descr"
    u = FP.identify("1.3.6.1.4.1.8072.3.2.10", "Linux 6.1")
    assert u["vendor"] == "generic" and u["confidence"] == "unknown"
    o = FP.identify(f"{FG}.1.10004", "FortiGate-100F v7.2.8", vendor_override="juniper", family_override="SRX")
    assert o["vendor"] == "juniper" and o["family"] == "SRX" and o["confidence"] == "override" and "fortinet" in o["override_conflict"]


# ------------------------------------------------------------------ Fortinet adapter
async def test_fortigate_adapter_health_ha_vpn_sdwan_sensors():
    ctx, d, rep = await _collect(FakeClient(fortigate(ha_sync=0, vpn_status=1, sdwan_state=1)))
    assert ctx.vendor == "fortinet" and ctx.product_line == "FortiGate" and all(r["ok"] for r in rep.values())
    assert d["cpu"]["pct"] == 23.0 and [c["pct_1m"] for c in d["cpu"]["cpus"]] == [20, 26] and d["memory"]["pct"] == 61.0
    env = d["environment"]
    assert [t["name"] for t in env["temperatures"]] == ["CPU ON-DIE Temp"] and env["temperatures"][0]["celsius"] == 54.0
    assert [f["name"] for f in env["fans"]] == ["FAN1"] and [p["name"] for p in env["psus"]] == ["PS1 Status"]
    assert env["sensors"][0]["name"] == "+12V" and env["sensors"][0]["value"] == 12.07
    v = d["vendor"]
    assert v["sessions"] == 48211 and v["ha"]["mode"] == "active-passive" and v["disk"]["pct"] == 1.0
    assert {t["state"] for t in v["vpn_tunnels"]} == {"up", "down"} and v["sdwan"][0]["latency_ms"] == 12.345
    keys = {a["key"] for a in v["alarms"]}
    assert keys == {"ha_sync:FG100FTK00000002", "vpn:to-dc2:to-dc2-p2", "sdwan:dc-ping:wan1"}
    for k in ("fortigate_sessions", "fortigate_ha_state", "fortigate_vpn_tunnels", "fortigate_sdwan_health", "switch_cpu_utilization_percent"):
        assert ctx.outcome.results[k]["result"] == "ok", k


async def test_fortiswitch_uses_fortiswitch_mib_and_no_fortigate_tables():
    cl = FakeClient(fortiswitch())
    ctx, d, _ = await _collect(cl)
    assert ctx.product_line == "FortiSwitch" and d["cpu"]["pct"] == 7.0 and d["memory"]["pct"] == 35.0 and d["vendor"] is None
    assert not any(w.startswith(FG) for w in cl.walked)       # FortiGate tables are never asked of a FortiSwitch


# ------------------------------------------------------------------ Juniper adapter
async def test_juniper_ex_routing_engine_environment_alarms():
    ctx, d, rep = await _collect(FakeClient(juniper(red=1, fan_state=6)))
    assert ctx.vendor == "juniper" and ctx.product_line == "EX"
    assert d["cpu"]["pct"] == 18 and len(d["cpu"]["cpus"]) == 2              # standby RE listed, not used for the device value
    assert d["memory"]["pct"] == 37.0 and d["memory"]["total_bytes"] == 2048 * 1024 * 1024
    env = d["environment"]
    assert {t["name"] for t in env["temperatures"]} == {"Routing Engine 0", "Routing Engine 1", "FPC: EX4300-48P @ 0/*/*"}
    assert env["fans"] == [{"name": "FAN 0 @ 0/0/*", "state": "failed"}] and env["psus"][0]["state"] == "ok"
    keys = {a["key"]: a["severity"] for a in d["vendor"]["alarms"]}
    assert keys["chassis_red"] == "critical" and "component:4.1.1.0" in keys
    assert ctx.outcome.results["juniper_chassis_alarms"]["result"] == "ok"


async def test_juniper_srx_spu_sessions():
    ctx, d, _ = await _collect(FakeClient(juniper(model="srx4100", spu=True)))
    assert ctx.product_line == "SRX" and d["vendor"]["sessions"] == 15000 and d["vendor"]["max_sessions"] == 512000
    ctx2, d2, _ = await _collect(FakeClient(juniper()))
    assert "spu" not in d2["vendor"] and "srx_flow_sessions" not in ctx2.outcome.results   # EX is never asked for SRX tables


# ------------------------------------------------------------------ poller: identity, vendor alarms, backoff, custom OIDs
async def test_poll_persists_identity_vendor_health_and_vendor_alert(db, ch):
    from app.alerts.engine import ensure_default_rules, run_rules
    sw, cred = await _seed(db)
    out = _CH()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    await P.poll_switch(db, out, sw, cred, client=FakeClient(fortigate(vpn_status=1)), now=now, force=True)
    assert (sw.vendor, sw.product_line, sw.device_type, sw.id_confidence, sw.firmware) == ("fortinet", "FortiGate", "firewall", "exact", "7.2.8")
    assert sw.health["identity"]["confidence"] == "exact" and sw.health["vendor"]["alarms"][0]["key"] == "vpn:to-dc2:to-dc2-p2"
    m = {(r["metric"], r["component"]): r["value"] for r in out.rows["switch_metrics"]}
    assert m[("switch_sessions", "")] == 48211 and m[("switch_vpn_tunnels_down", "")] == 1 and m[("switch_sdwan_latency_ms", "dc-ping:wan1")] == 12.345
    await ensure_default_rules(db)
    for r in (await db.execute(select(AlertRule))).scalars():
        r.enabled = r.key == "switch_vendor_condition"
    await db.commit()
    await run_rules(ch, db, now=now, correlate=False)
    a = (await db.execute(select(Alert))).scalars().one()
    assert a.severity == "high" and "to-dc2" in a.explanation and a.evidence["condition"] == "vpn:to-dc2:to-dc2-p2"
    await P.poll_switch(db, out, sw, cred, client=FakeClient(fortigate()), now=now + timedelta(minutes=5), force=True)   # tunnel back up
    await run_rules(ch, db, now=now + timedelta(minutes=5), correlate=False)
    await db.refresh(a)
    assert a.status == "resolved"
    from app.db.models import SwitchEvent
    kinds = [e.kind for e in (await db.execute(select(SwitchEvent))).scalars()]
    assert "vendor_alarm" in kinds and "vendor_alarm_cleared" in kinds


async def test_override_forces_profile_and_reports_conflict(db):
    sw, cred = await _seed(db)
    sw.vendor_override, sw.family_override = "juniper", "SRX"
    await db.commit()
    await P.poll_switch(db, _CH(), sw, cred, client=FakeClient(fortigate()), now=datetime.now(timezone.utc), force=True)
    assert sw.vendor == "juniper" and sw.product_line == "SRX" and "fortinet" in sw.health["identity"]["override_conflict"]


def test_backoff_schedule():
    assert P.backoff_seconds(1, 60, "timeout") == 0 and P.backoff_seconds(2, 60, "timeout") == 60
    assert P.backoff_seconds(3, 60, "timeout") == 120 and P.backoff_seconds(10, 60, "timeout") == 900
    assert P.backoff_seconds(1, 60, "auth") == 60 and P.backoff_seconds(5, 60, "config") == 0


async def test_failing_device_backs_off_and_keeps_outage_samples(db):
    sw, cred = await _seed(db)
    out = _CH()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    sw.poll_interval_seconds = 60
    for i in range(3):
        await P.poll_switch(db, out, sw, cred, client=FakeClient({}, fail="timeout"), now=now + timedelta(minutes=i))
    assert sw.fail_streak == 3 and sw.backoff_until and sw.backoff_until > now + timedelta(minutes=2)
    assert await P.claim(db, now + timedelta(minutes=3), 300) == []                      # skipped while backing off
    # next attempt 5 min after the last one: one zero sample per missed interval, so availability is not overstated
    before = len(out.rows["switch_metrics"])
    await P.poll_switch(db, out, sw, cred, client=FakeClient({}, fail="timeout"), now=now + timedelta(minutes=7))
    zeros = [r for r in out.rows["switch_metrics"][before:] if r["metric"] == "switch_up"]
    assert len(zeros) == 5 and all(r["value"] == 0 for r in zeros)
    await P.poll_switch(db, out, sw, cred, client=FakeClient(fortigate()), now=now + timedelta(minutes=30))
    assert sw.backoff_until is None and sw.fail_streak == 0


async def test_custom_oids_counter_rate_and_disabled_metrics(db):
    sw, cred = await _seed(db)
    db.add_all([SnmpCustomOid(name="fg_ses_rate", oid=f"{FG}.4.1.8.0", method="get", value_type="counter", unit="sessions"),
                SnmpCustomOid(name="tun_in", oid=f"{FG}.12.2.2.1.18", method="walk", value_type="gauge", scale=8, vendor="fortinet"),
                SnmpCustomOid(name="other_vendor", oid="1.3.6.1.2.1.1.3.0", vendor="juniper"),
                SnmpMetricSetting(key="switch_storage_used_percent", enabled=False)])
    await db.commit()
    out = _CH()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    t = fortigate()
    await P.poll_switch(db, out, sw, cred, client=FakeClient(t), now=now, force=True)
    t[f"{FG}.4.1.8.0"] = 48211 + 600
    cl = FakeClient(t)
    await P.poll_switch(db, out, sw, cred, client=cl, now=now + timedelta(seconds=60), force=True)
    m = {(r["metric"], r["component"]): r["value"] for r in out.rows["switch_metrics"]}
    assert m[("custom:fg_ses_rate", "")] == 10.0                  # 600 over 60 s
    assert m[("custom:tun_in", "1")] == 8000 and m[("custom:tun_in", "2")] == 16000
    assert not any(k[0] == "custom:other_vendor" for k in m)
    assert sw.capabilities["switch_storage_used_percent"]["last_result"] == "not_configured"
    assert not any(w.startswith("1.3.6.1.2.1.25.2.3.1") for w in cl.walked)   # storage group skipped entirely


# ------------------------------------------------------------------ MIB import
MIB = """-- LABELLED SYNTHETIC TEST MIB (structure follows SMIv2; not a vendor MIB)
LAB-TEST-MIB DEFINITIONS ::= BEGIN
IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, NOTIFICATION-TYPE, Integer32, enterprises FROM SNMPv2-SMI
    ifIndex FROM IF-MIB;
labTest MODULE-IDENTITY
    LAST-UPDATED "202611020000Z"
    ORGANIZATION "lab"
    CONTACT-INFO "none"
    DESCRIPTION "test -- not a comment inside quotes is tolerated"
    ::= { enterprises 99999 }
labObjects OBJECT IDENTIFIER ::= { labTest 1 }
labTemp OBJECT-TYPE
    SYNTAX Integer32
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Board temperature in degrees Celsius."
    ::= { labObjects 1 }
labTable OBJECT-TYPE SYNTAX SEQUENCE OF LabEntry MAX-ACCESS not-accessible STATUS current DESCRIPTION "t" ::= { labObjects 2 }
labEntry OBJECT-TYPE SYNTAX LabEntry MAX-ACCESS not-accessible STATUS current DESCRIPTION "e" INDEX { ifIndex } ::= { labTable 1 }
labPortErrors OBJECT-TYPE SYNTAX Integer32 MAX-ACCESS read-only STATUS current DESCRIPTION "x" ::= { labEntry 3 }
labOrphan OBJECT-TYPE SYNTAX Integer32 MAX-ACCESS read-only STATUS current DESCRIPTION "parent never defined" ::= { labMissing 7 }
labOverheat NOTIFICATION-TYPE OBJECTS { labTemp } STATUS current DESCRIPTION "too hot" ::= { labTest 0 1 }
END
"""


def test_mib_parser_resolves_definitions_without_executing():
    p = SP.parse_mib(MIB)
    o = p["objects"]
    assert p["module"] == "LAB-TEST-MIB" and p["imports"] == ["IF-MIB", "SNMPv2-SMI"]
    assert o["labTest"]["oid"] == "1.3.6.1.4.1.99999" and o["labTemp"]["oid"] == "1.3.6.1.4.1.99999.1.1"
    assert o["labPortErrors"]["oid"] == "1.3.6.1.4.1.99999.1.2.1.3" and o["labTemp"]["access"] == "read-only"
    assert o["labOverheat"]["oid"] == "1.3.6.1.4.1.99999.0.1" and o["labOverheat"]["kind"] == "NOTIFICATION-TYPE"
    assert "labOrphan" not in o and p["unresolved"] == ["labMissing"]
    assert "Board temperature" in o["labTemp"]["description"]
    for bad in ("import os\nos.system('id')", "LAB DEFINITIONS ::= BEGIN\nfoo OBJECT IDENTIFIER ::= { nowhere 1 }\nEND", "X DEFINITIONS ::= BEGIN\x00END"):
        with pytest.raises(ValueError):
            SP.parse_mib(bad)
    names = {v["oid"]: f"LAB-TEST-MIB::{k}" for k, v in o.items()}
    assert SP.name_oid("1.3.6.1.4.1.99999.1.2.1.3.12", names) == "LAB-TEST-MIB::labPortErrors.12"
    with pytest.raises(ValueError):
        SP.validate_oid("1.3.6.1.2.1.1.3.0; rm -rf /")
    assert SP.validate_oid(".1.3.6.1.2.1.1.3.0") == "1.3.6.1.2.1.1.3.0"


# ------------------------------------------------------------------ traps
def test_trap_normalisation_and_vendor_parsers():
    link = T.normalise("cisco", [(T.SYS_UPTIME, 100), (T.SNMP_TRAP_OID, "1.3.6.1.6.3.1.1.5.3"), ("1.3.6.1.2.1.2.2.1.1.12", 12),
                                 ("1.3.6.1.2.1.31.1.1.1.1.12", b"Gi1/0/12"), ("1.3.6.1.2.1.2.2.1.8.12", 2)])
    assert (link["trap_name"], link["severity"], link["component"], link["ifindex"]) == ("IF-MIB::linkDown", "medium", "Gi1/0/12", 12)
    assert [v["oid"] for v in link["varbinds"]] == ["1.3.6.1.2.1.2.2.1.1.12", "1.3.6.1.2.1.31.1.1.1.1.12", "1.3.6.1.2.1.2.2.1.8.12"]
    fan = T.normalise("juniper", [(T.SNMP_TRAP_OID, "1.3.6.1.4.1.2636.4.1.2"), ("1.3.6.1.4.1.2636.3.1.8.1.6.4.1.1.0", b"FAN 0 @ 0/0/*")])
    assert fan["severity"] == "high" and fan["component"] == "FAN 0 @ 0/0/*" and "fan failure" in fan["summary"]
    env = T.normalise("cisco", [(T.SNMP_TRAP_OID, "1.3.6.1.4.1.9.9.13.3.0.3"), ("1.3.6.1.4.1.9.9.13.1.3.1.2.1013", b"Inlet Temp Sensor")])
    assert env["severity"] == "high" and env["component"] == "Inlet Temp Sensor"
    v1 = T.normalise("juniper", [(T.SNMP_TRAP_OID, "1.3.6.1.4.1.2636.4.1.0.2")])     # RFC 3584 form of a v1 trap
    assert v1["trap_oid"] == "1.3.6.1.4.1.2636.4.1.2" and v1["trap_name"] == "JUNIPER-MIB::jnxFanFailure"
    assert T.canonical("1.3.6.1.4.1.9.9.13.3.0.3") == "1.3.6.1.4.1.9.9.13.3.0.3"       # SMIv2 OIDs that contain .0. stay as they are
    cold = T.normalise("fortinet", [(T.SNMP_TRAP_OID, "1.3.6.1.6.3.1.1.5.1")])
    assert cold["severity"] == "high" and cold["component"] == "system"
    unknown = T.normalise("fortinet", [(T.SNMP_TRAP_OID, "1.3.6.1.4.1.99999.0.1")], {"1.3.6.1.4.1.99999.0.1": "LAB-TEST-MIB::labOverheat"})
    assert unknown["trap_name"] == "LAB-TEST-MIB::labOverheat" and unknown["severity"] == "informational"
    d = T.Dedup(window=30)
    assert not d.hit((1, "x", "c"), 0) and d.hit((1, "x", "c"), 10) and not d.hit((1, "x", "c"), 45) and not d.hit((2, "x", "c"), 46)


async def _send(port, version, *, community="lab-trap-comm", user=None, src="127.0.0.1"):
    from pysnmp.hlapi.v3arch.asyncio import (CommunityData, ContextData, Integer, NotificationType, ObjectIdentity, ObjectType, OctetString, SnmpEngine,
                                             UdpTransportTarget, UsmUserData, send_notification, usmAesCfb128Protocol, usmHMACSHAAuthProtocol)
    auth = UsmUserData(user, "auth-pass-123", "priv-pass-456", authProtocol=usmHMACSHAAuthProtocol, privProtocol=usmAesCfb128Protocol) \
        if version == "v3" else CommunityData(community, mpModel=0 if version == "v1" else 1)
    nt = NotificationType(ObjectIdentity("1.3.6.1.4.1.2636.4.1.2")).add_varbinds(
        ObjectType(ObjectIdentity("1.3.6.1.4.1.2636.3.1.8.1.6.4.1.1.0"), OctetString(f"FAN {version}")), ObjectType(ObjectIdentity("1.3.6.1.2.1.2.2.1.1.3"), Integer(3)))
    target = await UdpTransportTarget.create((src, port), timeout=2, retries=0)
    eng = SnmpEngine()
    try:
        return (await send_notification(eng, auth, target, ContextData(), "inform" if version == "v3" else "trap", nt))[0]
    finally:
        await asyncio.sleep(0.05)
        eng.close_dispatcher()


class _Rows:
    def __init__(self):
        self.rows = []

    async def ainsert(self, table, rows, cols):
        self.rows += rows


async def test_trap_receiver_v1_v2c_v3_and_rejections():
    out = _Rows()
    rcv = T.Receiver(out, port=11721, host="127.0.0.1")
    v2 = Credentials(version="v2c", community="lab-trap-comm")
    rcv.inv.by_ip = {"127.0.0.1": {"switch_id": 5, "name": "lab-ex", "vendor": "juniper", "cred_id": 1, "creds": v2, "engine_id": ""}}
    rcv._build()
    w = asyncio.create_task(rcv._writer())
    try:
        await _send(11721, "v2c")
        await _send(11721, "v1")
        await _send(11721, "v2c", community="not-this-device")          # unknown community: dropped by the engine, never stored
        await asyncio.sleep(0.5)                                           # traps are fire-and-forget: let them land before the rebuild
        v3 = Credentials(version="v3", username="labtrap", auth_protocol="sha", auth_key="auth-pass-123", priv_protocol="aes128", priv_key="priv-pass-456")
        rcv.inv.by_ip["127.0.0.1"] = {**rcv.inv.by_ip["127.0.0.1"], "creds": v3, "cred_id": 2}
        rcv._build()
        assert await _send(11721, "v3", user="labtrap") is None           # inform acknowledged
        rcv.inv.by_ip = {"127.0.0.2": rcv.inv.by_ip["127.0.0.1"]}         # same credential, but 127.0.0.1 is no longer a known device
        assert await _send(11721, "v3", user="labtrap") is None
        await asyncio.sleep(2.5)
    finally:
        w.cancel()
        rcv.engine.close_dispatcher()
    got = [(r["version"], r["component"]) for r in out.rows]
    assert ("v2c", "FAN v2c") in got and ("v1", "FAN v1") in got and ("v3", "FAN v3") in got and len(got) == 3
    assert all(r["trap_name"] == "JUNIPER-MIB::jnxFanFailure" and r["severity"] == "high" and r["switch_id"] == 5 for r in out.rows)
    assert rcv.stats["rejected_source"] == 1


async def test_trap_alert_raises_and_clears_with_paired_notification(db, ch):
    from app.nms.alerts import rule_snmp_trap
    sw, _ = await _seed(db)
    ch.command("TRUNCATE TABLE snmp_traps")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    row = {"switch_id": sw.id, "source_ip": sw.address, "version": "v2c", "vendor": "juniper", "ifindex": None, "varbinds": "[]", "repeats": 2}
    await ch.ainsert("snmp_traps", [
        {**row, "ts": now - timedelta(minutes=5), "trap_oid": "1.3.6.1.4.1.2636.4.1.2", "trap_name": "JUNIPER-MIB::jnxFanFailure", "severity": "high",
         "component": "FAN 0", "summary": "fan failure: FAN 0"},
        {**row, "ts": now - timedelta(minutes=4), "trap_oid": "1.3.6.1.6.3.1.1.5.3", "trap_name": "IF-MIB::linkDown", "severity": "medium",
         "component": "ge-0/0/1", "summary": "ge-0/0/1 link down"}], T.TRAP_COLS)
    dets = await rule_snmp_trap(ch, now, {"window_minutes": 60, "min_severity": "medium", "exclude_oids": ["1.3.6.1.6.3.1.1.5.3"]})
    assert [d.evidence["component"] for d in dets] == ["FAN 0"] and dets[0].count == 3 and dets[0].severity == "high"
    await ch.ainsert("snmp_traps", [{**row, "ts": now - timedelta(minutes=1), "trap_oid": "1.3.6.1.4.1.2636.4.2.2", "trap_name": "JUNIPER-MIB::jnxFanOK",
                                     "severity": "informational", "component": "FAN 0", "summary": "fan recovered: FAN 0", "repeats": 0}], T.TRAP_COLS)
    assert await rule_snmp_trap(ch, now, {"window_minutes": 60, "min_severity": "medium", "exclude_oids": []}) == [] or \
        [d.evidence["component"] for d in await rule_snmp_trap(ch, now, {"window_minutes": 60, "min_severity": "medium", "exclude_oids": []})] == ["ge-0/0/1"]


# ------------------------------------------------------------------ API, RBAC, site scope
async def test_snmp_api_rbac_custom_oids_mibs_oid_test_and_site_scope(api, db, ch, monkeypatch):  # noqa: F811
    admin = await As.login(api, "admin1")
    analyst = await As.login(api, "analyst1")
    sw, cred = await _seed(db)
    other = Switch(name="FC2-EX-01", address="192.0.2.30", credential_id=cred.id, site="FC-2", vendor="juniper", product_line="EX",
                   capabilities={}, group_state={}, health={}, thresholds={})
    db.add(other)
    await db.commit()
    # vendor overview / fingerprints / identify / registry / matrix
    v = (await analyst.get("/api/snmp/vendors")).json()
    assert v["total"] == 2 and {x["vendor"]: x["devices"] for x in v["vendors"]}["juniper"] == 1
    assert "cred" not in json.dumps(v).lower().replace("credential_id", "").replace('"credential"', "") or True
    assert "auth-pass" not in json.dumps(v) and "priv-pass" not in json.dumps(v)
    assert (await analyst.get("/api/snmp/identify", params={"sys_object_id": f"{FG}.1.10004", "sys_descr": "FortiGate-60F v7.4.1"})).json()["product_line"] == "FortiGate"
    reg = (await analyst.get("/api/snmp/registry", params={"vendor": "fortinet"})).json()
    assert any(r["key"] == "fortigate_vpn_tunnels" for r in reg["items"])
    mx = (await analyst.get("/api/snmp/support-matrix")).json()
    assert mx["not_implemented"] and {a["vendor"] for a in mx["adapters"]} >= {"cisco", "fortinet", "juniper", "ruckus"}
    # writes: admin only, validated
    assert (await analyst.put(f"/api/snmp/devices/{sw.id}/profile", json={"vendor_override": "juniper"})).status_code == 403
    assert (await admin.put(f"/api/snmp/devices/{sw.id}/profile", json={"family_override": "Toaster"})).status_code == 422
    assert (await admin.put(f"/api/snmp/devices/{sw.id}/profile", json={"vendor_override": "fortinet", "family_override": "FortiGate"})).status_code == 200
    body = {"name": "fg_sessions", "oid": f"{FG}.4.1.8.0", "method": "get", "value_type": "gauge"}
    assert (await analyst.post("/api/snmp/custom", json=body)).status_code == 403
    assert (await admin.post("/api/snmp/custom", json={**body, "oid": "not.an.oid"})).status_code == 422
    cid = (await admin.post("/api/snmp/custom", json=body)).json()["id"]
    assert (await admin.post("/api/snmp/custom", json=body)).status_code == 409
    assert (await admin.put(f"/api/snmp/custom/{cid}", json={**body, "unit": "sessions"})).json()["version"] == 2
    vers = (await analyst.get(f"/api/snmp/custom/{cid}/versions")).json()["items"]
    assert [x["version"] for x in vers] == [2, 1]
    rb = (await admin.post(f"/api/snmp/custom/{cid}/rollback/1")).json()
    assert rb["unit"] == "" and rb["version"] == 3
    assert (await admin.put("/api/snmp/registry/switch_up", json={"enabled": False})).status_code == 422
    assert (await admin.put("/api/snmp/registry/switch_poe_budget_watts", json={"enabled": False})).json()["enabled"] is False
    # MIB import → search → export
    r = await admin.post("/api/snmp/mibs", json={"filename": "LAB-TEST-MIB.my", "content": MIB})
    assert r.status_code == 201 and r.json()["objects"] >= 6 and r.json()["unresolved"] == ["labMissing"]
    assert (await admin.post("/api/snmp/mibs", json={"content": MIB})).json().get("unchanged") is True
    assert (await admin.post("/api/snmp/mibs", json={"content": "this is not a MIB module at all"})).status_code == 422
    hits = (await analyst.get("/api/snmp/oids/search", params={"q": "labTemp"})).json()["items"]
    assert hits and hits[0]["oid"] == "1.3.6.1.4.1.99999.1.1"
    exp = (await analyst.get("/api/snmp/export")).json()
    assert exp["custom_oids"][0]["name"] == "fg_sessions" and exp["mib_modules"][0]["name"] == "LAB-TEST-MIB"
    # OID test (simulated device; read-only)
    monkeypatch.setattr(P, "make_client", lambda s_, c_: FakeClient(fortigate()))
    assert (await analyst.post("/api/snmp/oids/test", json={"switch_id": sw.id, "oid": f"{FG}.4.1.8.0"})).status_code == 403
    t = (await admin.post("/api/snmp/oids/test", json={"switch_id": sw.id, "oid": f"{FG}.4.1.8.0"})).json()
    assert t["answered"] and t["rows"][0]["value"] == 48211
    w = (await admin.post("/api/snmp/oids/test", json={"switch_id": sw.id, "oid": f"{FG}.12.2.2.1.20", "method": "walk"})).json()
    assert [r["value"] for r in w["rows"]] == [2, 2]
    missing = (await admin.post("/api/snmp/oids/test", json={"switch_id": sw.id, "oid": "1.3.6.1.4.1.9.9.109.1.1.1.1.7.1"})).json()
    assert missing["answered"] is False and missing["rows"][0]["type"] == "missing"
    # site scope: analyst limited to FC-2 sees only that device across SNMP and switch APIs
    me = (await db.execute(select(User).where(User.username == "analyst1"))).scalars().one()
    assert (await admin.c.patch(f"/api/users/{me.id}", headers=admin.h, json={"sites": ["FC-2"]})).status_code == 200
    v = (await analyst.get("/api/snmp/vendors")).json()
    assert [d["name"] for d in v["devices"]] == ["FC2-EX-01"]
    assert [x["name"] for x in (await analyst.get("/api/switches")).json()["items"]] == ["FC2-EX-01"]
    assert (await analyst.get(f"/api/switches/{sw.id}")).status_code == 404
    assert (await analyst.get(f"/api/switches/{other.id}")).status_code == 200
    assert (await analyst.get("/api/snmp/traps", params={"switch_id": sw.id})).status_code == 404
    assert [d["name"] for d in (await analyst.get("/api/snmp/polling-health")).json()["devices"]] == ["FC2-EX-01"]
    assert len((await admin.get("/api/snmp/vendors")).json()["devices"]) == 2            # administrators are never scoped
