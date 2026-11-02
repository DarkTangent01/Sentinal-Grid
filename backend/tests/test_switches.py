"""Switch monitoring: identification, SNMP client (real local agent: v2c, SNMPv3 auth/priv, timeouts), OID normalisation
(Cisco C9300 / Ruckus ICX fixtures), unsupported OIDs, counter / rate maths (wrap, reset, restart, gaps), capability and
coverage status, polling persistence and events, alerts with recovery, API (RBAC, validation, pagination, no secrets)."""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.db.models import Alert, AlertRule, Firewall, Switch, SwitchCredential, SwitchEvent, SwitchInterface, SwitchMac, SwitchNetwork, SwitchPollRun
from app.switches import collect as C
from app.switches import poller as P
from app.switches import rates as R
from app.switches.registry import Outcome, coverage, merge_capabilities, status_of
from app.switches.snmp import Credentials, PysnmpClient, SnmpError

from .snmp_sim import FakeClient, UdpAgent
from .switch_fixtures import cisco_c9300, ruckus_icx7150
from .test_api import api, login  # noqa: F401
from .test_iac import As

T0 = datetime(2026, 10, 28, 10, 0, tzinfo=timezone.utc)


# ------------------------------------------------------------------ identification
def test_identify_cisco_ruckus_generic():
    c = C.identify("1.3.6.1.4.1.9.1.2694", "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE")
    assert c["vendor"] == "cisco" and c["os"] == "IOS-XE" and c["firmware"] == "17.9.4a"
    old = C.identify("1.3.6.1.4.1.9.1.1208", "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E8, RELEASE SOFTWARE (fc1)")
    assert old["vendor"] == "cisco" and old["os"] == "IOS" and old["firmware"] == "15.2(7)E8"
    r = C.identify("1.3.6.1.4.1.1991.1.3.62.2.3.1.1", "Ruckus ICX7150-48P-4X10GR, IronWare Version 08.0.95dT213 Compiled on Mar 1 2023")
    assert r["vendor"] == "ruckus" and r["model"] == "ICX7150-48P-4X10GR" and r["family"] == "ICX 7150" and r["firmware"] == "08.0.95dT213"
    assert C.identify("1.3.6.1.4.1.1991.1.3.70.1", "Brocade ICX 7450-48 Switch")["model"] == "ICX7450-48"
    j = C.identify("1.3.6.1.4.1.2636.1.1.1.2.57", "Juniper Networks, Inc. ex2300-24p")   # Juniper has its own adapter now
    assert j["vendor"] == "juniper" and j["model"] == "ex2300-24p" and j["product_line"] == "EX"
    g = C.identify("1.3.6.1.4.1.8072.3.2.10", "Linux appliance 6.1")
    assert g["vendor"] == "generic" and g["model"] == "" and g["confidence"] == "unknown"
    assert C.family_of("cisco", "C9300-48P") == "Catalyst 9300" and C.family_of("cisco", "C9200L-24P-4G") == "Catalyst 9200L"
    assert C.family_of("cisco", "WS-C3850-48P") == "Catalyst 3850"


def test_value_helpers():
    assert C.portlist(bytes([0b10100000, 0b00000001])) == [1, 3, 16]
    assert C.bits(bytes([0xBC])) == {"activity": True, "timeout": False, "aggregation": True, "synchronization": True, "collecting": True,
                                     "distributing": True, "defaulted": False, "expired": False}
    assert C.bridge_id(b"\x80\x00\x02\xc0\x00\x00\x95\x00") == "32768/02:c0:00:00:95:00"
    assert C.text(b"Gi1/0/1\x00 ") == "Gi1/0/1" and C.mac(b"\x02\x00\x00\x00\x00\x01") == "02:00:00:00:00:01"


# ------------------------------------------------------------------ rates
def test_counter_delta_wrap_reset_and_plausibility():
    assert R.counter_delta(100, 400, 64, 60) == (300, "")
    # 32-bit wrap: 10 MB before the wrap point → 20 MB after = 30 MB in 60 s on a 100 Mbit/s port (12.5 MB/s) is plausible
    d, why = R.counter_delta(2 ** 32 - 10_000_000, 20_000_000, 32, 60, 12_500_000)
    assert d == 30_000_000 and why == ""
    # a "wrap" that implies more than the link speed is a reset, not a wrap
    assert R.counter_delta(4_000_000_000, 5, 32, 60, 12_500)[0] is None
    assert R.counter_delta(500, 100, 64, 60) == (None, "counter reset")
    assert R.counter_delta(0, 10 ** 12, 64, 60, 125_000_000)[1].startswith("implausible")
    assert R.counter_delta(None, 5, 64, 60) == (None, "no previous sample")


def _s(name="Gi1/0/1", typ=6, speed=1_000_000_000, inb=0, outb=0, hc=True, disc=None, errs=0):
    return {"name": name, "type": typ, "oper": "up", "speed_bps": speed, "disc": disc, "hc": hc,
            "c": {"in_octets": inb, "out_octets": outb, "in_pkts": inb // 500, "out_pkts": outb // 500, "in_errors": errs, "out_errors": 0,
                  "in_discards": 0, "out_discards": 0, "crc": errs}}


def test_interface_rates_valid_reset_restart_gap_and_util():
    prev, cur = _s(inb=0, outb=0), _s(inb=375_000_000, outb=75_000_000, errs=25)
    r = R.interface_rates(prev, cur, elapsed=60, uptime_prev=1000, uptime_cur=7000, max_gap=300)
    assert r["rx_bps"] == pytest.approx(50_000_000) and r["tx_bps"] == pytest.approx(10_000_000)
    assert r["rx_util"] == pytest.approx(5.0) and r["in_errors"] == 25 and r["crc"] == 25 and r["flags"] == 0
    # restart: no rate, flagged
    r = R.interface_rates(prev, cur, elapsed=60, uptime_prev=7000, uptime_cur=100, max_gap=300)
    assert r["rx_bps"] is None and r["flags"] & R.RESET and "restarted" in r["reason"]
    # ifIndex renumbered to another interface
    r = R.interface_rates(prev, _s(name="Gi1/0/2", inb=10), elapsed=60, uptime_prev=1, uptime_cur=2, max_gap=300)
    assert r["rx_bps"] is None and "now names Gi1/0/2" in r["reason"]
    # counter discontinuity
    r = R.interface_rates(_s(disc=5), _s(disc=9, inb=10), elapsed=60, uptime_prev=1, uptime_cur=2, max_gap=300)
    assert r["rx_bps"] is None and "discontinuity" in r["reason"]
    # data gap: average rate kept, flagged GAP
    r = R.interface_rates(prev, cur, elapsed=900, uptime_prev=1, uptime_cur=2, max_gap=300)
    assert r["rx_bps"] == pytest.approx(375_000_000 * 8 / 900) and r["flags"] & R.GAP
    # SVI: no utilisation (speed meaning unknown)
    r = R.interface_rates(_s(typ=136), _s(typ=136, inb=1000), elapsed=60, uptime_prev=1, uptime_cur=2, max_gap=300)
    assert r["rx_util"] is None and r["flags"] & R.UNCERTAIN_UTIL
    # no speed: no utilisation
    r = R.interface_rates(_s(speed=None), _s(speed=None, inb=1000), elapsed=60, uptime_prev=1, uptime_cur=2, max_gap=300)
    assert r["rx_util"] is None and r["flags"] & R.NO_SPEED
    # 32-bit counters on a 10G port polled every 60 s can wrap more than once: utilisation uncertain
    r = R.interface_rates(_s(speed=10 ** 10, hc=False), _s(speed=10 ** 10, hc=False, inb=1000), elapsed=60, uptime_prev=1, uptime_cur=2, max_gap=300)
    assert r["flags"] & R.UNCERTAIN_UTIL and r["flags"] & R.COUNTER32
    assert R.speed_of(10000, 4294967295) == (10_000_000_000, "ifHighSpeed")
    assert R.speed_of(0, 4294967295)[0] is None and R.speed_of(None, 100_000_000) == (100_000_000, "ifSpeed")


# ------------------------------------------------------------------ registry / coverage
def test_capability_status_and_coverage():
    o = Outcome()
    o.ok("switch_up")
    o.ok("switch_cpu_utilization_percent")
    o.missing("switch_temperature_celsius")
    o.error("switch_fan_status", "no SNMP response")
    o.not_configured("switch_mac_table", "needs VLAN contexts")
    groups = {"system", "cpu_memory", "environment", "mac_table"}
    iv = {g: 60 for g in ("system", "cpu_memory", "environment", "mac_table", "interfaces")}
    caps = merge_capabilities({}, o, groups, T0, "cisco", iv)
    assert status_of(caps["switch_up"], T0, 60) == "healthy"
    assert status_of(caps["switch_temperature_celsius"], T0, 60) == "unsupported"
    assert status_of(caps["switch_fan_status"], T0, 60) == "failed"
    assert status_of(caps["switch_mac_table"], T0, 60) == "not_configured"
    assert status_of(caps["switch_cpu_utilization_percent"], T0 + timedelta(minutes=10), 60) == "stale"
    # supported before, missing now → unavailable (e.g. sensor removed); never reported as 0
    o2 = Outcome()
    o2.missing("switch_cpu_utilization_percent")
    caps = merge_capabilities(caps, o2, {"cpu_memory"}, T0 + timedelta(minutes=1), "cisco", iv)
    assert status_of(caps["switch_cpu_utilization_percent"], T0, 60) == "unavailable"
    cov = coverage(caps, T0 + timedelta(minutes=1), iv)
    assert cov["counts"]["unsupported"] == 1 and cov["counts"]["not_configured"] == 1
    assert cov["percent"] == pytest.approx(100 * 1 / 3, rel=0.01)  # healthy switch_up of (up, cpu unavailable, fan failed)
    # a disabled group is not_configured
    caps = merge_capabilities(caps, Outcome(), set(), T0, "cisco", {**iv, "poe": 0})
    assert status_of(caps["switch_poe_budget_watts"], T0, 0) == "not_configured"


# ------------------------------------------------------------------ collectors / normalisation
async def _collect(client, vendor="generic"):
    ctx = C.Ctx(client=client, vendor=vendor, outcome=Outcome())
    data, report, ran = await P.run_groups(ctx, P.ORDER)
    return ctx, data, report


async def test_cisco_c9300_normalisation():
    t, ctxs = cisco_c9300(0)
    cl = FakeClient(t, contexts=ctxs)
    ctx, d, rep = await _collect(cl)
    assert ctx.vendor == "cisco" and all(r["ok"] for r in rep.values())
    ident = d["identity"]
    assert ident["vendor"] == "cisco" and ident["model"] == "C9300-48P" and ident["serials"] == ["FOC0000X1AB", "FOC0000X1AC"]
    assert ident["firmware"] == "17.9.4a" and ident["family"] == "Catalyst 9300"
    assert d["cpu"]["pct"] == 12 and d["cpu"]["cpus"][0]["name"] == "Switch 1"
    assert d["memory"]["pct"] == pytest.approx(37.5) and d["memory"]["source"].startswith("CISCO-PROCESS-MIB")
    env = d["environment"]
    assert env["temperatures"][0]["celsius"] == 31 and env["temperatures"][0]["threshold"] == 46
    assert [p["state"] for p in env["psus"]] == ["ok", "absent"]
    assert [m["role"] for m in d["stack"]["members"]] == ["active", "member"] and d["stack"]["ring_redundant"] is True
    assert d["poe"]["budget_w"] == 874 and d["poe"]["used_w"] == 61
    gi1 = next(p for p in d["poe"]["ports"] if p["key"] == "1.1")
    assert gi1["ifindex"] == 9 and gi1["power_w"] == pytest.approx(6.1) and gi1["status"] == "delivering" and gi1["class"] == 3
    lag = d["lacp"]["lags"][65]
    assert sorted(m["ifindex"] for m in lag["members"]) == [37, 38] and all(m["in_bundle"] for m in lag["members"])
    assert d["vlans"][10]["untagged"] == [9, 10, 12] and d["vlans"][10]["tagged"] == [37, 38, 65] and 1002 not in d["vlans"]
    assert d["port_vlans"][37] == {"mode": "trunk", "native_vlan": 1, "allowed": 3}
    assert d["stp"]["mode"] == "rapid-pvst+" and set(d["stp"]["instances"]) == {"default", "vlan1", "vlan10", "vlan20"}
    assert d["stp"]["instances"]["default"]["root_port_ifindex"] == 65 and not d["stp"]["is_root"]
    assert {(m["mac"], m["vlan"], m["ifindex"]) for m in d["macs"]} == {("02:00:00:00:a1:01", 10, 9), ("02:00:00:00:a1:02", 10, 10), ("02:00:00:00:c0:01", 10, 65)}
    gi2 = d["interfaces"][10]
    assert gi2["name"] == "Gi1/0/2" and gi2["hc"] and gi2["c"]["crc"] == 2 and gi2["duplex"] == "full" and gi2["alias"] == "SCANNER-12"
    assert d["routing"]["route_count"] == 12 and d["routing"]["ip_interfaces"][0]["ip"] == "10.20.10.1"
    res = ctx.outcome.results
    assert res["switch_ospf_neighbors"]["result"] == "missing" and res["switch_interface_octets_32"]["result"] == "not_configured"
    # never asks a Cisco switch for Ruckus OIDs
    assert not [w for w in cl.walked if w.startswith("1.3.6.1.4.1.1991.")]


async def test_ruckus_icx_normalisation():
    cl = FakeClient(ruckus_icx7150(0))
    ctx, d, rep = await _collect(cl)
    assert ctx.vendor == "ruckus" and all(r["ok"] for r in rep.values())
    assert d["identity"]["model"] == "ICX7150-48P-4X10GR" and d["identity"]["serials"] == ["FEK0000Q0A1", "FEK0000Q0A2"]
    assert d["cpu"]["pct"] == 9 and d["cpu"]["cpus"][0]["id"] == "1.1"  # the 1-minute row, not 1 s / 5 s / 300 s
    assert d["memory"]["pct"] == 41 and d["memory"]["total_bytes"] == 1073741824
    temps = d["environment"]["temperatures"]
    assert [t["celsius"] for t in temps] == [38.0, 40.0] and temps[0]["threshold"] == 85.0  # 0.5 °C units
    assert [m["role"] for m in d["stack"]["members"]] == ["active", "standby"] and d["stack"]["topology"] == "ring"
    assert d["poe"]["budget_w"] == 740 and d["poe"]["used_w"] == 50
    assert {p["ifindex"]: p["power_w"] for p in d["poe"]["ports"]} == {1: pytest.approx(4.1), 3: pytest.approx(7.2)}
    assert d["vlans"][10]["untagged"] == [1, 2] and d["vlans"][10]["tagged"] == [3] and d["vlans"][20]["tagged"] == [3]
    assert d["port_vlans"][3]["mode"] == "trunk" and d["port_vlans"][1] == {"mode": "access", "access_vlan": 10, "native_vlan": None, "allowed": None}
    assert {(m["mac"], m["vlan"]) for m in d["macs"]} == {("02:00:00:00:b1:01", 10), ("02:00:00:00:b1:02", 10)}
    assert d["stp"]["mode"] == "rstp" and d["stp"]["is_root"]
    assert not d["interfaces"][5]["hc"] and d["interfaces"][5]["c"]["in_octets"] == 2 ** 32 - 10_000_000
    res = ctx.outcome.results
    assert res["switch_route_count"]["result"] == "missing" and res["switch_interface_duplex"]["result"] == "missing"
    # never asks a Ruckus switch for Cisco OIDs
    assert not [w for w in cl.walked if w.startswith("1.3.6.1.4.1.9.")]


async def test_unsupported_tables_are_missing_not_zero():
    t = {k: v for k, v in ruckus_icx7150(0).items() if not k.startswith(("1.3.6.1.4.1.1991.1.1.2.14", "1.3.6.1.4.1.1991.1.1.2.11",
                                                                        "1.3.6.1.4.1.1991.1.1.2.1.5", "1.3.6.1.2.1.105"))}
    ctx, d, _ = await _collect(FakeClient(t))
    assert d["poe"] is None and d["cpu"] is None and d["memory"] is None
    for k in ("switch_poe_budget_watts", "switch_cpu_utilization_percent", "switch_memory_utilization_percent"):
        assert ctx.outcome.results[k]["result"] == "missing"


async def test_failing_group_does_not_stop_others():
    t, ctxs = cisco_c9300(0)
    cl = FakeClient(t, contexts=ctxs, broken_prefixes=("1.3.6.1.4.1.9.9.13",))
    ctx, d, rep = await _collect(cl)
    assert rep["environment"]["ok"] is False and rep["environment"]["kind"] == "timeout"
    assert rep["interfaces"]["ok"] and rep["stack"]["ok"] and d["cpu"]["pct"] == 12
    assert ctx.outcome.results["switch_fan_status"]["result"] == "error"


async def test_cisco_per_vlan_context_not_configured():
    t, _ = cisco_c9300(0)
    ctx, d, rep = await _collect(FakeClient(t, contexts={}))  # contexts not readable → empty
    assert d["macs"] is None or d["macs"] == []
    assert ctx.outcome.results["switch_mac_table"]["result"] in ("missing", "not_configured")


# ------------------------------------------------------------------ real SNMP agent (UDP on localhost)
async def test_real_agent_v2c_v3_auth_priv_and_errors():
    tree, _ = cisco_c9300(0)
    agent = await UdpAgent(tree, v3_user="siem-ro").start()
    try:
        v2 = PysnmpClient("127.0.0.1", Credentials("v2c", community="public-test"), port=agent.port, timeout=1, retries=0)
        r = await v2.get(["1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.99.0"])
        assert r["1.3.6.1.2.1.1.3.0"] == 864000000 and r["1.3.6.1.2.1.1.5.0"] == b"WH1-ACC-SW01" and repr(r["1.3.6.1.2.1.1.99.0"]) == "MISSING"
        cols = await v2.walk_multi(["1.3.6.1.2.1.31.1.1.1.1", "1.3.6.1.2.1.31.1.1.1.6"])
        assert [v for _, v in cols["1.3.6.1.2.1.31.1.1.1.1"]][:2] == [b"Gi1/0/1", b"Gi1/0/2"] and len(cols["1.3.6.1.2.1.31.1.1.1.6"]) == 8
        # full collection over the wire
        ctx = C.Ctx(client=v2, vendor="generic", outcome=Outcome(), snmp_version="v2c")
        data, rep, _ = await P.run_groups(ctx, ["system", "interfaces", "cpu_memory", "environment", "stack"])
        assert ctx.vendor == "cisco" and data["cpu"]["pct"] == 12 and data["interfaces"][65]["type"] == 161 and data["interfaces"][65]["hc"]
        good = Credentials("v3", username="siem-ro", auth_protocol="sha", auth_key="auth-pass-123", priv_protocol="aes128", priv_key="priv-pass-456")
        assert good.security_level == "authPriv"
        v3 = PysnmpClient("127.0.0.1", good, port=agent.port, timeout=1, retries=0)
        assert (await v3.get(["1.3.6.1.2.1.1.5.0"]))["1.3.6.1.2.1.1.5.0"] == b"WH1-ACC-SW01"
        assert len(await v3.walk("1.3.6.1.2.1.2.2.1.2")) == 8
        bad = PysnmpClient("127.0.0.1", Credentials("v3", username="siem-ro", auth_protocol="sha", auth_key="wrong-pass-123", priv_protocol="aes128",
                                                    priv_key="priv-pass-456"), port=agent.port, timeout=1, retries=0)
        with pytest.raises(SnmpError) as e:
            await bad.get(["1.3.6.1.2.1.1.5.0"])
        assert e.value.kind == "auth" and "wrong-pass" not in e.value.message
        wrong_comm = PysnmpClient("127.0.0.1", Credentials("v2c", community="nope-nope"), port=agent.port, timeout=0.3, retries=1)
        with pytest.raises(SnmpError) as e:
            await wrong_comm.get(["1.3.6.1.2.1.1.5.0"])
        assert e.value.kind == "timeout" and "2 attempts" in e.value.message and "nope" not in e.value.message
    finally:
        agent.stop()


def test_credentials_validation():
    with pytest.raises(SnmpError):
        Credentials("v3", username="u", auth_protocol="sha", auth_key="short", priv_protocol="none").validate()
    with pytest.raises(SnmpError):
        Credentials("v3", username="u", auth_protocol="none", priv_protocol="aes128", priv_key="12345678").validate()
    with pytest.raises(SnmpError):
        Credentials("v2c", community="").validate()
    Credentials("v3", username="u", auth_protocol="sha256", auth_key="12345678", priv_protocol="aes256", priv_key="87654321").validate()


# ------------------------------------------------------------------ polling with persistence
async def _seed(db, vendor_fixture="cisco"):
    from app.security import TokenCipher  # noqa: F401
    db.add(SwitchNetwork(cidr="192.0.2.0/24", site="WH1"))
    cred = SwitchCredential(name="ro-v3", version="v3", username="siem-ro", auth_protocol="sha", priv_protocol="aes128",
                            secret_ciphertext=P.seal_secret({"auth_key": "auth-pass-123", "priv_key": "priv-pass-456"}))
    db.add(cred)
    await db.flush()
    sw = Switch(name="WH1-ACC-SW01", address="192.0.2.10", credential_id=cred.id, site="WH1", capabilities={}, group_state={}, health={},
                thresholds={})
    db.add(sw)
    await db.commit()
    return sw, cred


class _CH:
    def __init__(self):
        self.rows: dict[str, list] = {}

    async def ainsert(self, table, rows, cols):
        self.rows.setdefault(table, []).extend(rows)


async def test_poll_persists_rates_events_and_capabilities(db):
    sw, cred = await _seed(db)
    ch = _CH()
    t, ctxs = cisco_c9300(0)
    r = await P.poll_switch(db, ch, sw, cred, client=FakeClient(t, contexts=ctxs), now=T0)
    assert r["ok"], r
    assert sw.vendor == "cisco" and sw.model == "C9300-48P" and sw.state == "up" and sw.firmware == "17.9.4a"
    assert sw.cpu_pct == 12 and sw.poe_budget_w == 874 and sw.if_total == 6 and sw.if_up == 5
    gi1 = (await db.execute(select(SwitchInterface).where(SwitchInterface.switch_id == sw.id, SwitchInterface.ifindex == 9))).scalars().one()
    assert gi1.rx_bps is None and gi1.kind == "physical" and gi1.mode == "access" and gi1.access_vlan == 10 and gi1.poe["power_w"] == pytest.approx(6.1)
    te = (await db.execute(select(SwitchInterface).where(SwitchInterface.switch_id == sw.id, SwitchInterface.ifindex == 38))).scalars().one()
    assert te.lag_ifindex == 65 and te.mode == "trunk"
    assert sw.capabilities["switch_interface_octets_hc"]["last_result"] == "ok" and sw.coverage_pct is not None
    assert any(m["metric"] == "switch_up" and m["value"] == 1 for m in ch.rows["switch_metrics"])
    assert len(ch.rows["switch_if_samples"]) == 8
    # second poll 60 s later: rates, port down, MAC move, STP root change in VLAN 10, PSU unchanged
    t, ctxs = cisco_c9300(1)
    r = await P.poll_switch(db, ch, sw, cred, client=FakeClient(t, contexts=ctxs), now=T0 + timedelta(seconds=60), force=True)
    assert r["ok"]
    await db.refresh(gi1)
    assert gi1.rx_bps == pytest.approx(50_000_000) and gi1.rx_util == pytest.approx(5.0) and gi1.sample_flags == 0
    gi2 = (await db.execute(select(SwitchInterface).where(SwitchInterface.switch_id == sw.id, SwitchInterface.ifindex == 10))).scalars().one()
    assert gi2.in_errors_delta == 25 and gi2.crc_delta == 25
    kinds = [e.kind for e in (await db.execute(select(SwitchEvent).where(SwitchEvent.switch_id == sw.id))).scalars()]
    assert "port_down" in kinds and "mac_move" in kinds and "stp_root_change" in kinds and "stp_topology_change" in kinds
    mac = (await db.execute(select(SwitchMac).where(SwitchMac.mac == "02:00:00:00:a1:01"))).scalars().one()
    assert mac.moves == 1 and mac.ifindex == 10 and mac.port_name == "Gi1/0/2"
    # third poll: stack member removed, LACP member out of bundle, CPU 93 %
    t, ctxs = cisco_c9300(2)
    await P.poll_switch(db, ch, sw, cred, client=FakeClient(t, contexts=ctxs), now=T0 + timedelta(seconds=120), force=True)
    kinds = [e.kind for e in (await db.execute(select(SwitchEvent).where(SwitchEvent.switch_id == sw.id))).scalars()]
    assert "stack_member_failure" in kinds and "lacp_member_down" in kinds and sw.cpu_pct == 93
    # fourth poll: the switch rebooted (sysUpTime small): restart event, no rate (no false spike)
    t, ctxs = cisco_c9300(3, uptime_ticks=6000)
    await P.poll_switch(db, ch, sw, cred, client=FakeClient(t, contexts=ctxs), now=T0 + timedelta(seconds=180), force=True)
    await db.refresh(gi1)
    assert gi1.rx_bps is None and gi1.sample_flags & R.RESET
    assert (await db.execute(select(SwitchEvent).where(SwitchEvent.kind == "restart"))).scalars().first() is not None
    runs = (await db.execute(select(SwitchPollRun).where(SwitchPollRun.switch_id == sw.id))).scalars().all()
    assert len(runs) == 4 and all(x.ok for x in runs)


async def test_ruckus_32bit_counter_wrap_rate(db):
    sw, cred = await _seed(db)
    ch = _CH()
    await P.poll_switch(db, ch, sw, cred, client=FakeClient(ruckus_icx7150(0)), now=T0)
    await P.poll_switch(db, ch, sw, cred, client=FakeClient(ruckus_icx7150(1)), now=T0 + timedelta(seconds=60), force=True)
    p5 = (await db.execute(select(SwitchInterface).where(SwitchInterface.switch_id == sw.id, SwitchInterface.ifindex == 5))).scalars().one()
    assert p5.rx_bps == pytest.approx(30_000_000 * 8 / 60) and p5.sample_flags & R.COUNTER32 and not p5.sample_flags & R.RESET
    kinds = [e.kind for e in (await db.execute(select(SwitchEvent))).scalars()]
    assert "power_supply_failure" in kinds and "mac_move" in kinds
    assert sw.vendor == "ruckus" and sw.model == "ICX7150-48P-4X10GR"


async def test_unreachable_and_auth_failure_states(db):
    sw, cred = await _seed(db)
    ch = _CH()
    t, ctxs = cisco_c9300(0)
    await P.poll_switch(db, ch, sw, cred, client=FakeClient(t, contexts=ctxs), now=T0)
    r = await P.poll_switch(db, ch, sw, cred, client=FakeClient(t, fail="timeout"), now=T0 + timedelta(seconds=60))
    assert not r["ok"] and r["kind"] == "timeout" and sw.state == "up" and sw.fail_streak == 1  # damped: one miss is not DOWN
    await P.poll_switch(db, ch, sw, cred, client=FakeClient(t, fail="timeout"), now=T0 + timedelta(seconds=120))
    assert sw.state == "down"
    assert any(m["metric"] == "switch_up" and m["value"] == 0 for m in ch.rows["switch_metrics"])
    await P.poll_switch(db, ch, sw, cred, client=FakeClient(t, contexts=ctxs), now=T0 + timedelta(seconds=180))
    assert sw.state == "up"
    await P.poll_switch(db, ch, sw, cred, client=FakeClient(t, fail="auth"), now=T0 + timedelta(seconds=240))
    assert sw.state == "auth_failed" and sw.last_error_kind == "auth"
    kinds = [e.kind for e in (await db.execute(select(SwitchEvent).order_by(SwitchEvent.id))).scalars()]
    assert kinds.count("unreachable") == 1 and "reachable" in kinds and "auth_failure" in kinds


async def test_address_outside_authorised_networks_is_not_polled(db):
    sw, cred = await _seed(db)
    sw.address = "198.51.100.7"
    await db.commit()
    t, ctxs = cisco_c9300(0)
    fake = FakeClient(t, contexts=ctxs)
    r = await P.poll_switch(db, _CH(), sw, cred, client=fake, now=T0)
    assert not r["ok"] and r["kind"] == "config" and fake.requests == 0
    with pytest.raises(ValueError):
        P.validate_address("127.0.0.1", [])
    with pytest.raises(ValueError):
        P.validate_address("switch01.example.net", [SwitchNetwork(cidr="10.0.0.0/8")])
    assert P.validate_address("10.1.2.3", [SwitchNetwork(cidr="10.0.0.0/8")]) == "10.1.2.3"


async def test_snmpv2c_refused_unless_enabled(monkeypatch):
    from app.config import get_settings
    get_settings.cache_clear()
    with pytest.raises(SnmpError) as e:
        P.check_version_allowed("v2c")
    assert e.value.kind == "config"
    monkeypatch.setenv("SWITCH_ALLOW_SNMPV2C", "true")
    get_settings.cache_clear()
    P.check_version_allowed("v2c")
    monkeypatch.delenv("SWITCH_ALLOW_SNMPV2C")
    get_settings.cache_clear()


async def test_lease_prevents_duplicate_polls(db):
    sw, _ = await _seed(db)
    first = await P.claim(db, T0, 300)
    second = await P.claim(db, T0 + timedelta(seconds=1), 300)
    assert first == [sw.id] and second == []


# ------------------------------------------------------------------ alerts and recovery
async def test_switch_alerts_and_auto_resolve(db, ch):
    from app.alerts.engine import ensure_default_rules, run_rules
    sw, cred = await _seed(db)
    db.add(Firewall(name="WH1-FW", host="192.0.2.1", site="WH1"))
    await db.commit()
    await ensure_default_rules(db)
    for r in (await db.execute(select(AlertRule))).scalars():
        r.enabled = r.key.startswith("switch_")
    await db.commit()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    t, ctxs = cisco_c9300(0)
    for i in range(3):
        t, ctxs = cisco_c9300(i)
        await P.poll_switch(db, ch, sw, cred, client=FakeClient(t, contexts=ctxs), now=now - timedelta(seconds=180 - 60 * i), force=True)
    # PSU failure on the next poll
    t, ctxs = cisco_c9300(2)
    t["1.3.6.1.4.1.9.9.13.1.5.1.3.1013"] = 3
    await P.poll_switch(db, ch, sw, cred, client=FakeClient(t, contexts=ctxs), now=now, force=True)
    res = await run_rules(ch, db, now=now, correlate=False)
    alerts = {a.rule_key: a for a in (await db.execute(select(Alert))).scalars()}
    assert "switch_psu_failure" in alerts and "switch_stack_member" in alerts and "switch_lacp_member" in alerts
    assert "switch_stp_root_change" in alerts and "switch_mac_move" not in alerts  # one move is below the per-MAC threshold
    psu = alerts["switch_psu_failure"]
    assert psu.evidence["management_ip"] == "192.0.2.10" and psu.evidence["troubleshooting"] and psu.sites == ["WH1"]
    fw = (await db.execute(select(Firewall))).scalars().one()
    assert psu.firewall_ids == [fw.id]  # correlates with the site's firewall
    # same condition next cycle: updated, not duplicated
    res = await run_rules(ch, db, now=now + timedelta(minutes=1), correlate=False)
    assert res["switch_psu_failure"]["updated"] == 1 and res["switch_psu_failure"]["created"] == 0
    # PSU recovers → alert auto-resolves with a recovery notification queued for opted-in rules
    from app.db.models import NotificationChannel, NotificationOutbox, NotificationRule
    chn = NotificationChannel(name="ops", type="webhook", enabled=True)
    db.add(chn)
    await db.flush()
    db.add(NotificationRule(name="switch recoveries", channel_id=chn.id, event_types=["alert.resolved"], min_severity="low", enabled=True, rule_keys=[]))
    await db.commit()
    t["1.3.6.1.4.1.9.9.13.1.5.1.3.1013"] = 1
    await P.poll_switch(db, ch, sw, cred, client=FakeClient(t, contexts=ctxs), now=now + timedelta(minutes=2), force=True)
    res = await run_rules(ch, db, now=now + timedelta(minutes=2), correlate=False)
    await db.refresh(psu)
    assert psu.status == "resolved" and "auto-resolved" in psu.notes and res["switch_psu_failure"].get("resolved") == 1
    out = (await db.execute(select(NotificationOutbox).where(NotificationOutbox.event_type == "alert.resolved"))).scalars().all()
    assert len(out) == 1 and "[RESOLVED]" in out[0].payload["title"]


async def test_utilization_alert_ignores_flagged_samples(db, ch):
    from app.switches.alerts import rule_switch_if_utilization
    sw, _ = await _seed(db)
    sw.last_success_at = datetime.now(timezone.utc)
    await db.commit()
    ch.command("TRUNCATE TABLE switch_if_samples")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    rows = [{"ts": now - timedelta(minutes=4 - i), "switch_id": sw.id, "ifindex": 37, "interval_s": 60.0, "rx_bps": 9.5e9, "tx_bps": 1e8,
             "rx_util": 95.0, "tx_util": 1.0, "rx_pps": None, "tx_pps": None, "in_errors": 0, "out_errors": 0, "in_discards": 0, "out_discards": 0,
             "crc": 0, "oper": 1, "admin": 1, "flags": R.GAP if i == 3 else 0} for i in range(4)]
    await ch.ainsert("switch_if_samples", rows, P.IF_COLS)
    dets = await rule_switch_if_utilization(ch, now, {"util_pct": 90, "min_samples": 3, "window_minutes": 15})
    assert len(dets) == 1 and dets[0].evidence["observed"] == 95.0
    # three valid samples needed: with only two above the threshold among valid ones, nothing fires
    dets = await rule_switch_if_utilization(ch, now, {"util_pct": 90, "min_samples": 4, "window_minutes": 15})
    assert dets == []


async def test_error_and_discard_alerts_skip_reset_samples(db, ch):
    from app.switches.alerts import rule_switch_if_discards, rule_switch_if_errors
    sw, _ = await _seed(db)
    sw.last_success_at = datetime.now(timezone.utc)
    await db.commit()
    ch.command("TRUNCATE TABLE switch_if_samples")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    base = {"switch_id": sw.id, "ifindex": 10, "interval_s": 60.0, "rx_bps": 1e6, "tx_bps": 1e6, "rx_util": 0.1, "tx_util": 0.1, "rx_pps": None, "tx_pps": None,
            "out_errors": 0, "in_discards": 0, "out_discards": 0, "oper": 1, "admin": 1}
    rows = [{**base, "ts": now - timedelta(minutes=3), "in_errors": 40, "crc": 40, "flags": 0},
            {**base, "ts": now - timedelta(minutes=2), "in_errors": 50, "crc": 50, "flags": 0},
            {**base, "ts": now - timedelta(minutes=1), "in_errors": 10 ** 6, "crc": 10 ** 6, "flags": R.RESET, "in_discards": 10 ** 6}]
    await ch.ainsert("switch_if_samples", rows, P.IF_COLS)
    dets = await rule_switch_if_errors(ch, now, {"min_errors": 100, "window_minutes": 15})
    assert len(dets) == 1 and dets[0].evidence["observed"] == 180 and "90 CRC" in dets[0].explanation  # reset sample ignored
    assert await rule_switch_if_discards(ch, now, {"min_discards": 1000, "window_minutes": 15}) == []


# ------------------------------------------------------------------ API
async def test_api_rbac_validation_no_secrets_and_pagination(api, db, ch):  # noqa: F811
    admin = await As.login(api, "admin1")
    analyst = await As.login(api, "analyst1")
    cred = {"name": "ro-v3", "version": "v3", "username": "siem-ro", "auth_protocol": "sha", "priv_protocol": "aes128",
            "auth_key": "auth-pass-123", "priv_key": "priv-pass-456"}
    assert (await analyst.post("/api/switches/admin/credentials", json=cred)).status_code == 403
    r = await admin.post("/api/switches/admin/credentials", json=cred)
    assert r.status_code == 201 and "auth-pass" not in r.text and "priv-pass" not in r.text and r.json()["security_level"] == "authPriv"
    cid = r.json()["id"]
    assert (await admin.post("/api/switches/admin/credentials", json={**cred, "name": "weak", "auth_key": "short"})).status_code == 422
    v2 = await admin.post("/api/switches/admin/credentials", json={"name": "v2", "version": "v2c", "community": "public-test"})
    assert v2.status_code == 422 and "SNMPv2c is disabled" in v2.text
    body = {"name": "WH1-ACC-SW01", "address": "192.0.2.10", "credential_id": cid, "site": "WH1"}
    r = await admin.post("/api/switches", json=body)
    assert r.status_code == 422 and "authorised management network" in r.text
    assert (await admin.post("/api/switches/admin/networks", json={"cidr": "0.0.0.0/0"})).status_code == 422
    assert (await admin.post("/api/switches/admin/networks", json={"cidr": "127.0.0.0/24"})).status_code == 422
    assert (await analyst.post("/api/switches/admin/networks", json={"cidr": "192.0.2.0/24"})).status_code == 403
    assert (await admin.post("/api/switches/admin/networks", json={"cidr": "192.0.2.0/24", "site": "WH1"})).status_code == 201
    assert (await admin.post("/api/switches", json={**body, "address": "sw1.example.net"})).status_code == 422
    assert (await admin.post("/api/switches", json={**body, "group_intervals": {"bogus": 60}})).status_code == 422
    r = await admin.post("/api/switches", json=body)
    assert r.status_code == 201
    sid = r.json()["id"]
    assert (await admin.post("/api/switches", json=body)).status_code == 409
    assert (await analyst.post("/api/switches", json={**body, "name": "x", "address": "192.0.2.11"})).status_code == 403
    # poll through the real pipeline with a simulated device
    sw = await db.get(Switch, sid)
    credrow = await db.get(SwitchCredential, cid)
    t, ctxs = cisco_c9300(0)
    await P.poll_switch(db, ch, sw, credrow, client=FakeClient(t, contexts=ctxs), now=datetime.now(timezone.utc) - timedelta(seconds=60))
    t, ctxs = cisco_c9300(1)
    await P.poll_switch(db, ch, sw, credrow, client=FakeClient(t, contexts=ctxs), now=datetime.now(timezone.utc), force=True)
    inv = await analyst.get("/api/switches")
    assert inv.status_code == 200 and inv.json()["total"] == 1 and inv.json()["items"][0]["vendor"] == "cisco"
    assert "auth-pass" not in inv.text and "priv-pass" not in inv.text and "secret" not in inv.text
    d = (await analyst.get(f"/api/switches/{sid}")).json()
    assert d["model"] == "C9300-48P" and d["sections"]["poe"] and d["sections"]["routing"] and "entity_names" not in d["health"]
    assert d["site_context"] is None or "firewalls" in d["site_context"]
    ifs = (await analyst.get(f"/api/switches/{sid}/interfaces", params={"limit": 3, "offset": 0})).json()
    assert ifs["total"] == 8 and len(ifs["items"]) == 3
    ifd = (await analyst.get(f"/api/switches/{sid}/interfaces/9", params={"range": "1h"})).json()
    assert ifd["interface"]["name"] == "Gi1/0/1" and ifd["series"]["source"] == "raw" and ifd["vlans"]["untagged"] == [10]
    pts = [p for p in ifd["series"]["points"] if p["rx_bps"] is not None]
    assert pts and pts[-1]["rx_bps"] == pytest.approx(50_000_000, rel=0.01)  # elapsed is wall-clock here
    ts = (await analyst.get(f"/api/switches/{sid}/timeseries", params={"metric": "cpu", "range": "1h"})).json()
    assert ts["series"] and ts["series"][0]["component"] == "Switch 1"
    long = (await analyst.get(f"/api/switches/{sid}/timeseries", params={"metric": "cpu", "range": "7d"})).json()
    assert long["bucket_seconds"] >= 3600
    caps = (await analyst.get(f"/api/switches/{sid}/capabilities")).json()
    st = {m["metric"]: m["status"] for m in caps["metrics"]}
    assert st["switch_cpu_utilization_percent"] == "healthy" and st["switch_ospf_neighbors"] == "unsupported"
    assert (await analyst.get(f"/api/switches/{sid}/vlans")).json()["items"][1]["svi"]["name"] == "Vl10"
    macs = (await analyst.get(f"/api/switches/{sid}/macs", params={"limit": 1})).json()
    assert macs["total"] == 3 and len(macs["items"]) == 1 and macs["moves"]
    assert (await analyst.get("/api/switches/macs/search", params={"mac": "02:00:00:00:a1:01"})).json()["items"][0]["port"] == "Gi1/0/2"
    ev = (await analyst.get("/api/switches/events", params={"switch_id": sid, "limit": 2})).json()
    assert ev["total"] >= 3 and len(ev["items"]) == 2
    ov = (await analyst.get("/api/switches/overview", params={"range": "1h"})).json()
    assert ov["totals"]["switches"] == 1 and ov["totals"]["online"] == 1 and ov["totals"]["interfaces_with_errors"] >= 1
    assert ov["top_utilization"] and ov["poe"][0]["budget_w"] == 874
    assert (await analyst.get("/api/switches/overview", params={"range": "2h"})).status_code == 422
    assert (await analyst.post(f"/api/switches/{sid}/monitoring/pause")).status_code == 403
    assert (await admin.post(f"/api/switches/{sid}/monitoring/pause")).json()["monitoring"] == "paused"
    assert (await analyst.get("/api/switches/admin/credentials")).status_code == 403
    creds = (await admin.get("/api/switches/admin/credentials")).json()["items"]
    assert creds[0]["used_by"] == 1 and "auth_key" not in creds[0] and creds[0]["has_secret"]
    assert (await admin.delete(f"/api/switches/admin/credentials/{cid}")).status_code == 409
    from app.db.models import AuditLog
    acts = {a.action for a in (await db.execute(select(AuditLog))).scalars()}
    assert {"switch_credential_create", "switch_network_create", "switch_create", "switch_pause"} <= acts


async def test_api_csv_import_dry_run_and_commit(api, db):  # noqa: F811
    admin = await As.login(api, "admin1")
    cid = (await admin.post("/api/switches/admin/credentials", json={"name": "ro", "version": "v3", "username": "u", "auth_protocol": "sha",
                                                                    "auth_key": "12345678", "priv_protocol": "aes128", "priv_key": "87654321"})).json()["id"]
    await admin.post("/api/switches/admin/networks", json={"cidr": "192.0.2.0/24"})
    csv_text = "name,address,credential,site\nSW-A,192.0.2.21,ro,WH1\nSW-B,192.0.2.22,ro,WH1\nSW-C,203.0.113.5,ro,WH2\nSW-D,192.0.2.24,nope,WH1\n"
    r = (await admin.post("/api/switches/import", json={"csv": csv_text, "dry_run": True})).json()
    assert r["valid"] == 2 and r["invalid"] == 2 and r["created"] == 0
    errs = {x["name"]: x["errors"] for x in r["rows"]}
    assert "authorised" in errs["SW-C"][0] and "unknown credential" in errs["SW-D"][0]
    r = (await admin.post("/api/switches/import", json={"csv": csv_text, "dry_run": False})).json()
    assert r["created"] == 0 and "all-or-nothing" in r["note"]
    good = "name,address,credential,site\nSW-A,192.0.2.21,ro,WH1\nSW-B,192.0.2.22,ro,WH1\n"
    r = (await admin.post("/api/switches/import", json={"csv": good, "dry_run": False})).json()
    assert r["created"] == 2
    assert cid and (await admin.get("/api/switches")).json()["total"] == 2


async def test_discovery_only_in_authorised_networks(api, db):  # noqa: F811
    from app.switches import discovery
    admin = await As.login(api, "admin1")
    cid = (await admin.post("/api/switches/admin/credentials", json={"name": "ro", "version": "v3", "username": "u", "auth_protocol": "sha",
                                                                    "auth_key": "12345678", "priv_protocol": "aes128", "priv_key": "87654321"})).json()["id"]
    nid = (await admin.post("/api/switches/admin/networks", json={"cidr": "192.0.2.0/29"})).json()["id"]
    r = await admin.post("/api/switches/admin/discovery", json={"network_id": nid, "credential_id": cid})
    assert r.status_code == 422  # allow_discovery is off
    await admin.put(f"/api/switches/admin/networks/{nid}", json={"cidr": "192.0.2.0/29", "allow_discovery": True})
    r = await admin.post("/api/switches/admin/discovery", json={"network_id": nid, "credential_id": cid})
    assert r.status_code == 202 and r.json()["hosts"] == 6
    t, _ = cisco_c9300(0)
    from app.switches.discovery import SwitchDiscoveryRun
    run = (await db.execute(select(SwitchDiscoveryRun))).scalars().one()
    await discovery.run(db, run, client_factory=lambda ip: FakeClient(t) if ip == "192.0.2.3" else FakeClient({}, fail="timeout"))
    assert run.status == "done" and run.scanned == 6 and [x["address"] for x in run.results] == ["192.0.2.3"]
    assert run.results[0]["vendor"] == "cisco" and run.results[0]["supported"]
    with pytest.raises(ValueError):
        discovery.hosts_of("10.0.0.0/16")


# ------------------------------------------------------------------ LLDP / CDP topology
def test_port_key_normalisation():
    assert C.port_key("TenGigabitEthernet1/1/1") == C.port_key("Te1/1/1") == "te1/1/1"
    assert C.port_key("GigabitEthernet 0/0/12") == C.port_key("Gi0/0/12")
    assert C.port_key("Port-channel1") == "po1" and C.port_key("1/1/2") == "1/1/2" and C.port_key("ethernet1/1/2") == "eth1/1/2"


async def test_lldp_cdp_collection_maps_local_ports():
    t, ctxs = cisco_c9300(0)
    ctx, d, _ = await _collect(FakeClient(t, contexts=ctxs))
    by = {n["sys_name"]: n for n in d["neighbors"]}
    assert by["FC2-ICX-01"]["local_ifindex"] == 37 and by["FC2-ICX-01"]["local_port"] == "Te1/1/1"  # lldpLocPortNum 1037 → ifIndex via port name
    assert by["FC2-ICX-01"]["mgmt_ip"] == "198.51.100.20" and set(by["FC2-ICX-01"]["caps"]) == {"bridge", "router"}
    assert by["FC2-ICX-01"]["chassis_id"] == "02:1c:00:00:00:01"
    assert by["AP-ROW-A-01"]["caps"] == ["wlan_ap"] and by["AP-ROW-A-01"]["local_ifindex"] == 9
    assert by["SEP0200000000A2"]["protocol"] == "cdp" and by["SEP0200000000A2"]["local_ifindex"] == 10 and by["SEP0200000000A2"]["mgmt_ip"] == "10.20.20.5"
    assert "telephone" in by["SEP0200000000A2"]["caps"]
    assert ctx.outcome.results["switch_lldp_neighbors"]["result"] == "ok" and ctx.outcome.results["switch_cdp_neighbors"]["result"] == "ok"
    ctx, d, _ = await _collect(FakeClient(ruckus_icx7150(0)))
    assert [(n["local_ifindex"], n["sys_name"], n["port_id"]) for n in d["neighbors"]] == [(2, "WH1-ACC-SW01.example.net", "TenGigabitEthernet1/1/1")]
    assert "switch_cdp_neighbors" not in ctx.outcome.results  # never asks a Ruckus switch for CDP


async def _two_switches(db):
    sw, cred = await _seed(db)
    db.add(SwitchNetwork(cidr="198.51.100.0/24", site="FC2"))
    icx = Switch(name="FC2-ICX-01", address="198.51.100.20", credential_id=cred.id, site="FC2", capabilities={}, group_state={}, health={}, thresholds={})
    db.add(icx)
    await db.commit()
    return sw, icx, cred


async def test_topology_merges_both_ends_and_checks_paths(db):
    from app.switches.topology import build, path
    sw, icx, cred = await _two_switches(db)
    ch = _CH()
    for step, now in ((0, T0), (1, T0 + timedelta(seconds=60))):
        t, ctxs = cisco_c9300(step)
        await P.poll_switch(db, ch, sw, cred, client=FakeClient(t, contexts=ctxs), now=now, force=True)
        await P.poll_switch(db, ch, icx, cred, client=FakeClient(ruckus_icx7150(step)), now=now, force=True)
    topo = await build(db, now=T0 + timedelta(seconds=60))
    ids = {n["id"]: n for n in topo["nodes"]}
    a, b = f"sw:{sw.id}", f"sw:{icx.id}"
    link = next(lk for lk in topo["links"] if {lk["a"]["node"], lk["b"]["node"]} == {a, b})
    assert link["bidirectional"] and link["status"] == "up" and link["protocols"] == ["lldp"]
    ends = {lk_end["node"]: lk_end for lk_end in (link["a"], link["b"])}
    assert ends[a]["port"] == "Te1/1/1" and ends[b]["port"] == "1/1/2" and ends[b]["interface"]["ifindex"] == 2
    assert len([lk for lk in topo["links"] if {lk["a"]["node"], lk["b"]["node"]} == {a, b}]) == 1  # one cable, not two
    assert "ext:core-sw-01" in ids and ids["ext:core-sw-01"]["type"] == "switch" and topo["totals"]["external"] == 1
    assert not any(n["type"] in ("ap", "phone") for n in topo["nodes"]) and topo["totals"]["hidden_endpoints"] == 2
    full = await build(db, endpoints=True, now=T0 + timedelta(seconds=60))
    assert {"ap", "phone"} <= {n["type"] for n in full["nodes"]}
    p = path(topo, b, "ext:core-sw-01")
    assert p["connected"] and [h["to"] for h in p["hops"]] == [a, "ext:core-sw-01"]
    # step 2: CORE-SW-01 disappears from Te2/1/1 → link lost, path gone
    t, ctxs = cisco_c9300(2)
    await P.poll_switch(db, ch, sw, cred, client=FakeClient(t, contexts=ctxs), now=T0 + timedelta(seconds=120), force=True)
    topo = await build(db, now=T0 + timedelta(seconds=120))
    lost = next(lk for lk in topo["links"] if "ext:core-sw-01" in (lk["a"]["node"], lk["b"]["node"]))
    assert lost["status"] == "lost" and topo["totals"]["lost"] == 1
    assert not path(topo, b, "ext:core-sw-01")["connected"]
    assert path(topo, b, "ext:core-sw-01", usable=("up", "degraded", "lost"))["connected"]
    kinds = [e.kind for e in (await db.execute(select(SwitchEvent).where(SwitchEvent.switch_id == sw.id))).scalars()]
    assert "neighbor_removed" in kinds


async def test_topology_link_lost_alert_and_recovery(db, ch):
    from app.alerts.engine import ensure_default_rules, run_rules
    sw, cred = await _seed(db)
    await ensure_default_rules(db)
    for r in (await db.execute(select(AlertRule))).scalars():
        r.enabled = r.key == "switch_topology_link_lost"
    await db.commit()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    for i, step in enumerate((0, 1, 2)):
        t, ctxs = cisco_c9300(step)
        await P.poll_switch(db, ch, sw, cred, client=FakeClient(t, contexts=ctxs), now=now - timedelta(seconds=120 - 60 * i), force=True)
    await run_rules(ch, db, now=now, correlate=False)
    a = (await db.execute(select(Alert).where(Alert.rule_key == "switch_topology_link_lost"))).scalars().one()
    assert "CORE-SW-01" in a.explanation and "Te2/1/1" in a.explanation and a.status == "new"
    t, ctxs = cisco_c9300(1)  # the neighbor is back
    await P.poll_switch(db, ch, sw, cred, client=FakeClient(t, contexts=ctxs), now=now + timedelta(seconds=60), force=True)
    await run_rules(ch, db, now=now + timedelta(seconds=60), correlate=False)
    await db.refresh(a)
    assert a.status == "resolved"


async def test_topology_and_neighbor_api(api, db):  # noqa: F811
    admin = await As.login(api, "admin1")
    analyst = await As.login(api, "analyst1")
    cid = (await admin.post("/api/switches/admin/credentials", json={"name": "ro", "version": "v3", "username": "u", "auth_protocol": "sha",
                                                                    "auth_key": "12345678", "priv_protocol": "aes128", "priv_key": "87654321"})).json()["id"]
    for c in ("192.0.2.0/24", "198.51.100.0/24"):
        await admin.post("/api/switches/admin/networks", json={"cidr": c})
    s1 = (await admin.post("/api/switches", json={"name": "WH1-ACC-SW01", "address": "192.0.2.10", "credential_id": cid})).json()["id"]
    s2 = (await admin.post("/api/switches", json={"name": "FC2-ICX-01", "address": "198.51.100.20", "credential_id": cid})).json()["id"]
    credrow = await db.get(SwitchCredential, cid)
    t, ctxs = cisco_c9300(0)
    await P.poll_switch(db, None, await db.get(Switch, s1), credrow, client=FakeClient(t, contexts=ctxs))
    await P.poll_switch(db, None, await db.get(Switch, s2), credrow, client=FakeClient(ruckus_icx7150(0)))
    topo = (await analyst.get("/api/switches/topology")).json()
    assert topo["totals"]["links"] == 2 and topo["totals"]["up"] == 2  # ICX link + CORE-SW-01 (AP / phone hidden)
    assert (await analyst.get("/api/switches/topology", params={"endpoints": True})).json()["totals"]["links"] == 4
    p = (await analyst.get("/api/switches/topology/path", params={"src": f"sw:{s2}", "dst": "ext:core-sw-01"})).json()
    assert p["connected"] and len(p["hops"]) == 2
    assert (await analyst.get("/api/switches/topology/path", params={"src": "sw:999", "dst": "ext:x"})).status_code == 404
    nb = (await analyst.get(f"/api/switches/{s1}/neighbors")).json()["items"]
    icx = next(x for x in nb if x["remote_name"] == "FC2-ICX-01")
    assert icx["matched_switch"] == {"id": s2, "name": "FC2-ICX-01"} and icx["local_oper"] == "up" and icx["type"] == "switch"
