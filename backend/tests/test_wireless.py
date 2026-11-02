"""Wireless Analysis (Cisco Catalyst 9800 WLC over SNMP): registry, collectors, normalisation, persistence, state
machines, roaming, scoring, switch correlation, troubleshooting, alerts and APIs. Mocked SNMP only."""
import re
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.alerts.engine import ensure_default_rules, run_rules
from app.db.models import (Alert, AlertRule, Switch, SwitchCredential, SwitchInterface, SwitchNetwork, User, WirelessAp, WirelessClient,
                           WirelessEvent, WirelessRadio, WirelessWlan)
from app.security import hash_password
from app.switches import poller as P
from app.switches.collect import Ctx
from app.switches.registry import Outcome
from app.wireless import collect as WC
from app.wireless import service as W
from app.wireless.oids import ENUMS, OBJ

from .snmp_sim import FakeClient
from .test_api import PW, api, login  # noqa: F401
from .test_iac import As
from .test_switches import _CH
from .wireless_fixtures import AP1, AP2, C1, C2, C3, c9800

T0 = datetime(2026, 10, 28, 10, 0, tzinfo=timezone.utc)


def test_registry_objects_are_readable_mib_objects_under_cisco_roots():
    roots = {"CISCO-LWAPP-AP-MIB": "1.3.6.1.4.1.9.9.513.", "CISCO-LWAPP-WLAN-MIB": "1.3.6.1.4.1.9.9.512.",
             "CISCO-LWAPP-DOT11-CLIENT-MIB": "1.3.6.1.4.1.9.9.599.", "CISCO-LWAPP-CDP-MIB": "1.3.6.1.4.1.9.9.623.",
             "AIRESPACE-WIRELESS-MIB": "1.3.6.1.4.1.14179.2."}
    for name, o in OBJ.items():
        assert re.fullmatch(r"[\d.]+", o["oid"]) and o["oid"].startswith(roots[o["mib"]]), name
    # spot checks against the MIB text (column numbers)
    assert OBJ["bsnMobileStationRSSI"]["oid"] == "1.3.6.1.4.1.14179.2.1.6.1.1" and OBJ["bsnMobileStationSnr"]["oid"].endswith(".6.1.26")
    assert OBJ["cLApCpuCurrentUsage"]["oid"] == "1.3.6.1.4.1.9.9.513.1.1.1.1.57"
    assert ENUMS["bsnAPIfType"][6] == "dot116ghz" and ENUMS["cldcClientStatus"][4] == "associated"
    assert OBJ["bsnAPIfPhyTxPowerLevel"]["unit"] == "level 1-8"          # a level, never presented as dBm


async def _groups(tree, groups=("wireless_ap", "wireless_radio", "wireless_radio_rf", "wireless_wlan", "wireless_client", "wireless_ap_cdp")):
    ctx = Ctx(client=FakeClient(tree), vendor="cisco", outcome=Outcome())
    data, report, ran = await P.run_groups(ctx, ["system", *groups])
    return data, report, ctx.outcome


async def test_collectors_normalise_9800_tables():
    data, report, out = await _groups(c9800(0))
    assert all(r["ok"] for r in report.values()), report
    a = data["wireless_aps"][AP1]
    assert a["name"] == "WH1-AP-01" and a["model"] == "C9120AXI-D" and a["ip"] == "10.30.0.11" and a["oper_status"] == "associated"
    assert a["uptime_s"] == 7200 and a["cpu_pct"] == 12 and a["reboot_reason"] == "rebootFromController"
    assert set(a["sources"]) == {"AIRESPACE-WIRELESS-MIB", "CISCO-LWAPP-AP-MIB"}
    r5 = data["wireless_radios"][f"{AP1}/1"]
    assert (r5["band"], r5["channel"], r5["channel_width_mhz"], r5["channel_util_pct"], r5["oper_up"]) == ("5", 36, 80, 82, True)
    assert data["wireless_radios"][f"{AP1}/0"]["band"] == "2.4"
    rf = data["wireless_rf"][f"{AP1}/1"]
    assert rf == {"channel": 36, "noise_dbm": -95, "interference_pct": 40, "interference_dbm": -80}   # current channel row only
    c = data["wireless_clients"][C2]
    assert (c["ap_mac"], c["band"], c["rssi_dbm"], c["snr_db"], c["ssid"], c["vlan"], c["status"]) == (AP1, "2.4", -80, 9, "CORP", 40, "associated")
    assert data["wireless_wlans"][1]["ssid"] == "CORP" and data["wireless_wlans"][1]["enabled"] is True
    assert data["wireless_ap_cdp"][AP1]["port"] == "GigabitEthernet1/0/5"
    assert out.results["wireless_radio_channel_utilization_percent"]["result"] == "ok"


async def test_unsupported_mib_is_missing_not_zero():
    data, report, out = await _groups(c9800(0, with_lwapp_ap=False))
    a = data["wireless_aps"][AP1]
    assert a["name"] == "WH1-AP-01" and a["cpu_pct"] is None and a["uptime_s"] is None      # from AIRESPACE only
    assert out.results["wireless_ap_cpu_percent"]["result"] == "missing"
    assert out.results["wireless_ap_up"]["result"] == "ok"


async def _seed(db, role="wlc"):
    db.add(SwitchNetwork(cidr="192.0.2.0/24", site="WH1"))
    cred = SwitchCredential(name="ro-v3", version="v3", username="siem-ro", auth_protocol="sha", priv_protocol="aes128",
                            secret_ciphertext=P.seal_secret({"auth_key": "auth-pass-123", "priv_key": "priv-pass-456"}))
    db.add(cred)
    await db.flush()
    wlc = Switch(name="WLC-WH1", address="192.0.2.20", credential_id=cred.id, site="WH1", role=role, capabilities={}, group_state={}, health={},
                 thresholds={})
    db.add(wlc)
    await db.commit()
    return wlc, cred


async def _poll(db, ch, wlc, cred, tree, step):
    return await P.poll_switch(db, ch, wlc, cred, client=FakeClient(tree), now=T0 + timedelta(minutes=step), force=True)


async def test_poll_persists_inventory_state_roams_and_history(db):
    wlc, cred = await _seed(db)
    ch = _CH()
    r = await _poll(db, ch, wlc, cred, c9800(0), 0)
    assert r["ok"] and all(g["ok"] for k, g in r["groups"].items() if k.startswith("wireless_")), r["groups"]
    aps = {a.mac: a for a in (await db.execute(select(WirelessAp))).scalars()}
    assert set(aps) == {AP1, AP2} and aps[AP1].state == "up" and aps[AP1].site == "WH1"
    assert aps[AP1].clients == 2          # not reported by cLApAssociatedClientCount here: derived from the client table (C1, C2)
    radios = (await db.execute(select(WirelessRadio))).scalars().all()
    assert len(radios) == 4 and {r.band for r in radios} == {"2.4", "5"}
    r5 = next(r for r in radios if r.ap_id == aps[AP1].id and r.slot == 1)
    assert r5.noise_dbm == -95 and r5.interference_pct == 40 and r5.wlans[0]["ssid"] == "CORP" and r5.retry_pct is None   # no rate on first poll
    assert (await db.execute(select(WirelessWlan))).scalars().one().aps == 2
    cl = {c.mac: c for c in (await db.execute(select(WirelessClient))).scalars()}
    assert cl[C1].ap_id == aps[AP1].id and cl[C1].username == "user1@corp" and set(cl[C1].sources) == {"AIRESPACE-WIRELESS-MIB", "CISCO-LWAPP-DOT11-CLIENT-MIB"}
    assert any(m["metric"] == "wireless_radio_channel_utilization_percent" and m["value"] == 82 for m in ch.rows["wireless_metrics"])
    assert not any(m["metric"] == "wireless_ap_cpu_percent" and m["value"] == 0 for m in ch.rows["wireless_metrics"])
    assert len(ch.rows["wireless_client_samples"]) == 3
    assert wlc.health["wireless"]["aps"] == 2 and wlc.health["wireless"]["clients"] == 3
    # poll 2: counters → retry rate; C1 roams to AP2; C3 leaves; AP2 missing once (not down yet)
    t = c9800(1, aps=(AP1,), clients={C1: (AP2, 1, -62, 30), C2: (AP1, 0, -81, 8)}, retries=(1000, 2000))
    await _poll(db, ch, wlc, cred, t, 1)
    await db.refresh(r5)
    assert r5.retry_pct == 10.0                                    # Δretries 1000 / Δtx 10000
    await db.refresh(aps[AP2])
    assert aps[AP2].state == "up" and aps[AP2].counters["missing_polls"] == 1
    evs = {e.kind: e for e in (await db.execute(select(WirelessEvent))).scalars()}
    assert evs["client_roam"].data["measured"] is False and evs["client_roam"].client_mac == C1
    assert "client_disconnected" in evs
    # poll 3: AP2 missing twice → down; counter reset → no retry rate
    await _poll(db, ch, wlc, cred, c9800(2, aps=(AP1,), clients={C2: (AP1, 0, -81, 8)}, retries=(1000, 2000, 50)), 2)
    await db.refresh(aps[AP2])
    await db.refresh(r5)
    assert aps[AP2].state == "down" and r5.retry_pct is None
    # poll 4: controller answers but its AP table is empty → collection problem, AP1 stays as it was
    await _poll(db, ch, wlc, cred, c9800(3, ap_table=False), 3)
    await db.refresh(aps[AP1])
    assert aps[AP1].state == "up" and wlc.health["wireless"]["ap_table_ok"] is False


async def test_plain_switch_never_polls_wireless(db):
    wlc, cred = await _seed(db, role="access")
    fake = FakeClient(c9800(0))
    await P.poll_switch(db, _CH(), wlc, cred, client=fake, now=T0)
    assert not any(w.startswith("1.3.6.1.4.1.14179") or w.startswith("1.3.6.1.4.1.9.9.513") for w in fake.walked)
    assert not any(k.startswith("wireless_") for k in wlc.capabilities)
    assert not (await db.execute(select(WirelessAp))).scalars().all()


def test_client_experience_score_uses_only_measured_components():
    t = W.thresholds(None)
    c = WirelessClient(mac=C1, rssi_dbm=-60, snr_db=35, tx_rate_mbps=433)
    s = W.client_score(c, WirelessRadio(slot=1, band="5", channel_util_pct=82, retry_pct=None), t)
    assert s["confidence"] == 0.9 and s["grade"] in ("good", "fair") and {f["key"] for f in s["factors"]} == {"rssi", "snr", "rate", "channel_util"}
    poor = W.client_score(WirelessClient(mac=C2, rssi_dbm=-82, snr_db=8), None, t)
    assert poor["score"] == 0 and poor["confidence"] == 0.6 and poor["grade"] == "poor"
    none = W.client_score(WirelessClient(mac=C3), None, t)
    assert none["score"] is None and none["confidence"] == 0.0


async def test_ap_switch_correlation_and_troubleshooting(db):
    wlc, cred = await _seed(db)
    sw = Switch(name="WH1-ACC-SW01", address="192.0.2.30", sys_name="WH1-ACC-SW01.corp.example", site="WH1", state="up", capabilities={},
                group_state={}, health={}, thresholds={})
    db.add(sw)
    await db.flush()
    db.add(SwitchInterface(switch_id=sw.id, ifindex=5, name="Gi1/0/5", oper="down", admin="up", poe={"status": "searching", "power_w": 0}))
    await db.commit()
    await _poll(db, _CH(), wlc, cred, c9800(0), 0)
    ap1 = (await db.execute(select(WirelessAp).where(WirelessAp.mac == AP1))).scalars().one()
    assert ap1.switch_id == sw.id and ap1.switch_ifindex == 5
    ap2 = (await db.execute(select(WirelessAp).where(WirelessAp.mac == AP2))).scalars().one()
    assert ap2.switch_id is None and ap2.uplink["switch"].startswith("WH1-ACC-SW02")       # CDP names an unmonitored switch
    r = await W.troubleshoot(db, "ap_offline", ap_id=ap1.id)
    kinds = {e["check"]: e for e in r["evidence"]}
    assert kinds["port"]["ok"] is False and kinds["poe"]["ok"] is False and any("Gi1/0/5" in c for c in r["probable_causes"])
    perf = await W.troubleshoot(db, "poor_performance", ap_id=ap1.id)
    assert any("channel is busy" in c for c in perf["probable_causes"]) and "not a determined root cause" in perf["note"]
    cl = await W.troubleshoot(db, "client_cannot_connect", mac=C2, ssid="NOPE")
    assert any("NOPE" in c for c in cl["probable_causes"]) and any(e["check"] == "auth_detail" for e in cl["evidence"])
    with pytest.raises(ValueError):
        await W.troubleshoot(db, "ap_offline")


async def test_alerts_for_ap_down_overload_and_stale(db, ch):
    ch.command("TRUNCATE TABLE wireless_metrics")
    wlc, cred = await _seed(db)
    wlc.thresholds = {"wireless": {"ap_clients_max": 2}}
    await db.commit()
    for i in range(3):
        await _poll(db, ch, wlc, cred, c9800(i, aps=(AP1, AP2) if i == 0 else (AP1,)), i)
    wlc.state = "up"
    ap2 = (await db.execute(select(WirelessAp).where(WirelessAp.mac == AP2))).scalars().one()
    ap2.state_since = datetime.now(timezone.utc) - timedelta(minutes=10)
    await db.commit()
    await ensure_default_rules(db)
    for r in (await db.execute(select(AlertRule))).scalars():
        r.enabled = r.key in ("wireless_ap_down", "wireless_ap_overload")
    await db.commit()
    res = await run_rules(ch, db)
    assert res["wireless_ap_down"]["created"] == 1 and res["wireless_ap_overload"]["created"] == 1
    a = (await db.execute(select(Alert).where(Alert.rule_key == "wireless_ap_down"))).scalars().one()
    assert "WH1-AP-02" in a.explanation and a.evidence["ap_id"] == ap2.id
    assert (await run_rules(ch, db))["wireless_ap_down"]["created"] == 0          # same outage: updated, not re-created
    o = W.wlc_out(wlc, T0 + timedelta(hours=2))
    assert "wireless_client" in o["stale_groups"]


async def test_wireless_api_rbac_identity_and_views(api, db, ch):
    ch.command("TRUNCATE TABLE wireless_metrics")
    ch.command("TRUNCATE TABLE wireless_client_samples")
    wlc, cred = await _seed(db)
    await _poll(db, ch, wlc, cred, c9800(0), 0)
    db.add(User(username="gridonly", password_hash=hash_password(PW), role="analyst", products=["grid"]))
    await db.commit()
    A = await As.login(api, "admin1")
    N = await As.login(api, "analyst1")
    G = await As.login(api, "gridonly")
    assert (await G.get("/api/wireless/overview")).status_code == 403
    ov = (await N.get("/api/wireless/overview")).json()
    assert ov["cards"]["aps"] == 2 and ov["cards"]["clients"] == 3 and ov["cards"]["poor_signal_clients"] == 1 and ov["cards"]["high_util_radios"] == 1
    cl = (await N.get("/api/wireless/clients")).json()
    assert {c["username"] for c in cl["items"]} == {"(hidden)"}                      # analysts never see usernames
    assert cl["items"][0]["mac"] == C2 and cl["items"][0]["experience"]["grade"] == "poor"   # worst first
    assert "user1@corp" in {c["username"] for c in (await A.get("/api/wireless/clients")).json()["items"]}
    assert (await N.get("/api/wireless/clients", params={"q": "user1"})).json()["total"] == 0   # cannot search by hidden identity
    aps = (await N.get("/api/wireless/aps")).json()
    ap1 = next(x for x in aps["items"] if x["mac"] == AP1)
    d = (await N.get(f"/api/wireless/aps/{ap1['id']}")).json()
    assert len(d["radios"]) == 2 and "high_utilization" in d["radios"][1]["flags"] and d["switch_port"]["monitored"] is False
    h = (await N.get(f"/api/wireless/aps/{ap1['id']}/history", params={"range": "30d"})).json()
    assert h["radios"] and any("wireless_radio_channel_utilization_percent" in p for p in h["radios"])
    rf = (await N.get("/api/wireless/rf")).json()
    assert rf["radios"][0]["ap"] == "WH1-AP-01" and {c["channel"] for c in rf["channels"]} >= {6, 36, 40}
    hl = (await N.get("/api/wireless/health")).json()["items"][0]
    rssi = next(m for m in hl["metrics"] if m["metric"] == "wireless_client_rssi_dbm")
    assert rssi["last_success"] and rssi["status"] == "stale"          # collected (fixture time), now older than 3 intervals
    assert (await N.c.put(f"/api/wireless/controllers/{wlc.id}/thresholds", json={"thresholds": {"rssi_poor_dbm": -70}}, headers=N.h)).status_code == 403
    r = await A.c.put(f"/api/wireless/controllers/{wlc.id}/thresholds", json={"thresholds": {"channel_util_pct": {"5": 90}}}, headers=A.h)
    assert r.status_code == 200 and r.json()["thresholds"]["channel_util_pct"]["5"] == 90
    assert (await A.c.put(f"/api/wireless/controllers/{wlc.id}/thresholds", json={"thresholds": {"bogus": 1}}, headers=A.h)).status_code == 422
    t = await N.post("/api/wireless/troubleshoot", json={"scenario": "high_load", "ap_id": ap1["id"]})
    assert t.status_code == 200 and t.json()["evidence"]
    assert len((await N.get("/api/wireless/oids")).json()["items"]) == len(OBJ)
