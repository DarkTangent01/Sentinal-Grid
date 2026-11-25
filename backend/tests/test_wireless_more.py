"""Rogue APs, AP power (PoE), per-floor experience SLA and controller client notifications (phase 6)."""
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app import snmp_traps as TR
from app.db.models import Switch, SwitchInterface, WirelessAp, WirelessClient, WirelessRogue, WirelessWlan
from app.switches import poller as P
from app.switches.collect import Ctx
from app.switches.registry import Outcome
from app.wireless import alerts as WA
from app.wireless import service as W
from app.wireless.collect import collect_rogues
from app.wireless.store import persist

from .snmp_sim import FakeClient
from .wireless_fixtures import mi, put

NOW = datetime(2026, 11, 13, 10, tzinfo=timezone.utc)
R1, R2, R3 = "00:de:ad:00:00:01", "00:de:ad:00:00:02", "00:de:ad:00:00:03"


def rogue_tree() -> dict:
    t: dict = {}
    for mac, ssid, cls, state, onnet, rssi in ((R1, "CORP", 3, 2, 0, -60), (R2, "FreeWifi", 2, 7, 0, -75), (R3, "Neighbour", 1, 4, 1, -88)):
        i = mi(mac)
        put(t, "bsnRogueAPSSID", i, ssid.encode())
        put(t, "bsnRogueAPClassType", i, cls)
        put(t, "bsnRogueAPState", i, state)
        put(t, "bsnRogueAPOnNetwork", i, onnet)
        put(t, "bsnRogueAPMaxDetectedRSSI", i, rssi)
        put(t, "bsnRogueAPChannel", i, 36)
        put(t, "bsnRogueAPTotalClients", i, 2)
        put(t, "bsnRogueAPTotalDetectingAPs", i, 3)
        put(t, "bsnRogueAPDetectingAPName", i, b"AP-01")
        put(t, "bsnRogueAPType", i, 0)
    return t


async def test_rogue_collection_spoofed_ssid_and_rule(db):
    wlc = Switch(name="WLC", address="192.0.2.9", role="wlc", vendor="cisco", state="up", monitoring="active", capabilities={}, group_state={},
                 health={}, thresholds={})
    db.add(wlc)
    await db.flush()
    db.add(WirelessWlan(wlc_id=wlc.id, wlan_id=1, ssid="CORP", present=True))
    await db.commit()
    ctx = Ctx(client=FakeClient(rogue_tree()), vendor="cisco", outcome=Outcome())
    data = await collect_rogues(ctx)
    assert set(data["wireless_rogues"]) == {R1, R2, R3} and data["wireless_rogues"][R2]["class_type"] == "malicious"
    assert data["wireless_rogues"][R3]["on_network"] is True and data["wireless_rogues"][R1]["rssi_dbm"] == -60
    assert ctx.outcome.results["wireless_rogue_aps"]["result"] == "ok"
    await persist(db, None, wlc, data, {"wireless_rogue"}, NOW, P.intervals_of(wlc), dict(wlc.health or {}))
    await db.commit()
    rs = {r.mac: r for r in (await db.execute(select(WirelessRogue))).scalars()}
    assert rs[R1].spoofs_ssid and not rs[R2].spoofs_ssid
    dets = {d.evidence["rogue"]: d for d in await WA.rule_wireless_rogue_detected(None, NOW, {})}
    assert set(dets) == {R1, R2}                                  # R3: on the wired network but the controller marks it "known"
    assert "broadcasts one of our SSIDs" in dets[R1].evidence["reasons"]
    # next poll: R2 gone from a complete table → no longer present, no longer alerted
    t = rogue_tree()
    t = {k: v for k, v in t.items() if not k.endswith(mi(R2))}
    data = await collect_rogues(Ctx(client=FakeClient(t), vendor="cisco", outcome=Outcome()))
    await persist(db, None, wlc, data, {"wireless_rogue"}, NOW + timedelta(minutes=15), P.intervals_of(wlc), dict(wlc.health or {}))
    await db.commit()
    assert {d.evidence["rogue"] for d in await WA.rule_wireless_rogue_detected(None, NOW, {})} == {R1}
    assert "wireless_rogue" in P.WIRELESS_HEAVY and "wireless_rogue" in P.ORDER


async def _ap_on_port(db, poe_status: str, ap_state: str, power: str = "full"):
    sw = Switch(name="ACC1", address="192.0.2.1", state="up", capabilities={}, group_state={}, health={}, thresholds={})
    wlc = Switch(name="WLC", address="192.0.2.9", role="wlc", vendor="cisco", state="up", monitoring="active", capabilities={}, group_state={},
                 health={}, thresholds={})
    db.add_all([sw, wlc])
    await db.flush()
    db.add(SwitchInterface(switch_id=sw.id, ifindex=5, name="Gi1/0/5", present=True, poe={"status": poe_status, "power_w": 6.5, "class": 4}))
    a = WirelessAp(wlc_id=wlc.id, mac="00:aa:00:00:00:01", name="AP-01", site="HQ", building="B1", floor="2", state=ap_state,
                   state_since=NOW - timedelta(hours=1), present=True, counters={}, switch_id=sw.id, switch_ifindex=5, power_status=power)
    db.add(a)
    await db.commit()
    return a


async def test_ap_down_with_faulted_poe_port(db):
    await _ap_on_port(db, "fault", "down")
    (d,) = await WA.rule_wireless_ap_poe_issue(None, NOW, {})
    assert d.evidence["port"] == "Gi1/0/5" and d.evidence["poe"]["status"] == "fault"


async def test_ap_at_low_power(db):
    await _ap_on_port(db, "delivering", "up", power="low")
    (d,) = await WA.rule_wireless_ap_poe_issue(None, NOW, {})
    assert "low power" in d.explanation and d.evidence["power_status"] == "low"


async def test_floor_sla(db):
    a = await _ap_on_port(db, "delivering", "up")
    for i in range(12):                                  # 12 clients on floor 2, 4 with good signal → 33% good: breach
        good = i < 4
        db.add(WirelessClient(wlc_id=a.wlc_id, mac=f"00:cc:00:00:00:{i:02x}", ap_id=a.id, ssid="CORP", present=True, roams=0, disconnects=0,
                              rssi_dbm=-55 if good else -85, snr_db=35 if good else 8))
    await db.commit()
    res = await W.floors(db, None, target_pct=80)
    (f,) = res["items"]
    assert (f["building"], f["floor"], f["clients"], f["good_pct"], f["sla"]) == ("B1", "2", 12, 33.3, "breach")
    (d,) = await WA.rule_wireless_floor_sla_breach(None, NOW, {"target_pct": 80, "min_clients": 10})
    assert "HQ / B1 / 2" in d.explanation


def test_controller_client_notifications_are_parsed():
    mac = "00:11:22:33:44:55"
    idx = ".".join(str(int(x, 16)) for x in mac.split(":"))
    disassoc = [(TR.SNMP_TRAP_OID, f"{TR.CLD_NOTIF}6"), (f"{TR.CLD_ENTRY}8.{idx}", bytes.fromhex("00aa00000001")),
                (f"{TR.CLD_ENTRY}28.{idx}", b"CORP"), (f"{TR.CLD_ENTRY}37.{idx}", 1)]
    p = TR.parse_wlc_client(f"{TR.CLD_NOTIF}6", disassoc)
    assert p == {"kind": "trap_disassoc", "mac": mac, "ap_mac": "00:aa:00:00:00:01", "ssid": "CORP", "reason": "1"}
    auth = [(f"{TR.BSN_STATION_MAC}.0", bytes.fromhex("001122334455")), (f"{TR.BSN_STATION_AP}.0", bytes.fromhex("00aa00000001"))]
    assert TR.parse_wlc_client(f"{TR.BSN_TRAPS}3", auth)["kind"] == "trap_auth_fail"
    assert TR.parse_wlc_client("1.3.6.1.4.1.14179.2.6.3.0.3", auth)["kind"] == "trap_auth_fail"      # SNMPv1 form (RFC 3584)
    assert TR.parse_wlc_client("1.3.6.1.6.3.1.1.5.3", auth) is None                                  # linkDown: not a client notification
    assert TR.TRAP_NAMES[f"{TR.BSN_TRAPS}53"] == "AIRESPACE-WIRELESS-MIB::bsnDot11StationAssociate"
