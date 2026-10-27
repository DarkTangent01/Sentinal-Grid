"""BGP monitoring: log parsing, peer state / flaps / downtime, API snapshot diffs, PAN-OS parsing, alert rules and API."""
import xml.etree.ElementTree as ET
from datetime import timedelta

import pytest
from sqlalchemy import select

from app import bgp
from app.alerts.engine import ensure_default_rules, run_rules
from app.db.models import AlertRule, BgpPeer, Firewall
from app.ingest.pipeline import EventSink

from .test_api import api, login  # noqa: F401
from .test_ops import NOW, line
from .test_storage_analytics import registry


def router(ts, logid, msg, level="warning"):
    desc = "BGP neighbor status changed" if logid == "0103020300" else "Routing log warning"
    return line(ts, logid, "router", f'logdesc="{desc}" msg="{msg}"', level)


def test_parse_fortigate_messages():
    p = bgp.parse_msg("BGP: %BGP-5-ADJCHANGE: VRF 0 neighbor 169.254.104.2 Down BGP Notification FSM-ERR")
    assert (p["kind"], p["peer"], p["detail"]) == ("peer_down", "169.254.104.2", "BGP Notification FSM-ERR")
    p = bgp.parse_msg("BGP: %BGP-5-ADJCHANGE: VRF 0 neighbor 169.254.104.2 Up ")
    assert (p["kind"], p["peer"]) == ("peer_up", "169.254.104.2")
    assert bgp.parse_msg("BGP: %BGP-5-ADJCHANGE: neighbor 10.0.0.1 Down Hold Timer Expired")["detail"] == "Hold Timer Expired"
    p = bgp.parse_msg("BGP: %BGP-3-NOTIFICATION: sending to 169.254.108.1 4/0 (Hold Timer Expired/Unspecified Error Subcode) 0 data-bytes []")
    assert (p["kind"], p["peer"], p["direction"]) == ("notification", "169.254.108.1", "sent")
    assert p["detail"] == "sent 4/0 Hold Timer Expired/Unspecified Error Subcode"
    p = bgp.parse_msg("BGP: 169.254.108.1-Outgoing [RIB] Withdraw: Can't find route 10.20.0.0/16")
    assert (p["kind"], p["peer"], p["prefix"], p["direction"]) == ("route_withdraw", "169.254.108.1", "10.20.0.0/16", "sent")
    p = bgp.parse_msg("BGP: 192.0.2.1 rcvd UPDATE about 198.51.100.0/24 -- withdrawn")
    assert (p["kind"], p["prefix"], p["direction"]) == ("route_withdraw", "198.51.100.0/24", "received")
    assert bgp.parse_msg("BGP: 192.0.2.1 rcvd 198.51.100.0/24")["kind"] == "route_add"
    p = bgp.parse_msg("BGP peer session to peer 10.9.9.9 is Established")  # generic (e.g. PAN-OS routing logs)
    assert (p["kind"], p["peer"]) == ("peer_up", "10.9.9.9")
    assert bgp.parse_msg("OSPF neighbor 10.0.0.2 Full") is None


async def _ingest(ch):
    sink = EventSink(ch, registry())
    m = lambda x: NOW - timedelta(minutes=x)  # noqa: E731
    lines = [
        router(m(300), "0103020300", "BGP: %BGP-5-ADJCHANGE: VRF 0 neighbor 169.254.108.1 Up "),
        # peer A: two drops in the last hour, recovered
        router(m(50), "0103020304", "BGP: %BGP-3-NOTIFICATION: sending to 169.254.108.1 4/0 (Hold Timer Expired/Unspecified Error Subcode) 0 data-bytes []"),
        router(m(50), "0103020300", "BGP: %BGP-5-ADJCHANGE: VRF 0 neighbor 169.254.108.1 Down Hold Timer Expired"),
        router(m(50), "0103020300", "BGP: %BGP-5-ADJCHANGE: VRF 0 neighbor 169.254.108.1 Down BGP Notification FSM-ERR"),  # FortiOS logs both
        router(m(40), "0103020300", "BGP: %BGP-5-ADJCHANGE: VRF 0 neighbor 169.254.108.1 Up "),
        router(m(30), "0103020300", "BGP: %BGP-5-ADJCHANGE: VRF 0 neighbor 169.254.108.1 Down BGP Notification FSM-ERR"),
        router(m(28), "0103020300", "BGP: %BGP-5-ADJCHANGE: VRF 0 neighbor 169.254.108.1 Up "),
        # peer B: down 6 minutes ago, still down
        router(m(6), "0103020300", "BGP: %BGP-5-ADJCHANGE: VRF 0 neighbor 169.254.104.2 Down BGP Notification FSM-ERR"),
    ]
    lines += [router(m(29), "0103020304", f"BGP: 169.254.108.1-Outgoing [RIB] Withdraw: Can't find route 10.{i}.0.0/16") for i in range(60)]
    for ln in lines:
        assert sink.add_line(ln, source="syslog", peer_ip="10.1.0.1") is not None, ln
    await sink.flush()


@pytest.mark.asyncio
async def test_report_from_logs(clean_ch, db):
    await _ingest(clean_ch)
    r = await bgp.report(clean_ch, db, NOW - timedelta(hours=1), NOW + timedelta(seconds=1))
    peers = {p["peer"]: p for p in r["peers"]}
    a, b = peers["169.254.108.1"], peers["169.254.104.2"]
    assert a["status"] == "up" and a["flaps"] == 2 and a["notifications"] == 1 and a["routes_withdrawn"] == 60
    assert 11 * 60 <= a["downtime_s"] <= 13 * 60 and a["availability"] < 100 and a["source"] == "log"
    assert b["status"] == "down" and b["down_periods"][-1]["ongoing"] and r["peers"][0]["peer"] == "169.254.104.2"
    t = r["totals"]
    assert (t["peers"], t["up"], t["down"], t["flaps"], t["routes_withdrawn"]) == (2, 1, 1, 3, 60)
    assert {x["reason"]: x["count"] for x in r["down_reasons"]} == {"Hold Timer Expired": 1, "BGP Notification FSM-ERR": 3}
    assert any(e["detail"] == "BGP Notification FSM-ERR; Hold Timer Expired" for e in r["events"])
    assert sum(row["peer_down"] for row in r["timeline"]) == 3 and r["events"][0]["peer"] == "169.254.104.2"


def _peer(ip, state, routes=None, prefixes=None):
    return {"peer": ip, "remote_as": 65001, "local_ip": "169.254.0.2", "peer_type": "", "state": state, "admin_status": "up",
            "uptime_s": None, "routes": routes, "prefixes": prefixes}


def test_diff_peers_state_and_routes():
    b = BgpPeer(firewall_id=1, peer_ip="10.0.0.1", state="Established", routes=None, routes_truncated=False)
    t = NOW
    ev, gone, _ = bgp.diff_peers({"10.0.0.1": b}, [_peer("10.0.0.1", "Established", {"10.1.0.0/16", "10.2.0.0/16"}, 2)], 1, t)
    assert ev == [] and gone == [] and b.routes == ["10.1.0.0/16", "10.2.0.0/16"]  # first poll: baseline only
    assert b.state_since == t
    ev, _, deltas = bgp.diff_peers({"10.0.0.1": b}, [_peer("10.0.0.1", "Established", {"10.2.0.0/16", "10.3.0.0/16"}, 2)], 1, t + timedelta(minutes=1))
    assert deltas == {"10.0.0.1": ({"10.3.0.0/16"}, {"10.1.0.0/16"})}
    assert sorted((e["kind"], e["prefix"]) for e in ev) == [("route_add", "10.3.0.0/16"), ("route_withdraw", "10.1.0.0/16")]
    ev, _, _ = bgp.diff_peers({"10.0.0.1": b}, [_peer("10.0.0.1", "Active", set(), 0)], 1, t + timedelta(minutes=2))
    kinds = sorted(e["kind"] for e in ev)
    assert kinds == ["peer_down", "route_withdraw", "route_withdraw"] and b.state == "Active" and b.state_since == t + timedelta(minutes=2)
    big = {f"10.{i // 256}.{i % 256}.0/24" for i in range(bgp.MAX_ROUTE_EVENTS + 5)}
    ev, _, _ = bgp.diff_peers({"10.0.0.1": b}, [_peer("10.0.0.1", "Established", big, len(big))], 1, t + timedelta(minutes=3))
    adds = [e for e in ev if e["kind"] == "route_add"]
    assert len(adds) == bgp.MAX_ROUTE_EVENTS + 1 and "5 more" in adds[-1]["detail"] and any(e["kind"] == "peer_up" for e in ev)
    ev, gone, _ = bgp.diff_peers({"10.0.0.1": b}, [], 1, t + timedelta(minutes=4))
    assert gone == ["10.0.0.1"] and ev[0]["kind"] == "peer_removed"


def test_parse_pan_peers():
    root = ET.fromstring("""<response status="success"><result>
      <entry peer="isp1" vr="default"><peer-address>203.0.113.1:179</peer-address><local-address>203.0.113.2:52011</local-address>
        <remote-as>65010</remote-as><status>Established</status><status-duration>3600</status-duration>
        <prefix-counter><entry afi-safi="bgpAfiIpv4-unicast"><incoming-accepted>812</incoming-accepted></entry></prefix-counter></entry>
      <entry peer="isp2"><peer-address>[2001:db8::1]:179</peer-address><remote-as>65020</remote-as><status>Active</status></entry>
    </result></response>""")
    a, b = bgp.parse_pan_peers(root)
    assert (a["peer"], a["remote_as"], a["state"], a["prefixes"], a["uptime_s"], a["local_ip"]) == ("203.0.113.1", 65010, "Established", 812, 3600, "203.0.113.2")
    assert (b["peer"], b["state"], b["prefixes"]) == ("2001:db8::1", "Active", None)


@pytest.mark.asyncio
async def test_poll_records_samples_and_events(clean_ch, db, monkeypatch):
    fw = Firewall(name="FGT-TEST-01", host="10.1.0.1", serial="FGTEST0000000001", vendor="fortinet")
    db.add(fw)
    await db.commit()
    rib1 = {"10.1.0.0/16": [{"peer": "10.0.0.1", "interface": "hq-tun", "gateway": "203.0.113.9", "installed": None}]}
    script = [{"peers": [_peer("10.0.0.1", "Established", {"10.1.0.0/16"}, 1)], "rib": rib1, "config": None},
              {"peers": [_peer("10.0.0.1", "Idle", set(), 0)], "rib": {}, "config": None}]

    async def fake(_fw, _want):
        return script.pop(0)
    monkeypatch.setattr(bgp, "_fortigate_poll", fake)
    await bgp.poll(fw, db, clean_ch)
    await db.commit()
    await bgp.poll(fw, db, clean_ch)
    await db.commit()
    p = (await db.execute(select(BgpPeer))).scalars().one()
    assert p.state == "Idle" and p.prefixes == 0 and fw.health["bgp"]["established"] == 0
    kinds = [r["kind"] for r in clean_ch.query("SELECT kind FROM bgp_events ORDER BY kind")]
    assert kinds == ["peer_down", "route_withdraw", "unreachable"] and p.interface == "hq-tun"
    assert clean_ch.query("SELECT count() AS n FROM bgp_samples")[0]["n"] == 2
    r = await bgp.report(clean_ch, db, NOW - timedelta(hours=1), NOW + timedelta(minutes=5))
    x = r["peers"][0]
    assert (x["status"], x["source"], x["routes_withdrawn"], x["firewall_name"]) == ("down", "api", 1, "FGT-TEST-01")


@pytest.mark.asyncio
async def test_bgp_alert_rules(clean_ch, db):
    await _ingest(clean_ch)
    await ensure_default_rules(db)
    for r in (await db.execute(select(AlertRule))).scalars():
        r.enabled = r.key.startswith("bgp_")
        if r.key.startswith("bgp_"):
            r.params = {**r.params, "interval_minutes": 0}
        if r.key == "bgp_peer_flap":
            r.params = {**r.params, "min_flaps": 2}
    await db.commit()
    res = await run_rules(clean_ch, db)
    assert res["bgp_peer_down"]["created"] == 2      # peer A (two drops, one alert per peer) and peer B (ongoing)
    assert res["bgp_peer_flap"]["created"] == 1      # peer A
    assert res["bgp_route_withdrawals"]["created"] == 0  # 60 withdrawals happened 29 min ago, outside the 15 min window


@pytest.mark.asyncio
async def test_bgp_api(api, clean_ch, db):  # noqa: F811
    await _ingest(clean_ch)
    h = await login(api, "analyst1")
    o = (await api.get("/api/bgp/overview", params={"range": "24h"}, headers=h)).json()
    assert o["totals"]["peers"] == 2, [(p["firewall_id"], p["peer"]) for p in o["peers"]]
    d = (await api.get("/api/bgp/peers/1/169.254.108.1", params={"range": "24h"}, headers=h)).json()
    assert d["flaps"] == 2 and len(d["events"]) >= 60 and "samples" in d
    assert (await api.get("/api/bgp/peers/1/not-an-ip", headers=h)).status_code == 422
    assert (await api.get("/api/bgp/peers/1/192.0.2.77", headers=h)).status_code == 404


# ------------------------------------------------------------------ analysis
from app import bgp_analysis as BA  # noqa: E402

FGT_CFG = {"as": "65021", "router-id": "10.254.255.2", "holdtime-timer": 180, "keepalive-timer": 60, "graceful-restart": "disable",
           "log-neighbour-changes": "enable", "network": [{"prefix": "172.29.0.0 255.255.0.0"}], "network6": [{"prefix6": "::/128"}],
           "neighbor": [
               {"ip": "169.254.1.1", "remote-as": "65021", "bfd": "disable", "password": "", "holdtime-timer": 4294967295,
                "keep-alive-timer": 4294967295, "maximum-prefix": 0, "route-map-in": "", "prefix-list-out": "", "shutdown": "disable"},
               {"ip": "10.9.0.2", "remote-as": "65021", "bfd": "enable", "password": "ENC xyz", "holdtime-timer": 30,
                "keep-alive-timer": 10, "maximum-prefix": 2000, "route-map-in": "rm-in", "route-map-out": "rm-out", "shutdown": "disable"},
               {"ip": "169.254.9.9", "remote-as": "65021", "shutdown": "enable"}]}


def test_config_sanitize_and_audit():
    c = BA.sanitize_fortigate_config(FGT_CFG)
    assert c["networks"] == ["172.29.0.0/16"] and c["local_as"] == 65021 and c["neighbors"]["10.9.0.2"]["password"] is True
    assert "ENC" not in str(c)  # secrets reduced to booleans
    peers = [{"peer": "169.254.1.1", "state": "Connect", "state_since": NOW - timedelta(days=3), "prefixes": 0, "interface": "mum-tun-1"},
             {"peer": "10.9.0.2", "state": "Established", "state_since": NOW - timedelta(days=3), "prefixes": 1055, "interface": "port6"}]
    f = BA.audit(c, peers, NOW)
    checks = {(x["peer"], x["check"]) for x in f}
    assert {("169.254.1.1", c) for c in ("stale", "password", "bfd", "holdtime", "max_prefix", "filter_in", "filter_out")} <= checks
    assert ("", "graceful_restart") in checks and ("169.254.9.9", "shutdown") in checks
    assert not any(p == "10.9.0.2" for p, _ in checks)  # fully hardened neighbor
    assert next(x for x in f if x["check"] == "password")["severity"] == "low"  # inside an IPsec tunnel
    assert 'edit "169.254.1.1"' in next(x for x in f if x["check"] == "bfd")["cli"]


def test_classify_and_security_events():
    own = [BA._net("172.29.0.0/16")]
    assert BA.classify_prefix("0.0.0.0/0", own, 65021) == [("default_route", "default route received")]
    assert [k for k, _ in BA.classify_prefix("172.29.8.0/24", own, 65021)] == ["more_specific"]
    assert [k for k, _ in BA.classify_prefix("198.18.0.0/16", own, 65021)] == ["bogon_prefix"]
    assert [k for k, _ in BA.classify_prefix("8.8.8.0/24", own, 65021)] == ["public_via_internal"]
    assert BA.classify_prefix("8.8.8.0/24", own, 3356) == [] and BA.classify_prefix("10.1.0.0/16", own, 65021) == []
    peer = BgpPeer(firewall_id=1, peer_ip="10.9.0.2", remote_as=65021)
    known = {f"10.{i}.0.0/16": NOW.isoformat() for i in range(30)}
    burst = {f"10.{i}.1.0/24" for i in range(25)}
    ev = BA.security_events(peer, burst | {"0.0.0.0/0"}, set(), known, NOW - timedelta(days=2), own, 1, NOW)
    kinds = [e["kind"] for e in ev]
    assert "leak_suspect" in kinds and "default_route" in kinds and kinds.count("new_prefix") == 26
    assert BA.security_events(peer, burst, set(), known, NOW - timedelta(hours=2), own, 1, NOW) == []  # new neighbor: no baseline yet
    assert BA.update_known({"1.0.0.0/8": (NOW - timedelta(days=8)).isoformat()}, {"2.0.0.0/8"}, NOW).keys() == {"2.0.0.0/8"}


def test_rib_diff_paths():
    a = {"10.12.100.0/24": [{"peer": "169.254.107.1", "interface": "FGT-PALO-TCL"}, {"peer": "169.254.108.1", "interface": "FGT-PALO-TTSL"}],
         "10.13.0.0/21": [{"peer": "169.254.100.1", "interface": "mum-tun-1"}]}
    b = {"10.12.100.0/24": [{"peer": "169.254.108.1", "interface": "FGT-PALO-TTSL"}]}
    ev = BA.rib_diff(a, b, 3, NOW)
    assert [(e["kind"], e["prefix"]) for e in ev] == [("path_change", "10.12.100.0/24"), ("unreachable", "10.13.0.0/21")]
    assert "FGT-PALO-TCL (169.254.107.1) + FGT-PALO-TTSL (169.254.108.1) → via FGT-PALO-TTSL" in ev[0]["detail"]
    assert BA.rib_diff(None, b, 3, NOW) == []


def test_prefix_stability_dampening():
    evs = []
    for i in range(3):  # three flaps within 6 minutes
        evs.append({"t": NOW - timedelta(minutes=6 - 2 * i), "firewall_id": 1, "firewall_name": "fw", "peer": "p", "prefix": "10.1.0.0/16", "kind": "route_withdraw"})
        evs.append({"t": NOW - timedelta(minutes=5 - 2 * i), "firewall_id": 1, "firewall_name": "fw", "peer": "p", "prefix": "10.1.0.0/16", "kind": "route_add"})
    evs.append({"t": NOW - timedelta(hours=5), "firewall_id": 1, "firewall_name": "fw", "peer": "p", "prefix": "10.2.0.0/16", "kind": "route_withdraw"})
    a, b = BA.prefix_stability(sorted(evs, key=lambda e: e["t"]), NOW)
    assert a["prefix"] == "10.1.0.0/16" and a["withdrawals"] == 3 and a["suppressed"] and a["would_have_been_suppressed"]
    assert b["penalty"] < 10 and not b["suppressed"]


@pytest.mark.asyncio
async def test_correlation_tunnel_and_time_in_state(clean_ch, db):
    from .test_ops import vpn
    sink = EventSink(clean_ch, registry())
    lines = [router(NOW - timedelta(minutes=30), "0103020300", "BGP: %BGP-5-ADJCHANGE: VRF 0 neighbor 169.254.100.1 Down Hold Timer Expired"),
             router(NOW - timedelta(minutes=20), "0103020300", "BGP: %BGP-5-ADJCHANGE: VRF 0 neighbor 169.254.100.1 Up "),
             vpn(NOW - timedelta(minutes=31), "0101037138", "mum-tun-1", 'action="tunnel-down"'),
             vpn(NOW - timedelta(minutes=21), "0101037138", "mum-tun-1", 'action="tunnel-up"')]
    for ln in lines:
        sink.add_line(ln, source="syslog", peer_ip="10.1.0.1")
    await sink.flush()
    db.add(Firewall(id=1, name="FGT-TEST-01", host="10.1.0.1", serial="FGTEST0000000001", vendor="fortinet"))
    await db.flush()
    db.add(BgpPeer(firewall_id=1, peer_ip="169.254.100.1", state="Established", interface="mum-tun-1", first_seen=NOW - timedelta(days=1),
                   last_polled_at=NOW - timedelta(hours=1)))
    await db.commit()
    r = await bgp.report(clean_ch, db, NOW - timedelta(hours=1), NOW + timedelta(seconds=1), correlate=True)
    d = r["peers"][0]["down_periods"][0]
    assert d["verdict"] == "Underlay IPsec tunnel down" and d["causes"][0]["type"] == "tunnel"
    x = r["peers"][0]
    assert x["mttr_s"] == 600 and x["longest_s"] == 600 and x["interface"] == "mum-tun-1"
    clean_ch.insert("bgp_samples", [{"ts": NOW - timedelta(minutes=10 - i), "firewall_id": 1, "peer": "169.254.100.1",
                                     "state": "Connect" if i < 4 else "Established", "up": int(i >= 4), "prefixes": 5} for i in range(10)],
                    ["ts", "firewall_id", "peer", "state", "up", "prefixes"])
    t = await BA.time_in_state(clean_ch, 1, "169.254.100.1", NOW - timedelta(hours=1), NOW)
    st = {x["state"]: x["seconds"] for x in t["states"]}
    assert st == {"Established": 300, "Connect": 240} and "TCP/179" in t["states"][1]["hint"]


@pytest.mark.asyncio
async def test_baseline_anomaly_rules_and_views(clean_ch, db, monkeypatch):
    fw = Firewall(id=1, name="FGT-TEST-01", host="10.1.0.1", serial="FGTEST0000000001", vendor="fortinet")
    db.add(fw)
    await db.commit()
    clean_ch.insert("bgp_samples", [{"ts": NOW - timedelta(hours=24) + timedelta(minutes=10 * i), "firewall_id": 1, "peer": "10.9.0.2",
                                     "state": "Established", "up": 1, "prefixes": 1050 if i < 140 else 300} for i in range(144)],
                    ["ts", "firewall_id", "peer", "state", "up", "prefixes"])
    routes = {f"10.{i // 250}.{i % 250}.0/24" for i in range(40)}
    rib = {p: [{"peer": "10.9.0.2", "interface": "port6", "gateway": "10.9.0.2", "installed": (NOW - timedelta(days=2)).isoformat()}] for p in routes}
    script = [{"peers": [_peer("10.9.0.2", "Established", routes, 300)], "rib": rib, "config": BA.sanitize_fortigate_config(FGT_CFG)},
              {"peers": [_peer("10.9.0.2", "Established", (routes - {"10.0.5.0/24"}) | {"172.29.4.0/24", "0.0.0.0/0"}, 300)],
               "rib": {k: v for k, v in rib.items() if k != "10.0.5.0/24"}, "config": None}]

    async def fake(_fw, _want):
        return script.pop(0)
    monkeypatch.setattr(bgp, "_fortigate_poll", fake)
    await bgp.poll(fw, db, clean_ch)
    await db.commit()
    await bgp.poll(fw, db, clean_ch)
    await db.commit()
    kinds = {r["kind"] for r in clean_ch.query("SELECT kind FROM bgp_events")}
    assert {"more_specific", "default_route", "route_withdraw", "route_add", "unreachable"} <= kinds
    # watchlist of critical prefixes
    from app.db.models import Watchlist, WatchlistItem
    w = Watchlist(name="bgp_critical_prefixes", kind="ip", created_by="t")
    db.add(w)
    await db.flush()
    db.add(WatchlistItem(watchlist_id=w.id, value="10.0.0.0/16", label="DC", added_by="t"))
    await db.commit()
    await ensure_default_rules(db)
    for r in (await db.execute(select(AlertRule))).scalars():
        r.enabled = r.key in ("bgp_prefix_anomaly", "bgp_route_leak", "bgp_critical_prefix")
        if r.enabled:
            r.params = {**r.params, "interval_minutes": 0}
    await db.commit()
    res = await run_rules(clean_ch, db)
    assert res["bgp_prefix_anomaly"]["created"] == 1          # 300 vs 1050 median
    assert res["bgp_route_leak"]["created"] == 2              # more-specific of own 172.29/16 + default route
    assert res["bgp_critical_prefix"]["created"] == 2         # 10.0.5.0/24 withdrawn and unreachable
    pr = await bgp.prefixes_report(clean_ch, db, NOW - timedelta(hours=1), NOW + timedelta(minutes=5))
    assert pr["totals"]["installed"] == 39 and pr["critical"]["exists"] and pr["totals"]["critical_installed"] > 0
    assert all(x["age_s"] >= 2 * 86400 - 60 for x in pr["rib"])
    au = await bgp.audit_report(db)
    assert au["firewalls"][0]["local_as"] == 65021 and au["by_severity"]
    sec = await bgp.security_report(clean_ch, db, NOW - timedelta(hours=1), NOW + timedelta(minutes=5))
    assert sec["by_kind"]["more_specific"] == 1 and {x["kind"] for x in sec["present"]} >= {"more_specific", "default_route"}
    from app.compliance import compliance_status
    c = await compliance_status(db)
    ctl = next(x for f in c["frameworks"] for x in f["controls"] if x["id"] == "A.8.20 (routing)")
    assert ctl["status"] == "partial" and "max_prefix" in ctl["evidence"]


def test_bfd_and_report_section_listed():
    p = bgp.parse_msg("BFD neighbor 169.254.100.1 state changed to DOWN")
    assert (p["kind"], p["peer"]) == ("bfd_down", "169.254.100.1")
    from app.reports import SECTIONS
    assert "bgp" in SECTIONS


@pytest.mark.asyncio
async def test_bgp_new_endpoints(api, clean_ch, db):  # noqa: F811
    await _ingest(clean_ch)
    h = await login(api, "analyst1")
    for path in ("/api/bgp/prefixes", "/api/bgp/audit", "/api/bgp/security", "/api/bgp/correlation"):
        r = await api.get(path, headers=h)
        assert r.status_code == 200, (path, r.text)
    c = (await api.get("/api/bgp/correlation", params={"range": "24h"}, headers=h)).json()
    assert len(c["drops"]) == 3 and all(d.get("verdict") for d in c["drops"])  # peer A twice, peer B ongoing
    assert c["verdicts"][0]["count"] >= 1


def test_interface_mapping_ignores_unset_local_ip():
    ifaces = [{"name": "ha", "ip": "0.0.0.0"}, {"name": "mum-tun-1", "ip": "169.254.100.2"}]
    assert bgp._interface_for({"peer": "169.254.102.2", "local_ip": ""}, {}, ifaces) == ""
    assert bgp._interface_for({"peer": "169.254.102.2", "local_ip": "0.0.0.0"}, {}, ifaces) == ""
    assert bgp._interface_for({"peer": "169.254.100.1", "local_ip": "169.254.100.2"}, {}, ifaces) == "mum-tun-1"
