"""Identity index (app/platform/identity.py) with its product contributors, device intelligence, behaviour baselines,
threat intel on flows and alert → incident escalation. Flow and event rows are fixtures in the test databases only."""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.db.models import HostIdentity, IpMacBinding, IpUserBinding, Switch, SwitchMac, WirelessClient
from app.flows.server import FLOW_COLS
from app.platform import identity as I

from .test_api import api  # noqa: F401  (fixture)
from .test_traffic import NOW, row, tch  # noqa: F401  (fixture)


@pytest.fixture(autouse=True)
def _fresh():
    I._STATE.clear()
    yield


def test_vendor_classification_and_mac_rules():
    assert I.vendor_of("00:00:0a:11:22:33").startswith("Omron")
    assert I.vendor_of("fe:69:97:4b:59:9a") == "" and I.is_randomized("fe:69:97:4b:59:9a")
    assert not I.is_unicast_host_mac("01:00:5e:00:00:01") and not I.is_unicast_host_mac("ff:ff:ff:ff:ff:ff")
    assert I.norm_mac("70B2.5826.F60C") == "70:b2:58:26:f6:0c" and I.norm_mac("70-B2-58-26-F6-0C") == "70:b2:58:26:f6:0c" and I.norm_mac("x") == ""
    assert I.classify({"vendor": "Hangzhou Hikvision Digital Technology"})[:2] == ("IP camera", "probable")
    assert I.classify({"fortigate_devtype": "Phone", "os": "Android", "vendor": "Hikvision"})[:2] == ("Phone or tablet", "high")   # fingerprint beats vendor
    assert I.classify({"inventory": "Network equipment", "vendor": "Apple"})[:2] == ("Network equipment", "confirmed")
    assert I.classify({"server_ports": {554}})[0] == "IP camera"
    assert I.classify({"randomized": True, "wireless": True})[0] == "Mobile device (private MAC)"
    assert I.classify({})[0] == ""
    assert I.router_macs([("10.0.0.1", "aa"), ("10.0.0.2", "aa"), ("10.0.0.3", "aa"), ("10.0.0.4", "aa"), ("10.0.0.9", "bb")]) == {"aa"}


async def test_contributors_store_and_read(db, tch, clean_ch):  # noqa: F811
    from app.enrich import identity_sources  # noqa: F401  (registration)
    from app.traffic import identity_sources as nms_sources  # noqa: F401
    sw = Switch(name="ACC-1", address="192.0.2.1", capabilities={}, group_state={}, health={}, thresholds={}, site="HQ")
    wlc = Switch(name="WLC-1", address="192.0.2.5", device_type="wlc", capabilities={}, group_state={}, health={}, thresholds={}, site="HQ")
    db.add_all([sw, wlc])
    await db.flush()
    db.add_all([SwitchMac(switch_id=sw.id, mac="00:00:0a:00:00:01", vlan_id=317, ifindex=14, port_name="Gi1/0/14"),
                WirelessClient(wlc_id=wlc.id, mac="fe:69:97:4b:59:9a", ip="10.10.10.50", username="asha", ssid="CORP", vlan=318, present=True,
                               last_seen=NOW)])
    await db.commit()
    # sFlow: one host MAC and one gateway MAC behind many addresses (never bound as a host)
    gw = "70:b2:58:26:f6:0c"
    tch.insert("flows", [row("10.10.10.20", "8.8.8.8", 5000, 53, 17, smac="00:00:0a:00:00:01", dmac=gw)]
               + [row("1.1.1.1", f"10.10.10.{30 + i}", 443, 5000, 6, smac=gw, dmac="") for i in range(6)], FLOW_COLS)
    # FortiGate traffic logs: device detection for a phone, and the router MAC (devtype Router)
    ev = lambda i, ip, extra: {"event_id": f"e{i}", "event_time": NOW, "ingest_time": NOW, "category": "traffic", "event_type": "traffic",  # noqa: E731
                               "src_ip": ip, "dst_ip": "8.8.8.8", "firewall_id": 1, "raw": f'date=x srcip={ip} {extra} dstip=8.8.8.8'}
    clean_ch.insert("events", [ev(1, "10.10.10.60", 'srcmac="aa:00:00:00:00:61" srchwvendor="OnePlus" devtype="Phone" osname="Android" srcname="pixel-7"'),
                               ev(2, "10.10.10.61", 'srcmac="70:b2:58:26:f6:0c" srchwvendor="Ruckus Wireless" devtype="Router"'),
                               {"event_id": "v1", "event_time": NOW, "ingest_time": NOW, "category": "system", "event_type": "event", "event_subtype": "vpn",
                                "src_ip": "203.0.113.9", "dst_ip": "", "firewall_id": 1, "user": "ravi", "raw": 'tunnelip=10.212.134.200 user="ravi"'}],
                    ["event_id", "event_time", "ingest_time", "category", "event_type", "src_ip", "dst_ip", "firewall_id", "raw", "user", "event_subtype"])
    res = await I.run_identity(tch, db, now=NOW + timedelta(minutes=1))
    assert all("error" not in v for k, v in res.items() if k != "stored"), res
    binds = {(b.ip, b.mac, b.source) for b in (await db.execute(select(IpMacBinding))).scalars()}
    assert ("10.10.10.20", "00:00:0a:00:00:01", "sflow") in binds and ("10.10.10.50", "fe:69:97:4b:59:9a", "wireless") in binds
    assert ("10.10.10.60", "aa:00:00:00:00:61", "fortigate") in binds
    assert not any(m == gw for _, m, _ in binds)                                         # router MAC never bound to an address
    users = {(b.ip, b.username, b.source) for b in (await db.execute(select(IpUserBinding))).scalars()}
    assert {("10.10.10.50", "asha", "wireless"), ("10.212.134.200", "ravi", "vpn"), ("203.0.113.9", "ravi", "vpn_remote")} <= users
    hosts = {h.mac: h for h in (await db.execute(select(HostIdentity))).scalars()}
    assert hosts[gw].device_type == "Network equipment" and hosts[gw].vendor == "Ruckus Wireless"
    phone = hosts["aa:00:00:00:00:61"]
    assert (phone.device_type, phone.device_type_confidence, phone.os, phone.hostname) == ("Phone or tablet", "high", "Android", "pixel-7")
    pc = hosts["00:00:0a:00:00:01"]
    assert (pc.switch, pc.port, pc.vlan, pc.site) == ("ACC-1", "Gi1/0/14", 317, "HQ") and pc.vendor.startswith("Omron")
    wl = hosts["fe:69:97:4b:59:9a"]
    assert wl.randomized and wl.device_type == "Mobile device (private MAC)" and wl.ssid == "CORP" and wl.last_user == "asha"
    got = await I.identities(db, ["10.10.10.20", "10.10.10.50", "10.212.134.200", "8.8.8.8"])
    assert got["10.10.10.20"]["switch"] == "ACC-1" and got["10.10.10.50"]["user"] == "asha" and got["10.212.134.200"]["user"] == "ravi"
    assert "8.8.8.8" not in got
    assert (await I.identities(db, ["10.10.10.50"], sensitive=False))["10.10.10.50"]["user"] == ""
    tl = await I.timeline(db, "10.10.10.50")
    assert tl["macs"][0]["mac"] == "fe:69:97:4b:59:9a" and tl["users"][0]["user"] == "asha"
    again = await I.run_identity(tch, db, now=NOW + timedelta(minutes=2))                 # idempotent: counts grow, no duplicates
    assert "stored" in again
    assert len({(b.ip, b.mac, b.source) for b in (await db.execute(select(IpMacBinding))).scalars()}) == len(binds)


async def test_identity_api_and_sensitivity(api, db, tch):  # noqa: F811
    from app.security import hash_password

    from .test_api import PW
    from .test_iac import As
    db.add_all([IpMacBinding(ip="10.1.1.5", mac="00:00:0a:00:00:05", source="sflow", first_seen=NOW, last_seen=NOW),
                IpUserBinding(ip="10.1.1.5", username="asha", source="vpn", first_seen=NOW, last_seen=NOW),
                HostIdentity(mac="00:00:0a:00:00:05", vendor="Omron", device_type="Computer", device_type_confidence="probable", last_ip="10.1.1.5")])
    from app.db.models import User
    db.add(User(username="nmsview", password_hash=hash_password(PW), role="analyst", products=["nms"]))
    await db.commit()
    a = await As.login(api, "analyst1")                                                     # has Sentinel Grid: sees users
    r = (await a.get("/api/identities/ip/10.1.1.5")).json()
    assert r["current"]["user"] == "asha" and r["current"]["mac"] == "00:00:0a:00:00:05" and r["sensitive"]
    v = await As.login(api, "nmsview")                                                      # NMS without a sensitive role
    r = (await v.get("/api/identities/ip/10.1.1.5")).json()
    assert r["current"]["user"] == "" and r["current"]["mac"] == "" and r["current"]["device_type"] == "Computer" and r["timeline"]["users"] == []
    d = (await a.get("/api/identities/devices", params={"device_type": "Computer"})).json()
    assert d["total"] == 1 and d["items"][0]["vendor"] == "Omron"
    assert (await a.get("/api/identities/devices", params={"sort": "evil"})).status_code == 422
    assert (await a.get("/api/identities/ip/not-an-ip")).status_code == 422
    assert (await api.get("/api/identities/ip/10.1.1.5")).status_code == 401


async def test_behaviour_baseline_and_rule(db, tch):  # noqa: F811
    from app.traffic import baselines as B
    from app.traffic import detections as T
    hour = (datetime.now(timezone.utc) - timedelta(hours=1)).replace(minute=10, second=0, microsecond=0)
    rows = []
    for d in range(1, 9):                       # eight normal days: ~20 MB upload in this hour
        rows.append(row("10.1.1.10", "142.250.1.1", 50000, 443, 6, b=20_000_000, ts=hour - timedelta(days=d)))
    rows.append(row("10.1.1.10", "142.250.1.1", 50000, 443, 6, b=900_000_000, ts=hour))   # this hour: 900 MB
    rows.append(row("10.1.1.11", "142.250.1.1", 50000, 443, 6, b=300_000_000, ts=hour))   # big, but always big:
    for d in range(1, 9):
        rows.append(row("10.1.1.11", "142.250.1.1", 50000, 443, 6, b=280_000_000, ts=hour - timedelta(days=d)))
    tch.insert("flows", rows, FLOW_COLS)
    assert B.robust([0, 0, 0, 10]) == (0.0, 0.0)
    p = {d["key"]: d["params"] for d in T.DEFAULT_RULES}["traffic_behaviour_anomaly"]
    out = await T.RULES["traffic_behaviour_anomaly"](tch, datetime.now(timezone.utc), {**p, "scopes": ["host"]})
    assert [(d.src_ip, d.evidence["metric"]) for d in out] == [("10.1.1.10", "bytes_out")]
    assert out[0].evidence["factor"] >= 40 and out[0].severity == "high"
    prof = await B.profile(tch, "10.1.1.10", hours=24)
    assert not prof["learning"] and any(pt["bytes_out"] == 900_000_000 for pt in prof["points"])


async def test_behaviour_rule_waits_for_learning(db, tch):  # noqa: F811
    from app.traffic import detections as T
    tch.insert("flows", [row("10.1.1.10", "142.250.1.1", 50000, 443, 6, b=900_000_000)], FLOW_COLS)
    p = {d["key"]: d["params"] for d in T.DEFAULT_RULES}["traffic_behaviour_anomaly"]
    assert await T.RULES["traffic_behaviour_anomaly"](tch, datetime.now(timezone.utc), p) == []


async def test_threat_intel_on_flows(db, tch):  # noqa: F811
    from app.db.models import TiFeed, TiIndicator
    from app.enrich import ti_flows
    feed = TiFeed(name="lab-feed", url="https://example.invalid/feed", kind="ip", category="c2", enabled=True)
    db.add(feed)
    await db.flush()
    db.add_all([TiIndicator(feed_id=feed.id, indicator="198.51.100.66", type="ip"), TiIndicator(feed_id=feed.id, indicator="203.0.113.0/24", type="cidr")])
    await db.commit()
    ti_flows._ENRICHER = None
    tch.insert("flows", [row("10.1.1.20", "198.51.100.66", 51000, 443, 6, b=5000), row("203.0.113.7", "10.1.1.21", 4444, 51000, 6, b=700),
                         row("10.1.1.22", "8.8.8.8", 51000, 53, 17, b=100)], FLOW_COLS)
    out = await ti_flows.rule_ti_flow_match(tch, datetime.now(timezone.utc), ti_flows.DEFAULT_RULE["params"])
    got = {(d.src_ip, d.evidence["indicator"], d.evidence["feed"]) for d in out}
    assert got == {("10.1.1.20", "198.51.100.66", "lab-feed"), ("10.1.1.21", "203.0.113.0/24", "lab-feed")}
    assert next(d for d in out if d.src_ip == "10.1.1.21").evidence["bytes_in"] == 700


async def test_alert_escalates_to_incident(api, db, tch):  # noqa: F811
    from app.db.models import Alert, Incident

    from .test_iac import As
    a = Alert(rule_key="traffic_unexpected_mqtt", name="Unexpected MQTT traffic", severity="high", status="new", group_key="g", open_seq=0,
              src_ip="10.1.1.50", dst_ip="203.0.113.7", first_seen=NOW, last_seen=NOW, event_count=3, explanation="x")
    db.add(a)
    await db.commit()
    c = await As.login(api, "analyst1")
    r = await c.post(f"/api/incidents/from-alert/{a.id}", json={"note": "from NMS"})
    assert r.status_code == 201, r.text
    inc = r.json()
    again = (await c.post(f"/api/incidents/from-alert/{a.id}", json={})).json()
    assert again["id"] == inc["id"]                                                         # one incident per alert
    i = await db.get(Incident, inc["id"])
    await db.refresh(a)
    assert a.incident_id == i.id and i.entity == "10.1.1.50" and i.severity == "high"
