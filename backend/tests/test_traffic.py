"""Application & Protocol Intelligence (app/traffic): classification, direction, deduplication, analytics on embedded
ClickHouse, detections, API (authentication, RBAC, validation) and exports.

Every flow row here is a test fixture inserted into the test database only."""
from datetime import datetime, timedelta, timezone

import pytest

from app.db.models import Switch, SwitchInterface, TrafficNetwork
from app.flows.server import FLOW_COLS
from app.traffic import analytics as A
from app.traffic import networks as N
from app.traffic import registry as R
from app.traffic.query import Filters

from .test_api import api  # noqa: F401  (fixture)

NOW = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=2)


def row(src, dst, sport, dport, proto=6, b=1000, pk=10, ex="192.0.2.1", ts=None, vlan=0, sampling=1, version="netflow9", in_if=3, out_if=7,
        l7="", flags=0, smac="", dmac=""):
    return {"ts": ts or NOW, "exporter": ex, "device_id": 1, "version": version, "in_if": in_if, "out_if": out_if, "src_ip": src, "dst_ip": dst,
            "src_port": sport, "dst_port": dport, "proto": proto, "bytes": b, "packets": pk, "vlan": vlan, "sampling": sampling,
            "src_mac": smac, "dst_mac": dmac, "tcp_flags": flags, "dst_vlan": 0, "l7": l7}


@pytest.fixture
def tch(ch):
    for t in ("flows", "flows_if_hourly", "flows_talkers_hourly", "flows_conv_hourly", "nms_self_metrics"):
        ch.command(f"TRUNCATE TABLE {t}")
    A.clear_cache()
    R.invalidate()
    N.invalidate()
    return ch


async def seed(db, ch, rows):
    sw = Switch(name="CORE", address="192.0.2.1", capabilities={}, group_state={}, health={}, thresholds={}, site="HQ")
    db.add(sw)
    await db.flush()
    db.add_all([SwitchInterface(switch_id=sw.id, ifindex=3, name="Gi1/0/3", present=True, speed_bps=1_000_000_000),
                SwitchInterface(switch_id=sw.id, ifindex=7, name="Te1/1/1", present=True)])
    await db.commit()
    await R.ensure_defaults(db)
    ch.insert("flows", rows, FLOW_COLS)
    return sw


BASIC = [
    row("10.1.1.10", "142.250.1.1", 50000, 443, 17, b=5000, l7="quic-v1", version="sflow5", sampling=512),
    row("10.1.1.10", "142.250.1.2", 50001, 443, 17, b=3000, version="sflow5", sampling=512),
    row("10.1.1.11", "8.8.8.8", 40000, 53, 17, b=200),
    row("10.1.1.12", "10.2.2.2", 40001, 443, 6, b=9000),
    row("10.2.2.2", "10.1.1.12", 443, 40001, 6, b=20000),
    row("10.1.1.13", "10.9.9.9", 51515, 23, 6, b=400),
    row("203.0.113.5", "10.1.1.14", 44444, 22, 6, b=700),
]


async def test_analytics_smoke(db, tch):
    await seed(db, tch, BASIC)
    f = Filters(range="1h")
    ov = await A.overview(db, tch, f)
    k = ov["kpis"]
    assert k["bytes"] == sum(r["bytes"] for r in BASIC)
    assert k["outbound"] == 8200 and k["inbound"] == 700 and k["internal"] == 29400
    assert k["sampled_bytes"] == 8000 and ov["source"] == "raw records"
    apps = {x["app"]: x for x in (await A.applications(db, tch, f, None, 50, 0))["items"]}
    assert apps["QUIC"]["confidence"] == "confirmed" and apps["QUIC (possible)"]["confidence"] == "port-based"
    assert apps["HTTPS"]["bytes"] == 29000 and apps["Telnet"]["bytes"] == 400 and apps["DNS"]["bytes"] == 200
    pr = await A.protocols(db, tch, f, 20)
    assert {p["name"] for p in pr["protocols"]} == {"TCP", "UDP"}
    srcs = await A.talkers(db, tch, f, "sources", None, 10, 0, sensitive=True)
    assert srcs["items"][0]["ip"] == "10.2.2.2" and srcs["total"] == 6
    conv = await A.conversations(db, tch, f, "-bytes", 5, 0, sensitive=True)
    assert conv["total"] == 7 and conv["items"][0]["src_ip"] == "10.2.2.2"
    fl = await A.flows(db, tch, f, 50, 0, sensitive=True)
    assert len(fl["items"]) == 7
    tr = await A.trends(db, tch, f, "app")
    assert sum(p["bytes"] for p in tr["points"]) == k["bytes"]
    web = await A.web_protocols(db, tch, f)
    assert {t["series"] for t in web["totals"]} >= {"UDP/443 QUIC confirmed (HTTP/3)", "UDP/443 possible QUIC"}
    vl = await A.vlans(db, tch, f, 50)
    assert vl["items"]
    ifs = await A.interfaces(db, tch, f, 50, lag_mode="members")
    assert ifs["items"][0]["name"] in ("Gi1/0/3", "Te1/1/1")
    col = await A.collectors(db, tch)
    assert col["exporters"][0]["device"] == "CORE"


# ------------------------------------------------------------------ decoding evidence
def _sflow_udp(payload: bytes, sport=50000, dport=443):
    import socket
    import struct
    eth = bytes.fromhex("aabbccddeeff") + bytes.fromhex("001122334455") + struct.pack("!H", 0x0800)
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0, socket.inet_aton("10.1.1.10"), socket.inet_aton("142.250.1.1"))
    header = eth + iph + udp
    rec = struct.pack("!IIII", 1, 1400, 4, len(header)) + header
    rec += b"\0" * ((4 - len(rec) % 4) % 4)
    flow_rec = struct.pack("!II", 1, len(rec)) + rec
    sample = struct.pack("!IIIIIIII", 1, 5, 256, 1000, 0, 12, 13, 1) + flow_rec
    return struct.pack("!II4sIIII", 5, 1, socket.inet_aton("192.0.2.1"), 0, 1, 1000, 1) + struct.pack("!II", 1, len(sample)) + sample


def test_sflow_quic_header_mac_and_flags_evidence():
    import struct

    from app.flows import decode as D
    (r,), _ = D.decode(_sflow_udp(b"\xc3" + struct.pack("!I", 1) + b"\x08" * 20), "192.0.2.1", D.Templates(), port_kind="sflow")
    assert r["l7"] == "quic-v1" and r["src_mac"] == "00:11:22:33:44:55" and r["dst_mac"] == "aa:bb:cc:dd:ee:ff"
    assert r["bytes"] == 1400 * 256 and r["sampling"] == 256
    (r,), _ = D.decode(_sflow_udp(b"\x41" + b"\x00" * 20), "192.0.2.1", D.Templates(), port_kind="sflow")
    assert r["l7"] == ""                              # short header: no proof, stays "possible QUIC"
    (r,), _ = D.decode(_sflow_udp(b"\xc3" + b"\x00" * 20, dport=4433), "192.0.2.1", D.Templates(), port_kind="sflow")
    assert r["l7"] == ""                              # not UDP/443: no QUIC claim


# ------------------------------------------------------------------ registry / direction
async def test_registry_classification_and_ambiguity(db):
    await R.ensure_defaults(db)
    R.invalidate()
    reg = await R.load(db)
    assert reg.port_app(6, 51000, 443) == ("HTTPS", "web")
    assert reg.port_app(6, 443, 51000) == ("HTTPS", "web")                   # reply direction: source port decides
    assert reg.port_app(17, 50000, 443)[0] == "QUIC (possible)"             # never "HTTP/3" from the port alone
    assert reg.port_app(6, 8080, 3306) == ("MySQL", "database")              # both registered: the lower port is the service
    assert reg.port_app(17, 50000, 3480)[0] == "Microsoft Teams media (possible)"
    assert reg.port_app(50, 0, 0)[0] == "IPsec ESP" and reg.port_app(6, 50000, 50001) == ("Unknown", "other")
    assert reg.domain_app("eu.teams.microsoft.com") == ("Microsoft Teams", "real-time") and reg.domain_app("notmicrosoft.com") is None
    n = await R.ensure_defaults(db)
    assert n == 0                                                            # seeded once


async def test_deleted_builtin_signature_is_not_reseeded(db):
    from sqlalchemy import select

    from app.db.models import TrafficSignature
    await R.ensure_defaults(db)
    row = (await db.execute(select(TrafficSignature).where(TrafficSignature.builtin_key == "tcp-23"))).scalar_one()
    await db.delete(row)
    await db.commit()
    await R.ensure_defaults(db)
    assert (await db.execute(select(TrafficSignature).where(TrafficSignature.builtin_key == "tcp-23"))).first() is None


async def test_direction_uses_configured_ranges_and_ipv6(db):
    N.invalidate()
    nets = await N.load(db)
    assert not nets.configured and nets.direction("10.0.0.1", "8.8.8.8") == "outbound" and nets.direction("fd00::1", "fd00::2") == "east_west"
    db.add_all([TrafficNetwork(cidr="198.51.100.0/24", name="public DMZ", internal=True, zone="dmz", vlan=50),
                TrafficNetwork(cidr="2001:db8::/32", name="v6 campus", internal=True, zone="corporate", vlan=60),
                TrafficNetwork(cidr="198.51.100.128/25", name="carved out", internal=False)])
    await db.commit()
    N.invalidate()
    nets = await N.load(db)
    assert nets.direction("198.51.100.5", "10.0.0.1") == "outbound"          # once ranges exist, private blocks are not implied
    assert nets.direction("198.51.100.200", "198.51.100.5") == "inbound"     # most specific range wins
    assert nets.direction("2001:db8::1", "2001:db8::2") == "east_west" and nets.lookup("2001:db8::9").vlan == 60
    assert nets.direction("bad-ip", "198.51.100.5") == "inbound"


# ------------------------------------------------------------------ dedup / rollups / LAG
async def test_dedup_counts_a_conversation_once_across_exporters(db, tch):
    rows = [row("10.1.1.10", "10.2.2.2", 50000, 445, b=1000, ex="192.0.2.1"), row("10.1.1.10", "10.2.2.2", 50000, 445, b=900, ex="192.0.2.9")]
    await seed(db, tch, rows)
    f = Filters(range="1h")
    assert (await A.overview(db, tch, f))["kpis"]["bytes"] == 1000
    from app.traffic.settings import save_settings
    await save_settings(db, {"dedup": "none"}, "t")
    await db.commit()
    A.clear_cache()
    assert (await A.overview(db, tch, f))["kpis"]["bytes"] == 1900


async def test_rollup_path_for_long_windows(db, tch):
    old = NOW - timedelta(days=2)
    await seed(db, tch, [row("10.1.1.10", "142.250.1.1", 50000, 443, b=7000, ts=old), row("10.1.1.10", "142.250.1.1", 50001, 443, b=3000)])
    f = Filters(range="7d")
    ov = await A.overview(db, tch, f)
    assert ov["source"].startswith("hourly rollups") and ov["kpis"]["bytes"] == 10000
    conv = await A.conversations(db, tch, f, None, 10, 0, sensitive=False)
    assert conv["items"][0]["app"] == "HTTPS" and conv["items"][0]["first"] is not None
    assert (await A.overview(db, tch, Filters(range="1h")))["kpis"]["bytes"] == 3000


async def test_lag_members_are_not_double_counted(db, tch):
    sw = await seed(db, tch, [row("10.1.1.1", "10.2.2.2", 1, 80, b=500, in_if=11, out_if=0), row("10.1.1.1", "10.2.2.2", 2, 80, b=700, in_if=12, out_if=0),
                              row("10.1.1.1", "10.2.2.2", 3, 80, b=1200, in_if=100, out_if=0)])
    db.add_all([SwitchInterface(switch_id=sw.id, ifindex=100, name="Po1", kind="lag", present=True),
                SwitchInterface(switch_id=sw.id, ifindex=11, name="Gi1/0/11", lag_ifindex=100, present=True),
                SwitchInterface(switch_id=sw.id, ifindex=12, name="Gi1/0/12", lag_ifindex=100, present=True)])
    await db.commit()
    res = await A.interfaces(db, tch, Filters(range="1h"), 50, lag_mode="members")
    by = {i["name"]: i for i in res["items"]}
    assert by["Po1"]["rx_bytes"] == 1200 and by["Po1"]["counted"] == "members"      # sum of members, not members + logical
    assert by["Gi1/0/11"]["counted"].startswith("member")


# ------------------------------------------------------------------ enrichment evidence
async def test_enrichment_evidence_levels(db):
    from app.traffic.enrich import classify
    await R.ensure_defaults(db)
    R.invalidate()
    reg = await R.load(db)
    c = classify("1.2.3.4", [("Microsoft.Teams", "Collaboration", 95), ("HTTPS.BROWSER", "Web", 40)], [], 8075, "MICROSOFT", reg)
    assert c["confidence"] == "confirmed" and c["app"] == "Microsoft.Teams"
    c = classify("1.2.3.4", [], ["teams.microsoft.com", "x.teams.microsoft.com"], 8075, "MICROSOFT", reg)
    assert (c["app"], c["confidence"]) == ("Microsoft Teams", "high")
    c = classify("1.2.3.4", [], [f"site{i}.example{i}.com" for i in range(8)] + ["meet.google.com"], 15169, "GOOGLE", reg)
    assert (c["app"], c["confidence"]) == ("Google", "probable") and "shared address" in " ".join(c["evidence"])   # CDN: no Meet claim
    c = classify("1.2.3.4", [], [], 15169, "GOOGLE", reg)
    assert (c["app"], c["confidence"]) == ("Google", "probable")                    # never "Google Meet" from the network alone
    assert classify("1.2.3.4", [], [], 0, "", reg)["confidence"] == "unknown"


async def test_enrichment_loop_uses_dns_logs(db, tch, clean_ch):
    await seed(db, tch, [row("10.1.1.10", "52.112.0.10", 50000, 443, b=9000)])
    clean_ch.insert("events", [{"event_id": "d1", "event_time": NOW, "ingest_time": NOW, "category": "dns", "event_type": "dns", "src_ip": "10.1.1.10",
                                "dst_ip": "10.0.0.53", "dns_qname": "eu.teams.microsoft.com", "dns_resolved": ["52.112.0.10"], "firewall_id": 1}],
                    ["event_id", "event_time", "ingest_time", "category", "event_type", "src_ip", "dst_ip", "dns_qname", "dns_resolved", "firewall_id"])
    from app.traffic.enrich import run_enrichment
    res = await run_enrichment(tch, db)
    assert res["enriched"] == 1 and res["dns_matched"] == 1
    A.clear_cache()
    apps = {x["app"]: x for x in (await A.applications(db, tch, Filters(range="1h"), None, 10, 0))["items"]}
    assert apps["Microsoft Teams"]["confidence"] == "high"
    dom = await A.domains(db, tch, Filters(range="1h"), 10, 0, None)
    assert dom["available"] and dom["items"][0]["domain"] == "eu.teams.microsoft.com" and dom["items"][0]["traffic_bytes"] == 9000


async def test_domains_unavailable_without_dns_logs(db, tch, clean_ch):
    dom = await A.domains(db, tch, Filters(range="1h"), 10, 0, None)
    assert dom["available"] is False and "DNS enrichment unavailable" in dom["reason"]


# ------------------------------------------------------------------ detections
async def _run(rule, ch, params=None):
    from app.traffic import detections as T
    p = {d["key"]: d["params"] for d in T.DEFAULT_RULES}[rule]
    return await T.RULES[rule](ch, datetime.now(timezone.utc), {**p, **(params or {})})


async def test_detection_mqtt_snmp_and_insecure(db, tch):
    await seed(db, tch, [row("10.1.1.50", "203.0.113.7", 40000, 1883, b=3000), row("10.1.1.51", "10.0.0.9", 40001, 8883, b=100),
                         row("10.9.9.9", "10.1.1.1", 50000, 161, 17, b=300), row("10.200.64.58", "10.1.1.2", 50001, 161, 17, b=300),
                         row("10.1.1.13", "10.9.9.9", 51515, 23, b=400)])
    from app.traffic.settings import save_settings
    out = await _run("traffic_unexpected_mqtt", tch)
    assert {d.group_key for d in out} == {"10.1.1.50|203.0.113.7|1883", "10.1.1.51|10.0.0.9|8883"}
    assert next(d for d in out if d.dst_ip == "203.0.113.7").severity == "high"
    await save_settings(db, {"mqtt_brokers": ["10.0.0.9/32"]}, "t")
    await db.commit()
    assert {d.dst_ip for d in await _run("traffic_unexpected_mqtt", tch)} == {"203.0.113.7"}     # approved broker: silent
    assert await _run("traffic_unauthorized_snmp", tch) == []                                     # not configured: never flags the NMS
    await save_settings(db, {"snmp_managers": ["10.200.64.58"]}, "t")
    await db.commit()
    (d,) = await _run("traffic_unauthorized_snmp", tch)
    assert d.src_ip == "10.9.9.9" and d.evidence["targets"] == 1
    ins = {d.evidence["app"]: d for d in await _run("traffic_insecure_protocol", tch)}
    assert set(ins) == {"Telnet", "MQTT"}                                                         # MQTT over TLS (8883) is not reported
    assert ins["Telnet"].dst_ip == "10.9.9.9" and ins["Telnet"].evidence["confidence"] == "port-based"


async def test_detection_scan_dns_and_thresholds(db, tch):
    scan = [row("10.1.1.66", "10.1.1.5", 40000 + i, 1 + i, b=60, flags=2) for i in range(120)]
    dns = [row("10.1.1.70", "8.8.4.4", 50000, 53, 17, b=6_000_000, pk=10_000)]
    await seed(db, tch, scan + dns)
    (d,) = await _run("traffic_port_scan", tch)
    assert d.evidence["ports"] == 120 and d.evidence["sequential"] and d.evidence["syn_only"] and d.severity == "high"
    assert await _run("traffic_port_scan", tch, {"min_ports": 500}) == []
    assert await _run("traffic_port_scan", tch, {"allow_sources": ["10.1.1.66/32"]}) == []
    (d,) = await _run("traffic_excessive_dns", tch, {"min_packets": 10**9})
    assert d.evidence["tunnel_indicator"] and d.src_ip == "10.1.1.70"                           # 600 bytes per DNS packet
    from app.traffic.settings import save_settings
    await save_settings(db, {"dns_resolvers": ["10.0.0.53"]}, "t")
    await db.commit()
    by = {x.src_ip: x for x in await _run("traffic_excessive_dns", tch, {"min_packets": 10**9, "tunnel_min_bytes": 10**12})}
    assert by["10.1.1.70"].evidence["unauthorised_resolvers"] == ["8.8.4.4"] and not by["10.1.1.70"].evidence["tunnel_indicator"]
    assert "10.1.1.66" not in by                                     # the scanner's SYN to TCP/53 is a probe, not DNS use
    assert await _run("traffic_insecure_protocol", tch) == []       # nor are its SYNs to 21 / 23 / 110 services in use


async def test_detection_vlan_policy_and_no_alert_for_plain_inter_vlan(db, tch):
    await seed(db, tch, [row("10.50.0.5", "10.10.0.5", 40000, 445, b=5000), row("10.10.0.6", "10.20.0.6", 40000, 445, b=5000)])
    db.add_all([TrafficNetwork(cidr="10.50.0.0/16", vlan=50, zone="guest", name="Guest"), TrafficNetwork(cidr="10.10.0.0/16", vlan=10, zone="corporate"),
                TrafficNetwork(cidr="10.20.0.0/16", vlan=20, zone="server")])
    await db.commit()
    N.invalidate()
    out = await _run("traffic_vlan_policy", tch)
    assert len(out) == 1 and out[0].evidence["src_zone"] == "guest" and out[0].evidence["policy"]["action"] == "deny"   # corporate → server: no policy, no alert
    vm = await A.vlan_matrix(db, tch, Filters(range="1h"), 50)
    pairs = {(x["src_vlan"], x["dst_vlan"]): x for x in vm["items"]}
    assert pairs[(50, 10)]["policy"]["action"] == "deny" and pairs[(10, 20)]["policy"] is None


async def test_new_external_destination_waits_for_learning_period(db, tch):
    await seed(db, tch, [row("10.1.1.10", "198.18.0.1", 50000, 443, b=80_000_000)])
    assert await _run("traffic_new_external_destination", tch) == []                             # no baseline history yet
    tch.insert("flows", [row("10.1.1.10", "203.0.113.200", 50000, 443, b=10, ts=NOW - timedelta(days=5))], FLOW_COLS)
    (d,) = await _run("traffic_new_external_destination", tch)
    assert d.dst_ip == "198.18.0.1" and d.evidence["sources"] == 1


async def test_engine_creates_and_dedupes_traffic_detections(db, tch):
    from app.alerts.engine import ensure_default_rules, run_rules
    await seed(db, tch, [row("10.1.1.50", "203.0.113.7", 40000, 1883, b=3000)])
    await ensure_default_rules(db)
    from app.alerts import engine
    engine._LAST_RUN.clear()
    res = await run_rules(tch, db, product="nms", correlate=False)
    assert res["traffic_unexpected_mqtt"]["created"] == 1
    res = await run_rules(tch, db, now=datetime.now(timezone.utc) + timedelta(minutes=6), product="nms", correlate=False)
    assert res["traffic_unexpected_mqtt"]["created"] == 0 and res["traffic_unexpected_mqtt"]["updated"] == 1


# ------------------------------------------------------------------ API
@pytest.fixture
async def tapi(api, db, tch):  # noqa: F811
    from app.db.models import User
    from app.security import hash_password

    from .test_api import PW
    db.add_all([User(username="engineer1", password_hash=hash_password(PW), role="analyst", products=["nms"], nms_roles=["network_engineer"]),
                User(username="gridonly", password_hash=hash_password(PW), role="analyst", products=["grid"]),
                User(username="scoped1", password_hash=hash_password(PW), role="analyst", products=["nms"], sites=["Branch"])])
    await db.commit()
    await seed(db, tch, BASIC + [row("10.1.1.10", "142.250.1.1", 50000, 443, 17, b=10, smac="00:aa:bb:cc:dd:ee")])
    return api


async def test_api_auth_rbac_and_validation(tapi, db):
    from .test_iac import As
    assert (await tapi.get("/api/nms/traffic/overview")).status_code == 401
    grid = await As.login(tapi, "gridonly")
    assert (await grid.get("/api/nms/traffic/overview")).status_code == 403
    viewer = await As.login(tapi, "analyst1")                       # NMS account without an NMS role: view only
    ov = await viewer.get("/api/nms/traffic/overview", params={"range": "1h"})
    assert ov.status_code == 200 and ov.json()["kpis"]["bytes"] > 0
    for bad in ({"range": "2y"}, {"src": "not-an-ip"}, {"interface": 3}, {"direction": "sideways"}, {"start": "2026-01-01T00:00:00"},
                {"start": "2026-01-01T00:00:00Z", "end": "2026-03-01T00:00:00Z"}):
        assert (await viewer.get("/api/nms/traffic/applications", params=bad)).status_code == 422, bad
    assert (await viewer.get("/api/nms/traffic/conversations", params={"sort": "password"})).status_code == 422
    assert (await viewer.get("/api/nms/traffic/domains")).status_code == 403                    # sensitive
    assert (await viewer.get("/api/nms/traffic/export/applications.csv")).status_code == 403    # export
    src = (await viewer.get("/api/nms/traffic/top-sources")).json()
    assert all(not x["mac"] for x in src["items"])                                               # MACs withheld
    eng = await As.login(tapi, "engineer1")
    src = (await eng.get("/api/nms/traffic/top-sources")).json()
    assert any(x["mac"] == "00:aa:bb:cc:dd:ee" for x in src["items"])
    csv = await eng.get("/api/nms/traffic/export/conversations.csv", params={"range": "1h"})
    assert csv.status_code == 200 and csv.text.splitlines()[0].startswith("src_ip,dst_ip") and len(csv.text.splitlines()) == 9
    assert (await viewer.post("/api/nms/traffic/networks", json={"cidr": "10.0.0.0/8"})).status_code == 403
    assert (await eng.post("/api/nms/traffic/networks", json={"cidr": "10.0.0.0/8"})).status_code == 403   # collector.manage: admins
    scoped = await As.login(tapi, "scoped1")
    assert (await scoped.get("/api/nms/traffic/overview")).json()["kpis"]["bytes"] == 0         # no exporter in its site


async def test_api_configuration_round_trip(tapi, db):
    from .test_iac import As
    adm = await As.login(tapi, "admin1")
    r = await adm.post("/api/nms/traffic/networks", json={"cidr": "10.1.1.0/24", "vlan": 11, "zone": "iot", "name": "IoT"})
    assert r.status_code == 201 and r.json()["cidr"] == "10.1.1.0/24"
    assert (await adm.post("/api/nms/traffic/networks", json={"cidr": "10.1.1.0/24"})).status_code == 409
    assert (await adm.post("/api/nms/traffic/networks", json={"cidr": "10.1.2.0/24", "zone": "moon"})).status_code == 422
    vl = (await adm.get("/api/nms/traffic/vlans")).json()
    assert any(x["vlan"] == 11 and x["zone"] == "iot" for x in vl["items"])
    assert (await adm.post("/api/nms/traffic/vlan-policies", json={"name": "x", "src": "zone:iot", "dst": "nowhere"})).status_code == 422
    assert (await adm.post("/api/nms/traffic/vlan-policies", json={"name": "iot-out", "src": "zone:iot", "dst": "external"})).status_code == 201
    s = await adm.post("/api/nms/traffic/signatures", json={"kind": "port", "proto": 6, "port_from": 9999, "app": "Lab App", "category": "other"})
    assert s.status_code == 201
    await adm.post("/api/nms/traffic/signatures", json={"kind": "domain", "match": "*.lab.example.com", "app": "Lab", "category": "saas"})
    assert (await adm.post("/api/nms/traffic/signatures", json={"kind": "port", "port_from": 1, "app": "x"})).status_code == 422
    assert (await adm.post("/api/nms/traffic/signatures", json={"kind": "port", "proto": 6, "port_from": 1, "port_to": 60000, "app": "x"})).status_code == 422
    r = await adm.put("/api/nms/traffic/settings", json={"dedup": "none", "snmp_managers": ["10.200.64.58"]})
    assert r.status_code == 200 and r.json()["snmp_managers"] == ["10.200.64.58/32"]
    assert (await adm.put("/api/nms/traffic/settings", json={"_seeded_signatures": []})).status_code == 422
    assert (await adm.put("/api/nms/traffic/settings", json={"snmp_managers": ["x"]})).status_code == 422
    from app.alerts.engine import ensure_default_rules
    await ensure_default_rules(db)
    r = await adm.put("/api/nms/traffic/detection-rules/traffic_port_scan", json={"params": {"min_ports": 30, "window_minutes": 20}, "severity": "medium"})
    assert r.status_code == 200 and r.json()["params"]["min_ports"] == 30
    assert (await adm.put("/api/nms/traffic/detection-rules/traffic_port_scan", json={"params": {"evil": 1}})).status_code == 422
    assert (await adm.put("/api/nms/traffic/detection-rules/traffic_port_scan", json={"params": {"window_minutes": 0}})).status_code == 422
    w = await adm.post("/api/nms/traffic/rules", json={"name": "lab", "ports": [9999], "dst_cidrs": ["10.0.0.0/8"], "min_bytes": 1})
    assert w.status_code == 201
    assert (await adm.post("/api/nms/traffic/rules", json={"name": "bad", "ports": [70000]})).status_code == 422
    assert (await adm.delete(f"/api/nms/traffic/rules/{w.json()['id']}")).status_code == 200
    from sqlalchemy import select

    from app.db.models import AuditLog
    acts = {a.action for a in (await db.execute(select(AuditLog))).scalars()}
    assert {"traffic_network_create", "traffic_signature_create", "traffic_settings_update", "traffic_rule_update"} <= acts


async def test_api_detection_workflow(tapi, db, tch):
    from app.alerts.engine import ensure_default_rules, run_rules

    from .test_iac import As
    await ensure_default_rules(db)
    tch.insert("flows", [row("10.1.1.50", "203.0.113.7", 40000, 1883, b=3000)], FLOW_COLS)
    from app.alerts import engine
    engine._LAST_RUN.clear()                                    # per-rule interval state from earlier tests
    await run_rules(tch, db, product="nms", correlate=False)
    eng = await As.login(tapi, "engineer1")
    d = (await eng.get("/api/nms/traffic/detections")).json()
    assert d["total"] >= 1
    did = next(x["id"] for x in d["items"] if x["rule_key"] == "traffic_unexpected_mqtt")
    r = await eng.c.patch(f"/api/nms/traffic/detections/{did}", headers=eng.h, json={"status": "investigating", "assignee": "engineer1", "notes": "checking"})
    assert r.status_code == 200 and r.json()["status"] == "investigating"
    assert (await eng.post(f"/api/nms/traffic/detections/{did}/suppress", json={"hours": 2})).status_code == 200   # rules.manage
    viewer = await As.login(tapi, "analyst1")
    assert (await viewer.post(f"/api/nms/traffic/detections/{did}/suppress", json={"hours": 2})).status_code == 403
    assert (await viewer.get("/api/nms/traffic/detections", params={"sort": "evil"})).status_code == 422


async def test_api_every_view_answers(tapi):
    from .test_iac import As
    adm = await As.login(tapi, "admin1")
    for path in ("overview", "applications", "protocols", "web", "top-sources", "top-destinations", "conversations", "flows", "vlans", "vlan-matrix",
                 "interfaces", "trends", "collectors", "options", "signatures", "networks", "vlan-policies", "settings", "rules", "detection-rules",
                 "detections", "hosts/10.1.1.10"):
        r = await adm.get(f"/api/nms/traffic/{path}", params={"range": "1h"})
        assert r.status_code == 200, (path, r.text)
    for view in ("applications", "top-sources", "top-destinations", "vlans", "vlan-matrix", "interfaces", "detections"):
        assert (await adm.get(f"/api/nms/traffic/export/{view}.csv")).status_code == 200, view
    assert (await adm.get("/api/nms/traffic/flows", params={"range": "7d"})).status_code == 422          # raw listing ≤ 24 h


# ------------------------------------------------------------------ VLAN resolution
def test_sflow_extended_switch_record_gives_vlans():
    import socket
    import struct

    from app.flows import decode as D
    eth = bytes.fromhex("aabbccddeeff001122334455") + struct.pack("!H", 0x0800)
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0, 64, 6, 0, socket.inet_aton("10.1.1.40"), socket.inet_aton("10.3.3.3"))
    header = eth + iph + struct.pack("!HH", 43210, 22) + b"\0" * 16
    hdr_rec = struct.pack("!IIII", 1, 1500, 4, len(header)) + header
    hdr_rec += b"\0" * ((4 - len(hdr_rec) % 4) % 4)
    sw_rec = struct.pack("!IIII", 317, 0, 319, 0)
    recs = struct.pack("!II", 1001, len(sw_rec)) + sw_rec + struct.pack("!II", 1, len(hdr_rec)) + hdr_rec
    sample = struct.pack("!IIIIIIII", 1, 5, 100, 1000, 0, 12, 13, 2) + recs
    dg = struct.pack("!II4sIIII", 5, 1, socket.inet_aton("192.0.2.30"), 0, 1, 1000, 1) + struct.pack("!II", 1, len(sample)) + sample
    (r,), st = D.decode(dg, "192.0.2.30", D.Templates(), port_kind="sflow")
    assert st["errors"] == 0 and (r["_sw_vlan"], r["_sw_dst_vlan"], r["dst_port"]) == (317, 319, 22)
    from app.flows.server import vlan_of
    alone = dict(r)
    vlan_of(alone, {})
    assert (alone["vlan"], alone["dst_vlan"]) == (317, 319) and "_sw_vlan" not in alone      # no MAC table: the port VLANs
    mac_wins = dict(r)
    vlan_of(mac_wins, {"aa:bb:cc:dd:ee:ff": 320})                     # the client (destination) MAC's VLAN beats the port's
    assert (mac_wins["vlan"], mac_wins["dst_vlan"]) == (320, 320)


def test_vlan_from_mac_tables_ignores_ambiguous_gateway_macs():
    from app.flows.server import vlan_of
    mv = {"00:00:00:00:00:a1": 317, "00:00:00:00:00:b2": 319}          # the gateway MAC is in every VLAN: absent from the map
    inbound = {"src_mac": "fe:fe:fe:fe:fe:fe", "dst_mac": "00:00:00:00:00:a1", "vlan": 0, "dst_vlan": 0}
    vlan_of(inbound, mv)
    assert (inbound["vlan"], inbound["dst_vlan"]) == (317, 317)        # internet → laptop: the client's VLAN
    outbound = {"src_mac": "00:00:00:00:00:b2", "dst_mac": "fe:fe:fe:fe:fe:fe", "vlan": 0, "dst_vlan": 0}
    vlan_of(outbound, mv)
    assert (outbound["vlan"], outbound["dst_vlan"]) == (319, 0)
    tagged = {"src_mac": "00:00:00:00:00:b2", "dst_mac": "", "vlan": 50, "dst_vlan": 0}
    vlan_of(tagged, mv)
    assert tagged["vlan"] == 50                                       # an exported tag always wins


async def test_collector_loads_unambiguous_mac_vlans(db, tch):
    from app.db.models import SwitchMac
    from app.flows.server import Collector
    sw = await seed(db, tch, [])
    db.add_all([SwitchMac(switch_id=sw.id, mac="00:00:00:00:00:a1", vlan_id=317), SwitchMac(switch_id=sw.id, mac="fe:fe:fe:fe:fe:fe", vlan_id=317),
                SwitchMac(switch_id=sw.id, mac="fe:fe:fe:fe:fe:fe", vlan_id=318), SwitchMac(switch_id=sw.id, mac="00:00:00:00:00:c3", vlan_id=319, present=False)])
    await db.commit()
    c = Collector(tch)
    await c.exporters.load()
    assert c.exporters.mac_vlan == {"00:00:00:00:00:a1": 317}
