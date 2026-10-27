"""Policy analytics engine. All policies/objects here are SYNTHETIC TEST FIXTURES (RFC 1918/5737/3849 ranges)."""
from datetime import datetime, timedelta, timezone


from app.policy.model import config_hash, normalize_policy
from app.policy.objects import ObjectResolver, parse_portrange
from app.policy.sets import AddrSpace, IntervalSet, ServiceSpace
from app.policy.shadow import analyze
from app.policy.usage import CounterPoint, assess, counter_deltas

OBJECTS = {
    "address": [
        {"name": "LAN", "type": "ipmask", "subnet": "10.10.0.0 255.255.0.0"},
        {"name": "LAN-Servers", "type": "ipmask", "subnet": "10.10.5.0 255.255.255.0"},
        {"name": "Guest", "type": "ipmask", "subnet": "192.168.50.0 255.255.255.0"},
        {"name": "Range", "type": "iprange", "start-ip": "10.10.1.10", "end-ip": "10.10.1.20"},
        {"name": "CloudApp", "type": "fqdn", "fqdn": "app.example.com"},
        {"name": "Ext-Web", "type": "ipmask", "subnet": "203.0.113.0 255.255.255.0"},
    ],
    "addrgrp": [{"name": "Internal", "member": [{"name": "LAN"}, {"name": "Guest"}]},
                {"name": "LAN-minus-servers", "member": [{"name": "LAN"}], "exclude": "enable", "exclude-member": [{"name": "LAN-Servers"}]}],
    "address6": [{"name": "LAN6", "type": "ipprefix", "ip6": "2001:db8:10::/48"}, {"name": "LAN6-sub", "type": "ipprefix", "ip6": "2001:db8:10:5::/64"}],
    "service_custom": [
        {"name": "ALL", "protocol": "IP", "protocol-number": 0},
        {"name": "HTTP", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "80"},
        {"name": "HTTPS", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "443"},
        {"name": "DNS", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "53", "udp-portrange": "53"},
        {"name": "WebHigh", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "8000-8100"},
        {"name": "Web8080", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "8080"},
        {"name": "SrcRestricted", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "443:1024-2048"},
        {"name": "PING", "protocol": "ICMP", "icmptype": 8},
    ],
    "service_group": [{"name": "Web", "member": [{"name": "HTTP"}, {"name": "HTTPS"}]}],
    "zone": [{"name": "LAN-ZONE", "interface": [{"interface-name": "port1", "name": "port1"}, {"name": "port2"}]}],
}


def pol(pid, seq, **kw):
    raw = {"policyid": pid, "name": f"P{pid}", "status": "enable", "action": "accept", "srcintf": [{"name": "port1"}],
           "dstintf": [{"name": "wan1"}], "srcaddr": [{"name": "LAN"}], "dstaddr": [{"name": "all"}],
           "service": [{"name": "HTTPS"}], "schedule": "always", "logtraffic": "all", "uuid": f"uuid-{pid}"}
    for k, v in kw.items():
        raw[k.replace("_", "-")] = [{"name": x} for x in v] if isinstance(v, list) else v
    return normalize_policy(raw, seq)


# ------------------------------------------------------------------ sets
def test_interval_set_ops():
    a = IntervalSet([(1, 10), (5, 20), (30, 40)])
    assert a.iv == [(1, 20), (30, 40)] and a.size() == 31
    assert a.difference(IntervalSet([(5, 35)])).iv == [(1, 4), (36, 40)]
    assert a.covers(IntervalSet([(2, 3), (31, 39)])) and not a.covers(IntervalSet([(19, 25)]))


def test_ipv4_ipv6_spaces():
    lan = AddrSpace.from_network("10.10.0.0/16")
    assert lan.covers(AddrSpace.from_network("10.10.5.0/24"))
    assert not AddrSpace.from_network("10.10.5.0/24").covers(lan)
    v6 = AddrSpace.from_network("2001:db8:10::/48")
    assert v6.covers(AddrSpace.from_network("2001:db8:10:5::/64")) and not lan.covers(v6)
    assert AddrSpace.any4().union(AddrSpace.any6()).covers(v6.union(lan))


def test_portrange_parsing_and_service_cover():
    iv, src = parse_portrange("80 443 1000-2000:1024-65535")
    assert iv.iv == [(80, 80), (443, 443), (1000, 2000)] and src is True
    web = ServiceSpace({6: IntervalSet([(8000, 8100)])})
    assert web.covers(ServiceSpace({6: IntervalSet([(8080, 8080)])}))
    assert not ServiceSpace({6: IntervalSet([(443, 443)])}).covers(ServiceSpace({17: IntervalSet([(443, 443)])}))
    assert ServiceSpace.any().covers(ServiceSpace(protos=IntervalSet([(47, 47)])))  # ALL covers GRE


def test_resolver_groups_exclusion_and_uncertainty():
    r = ObjectResolver(OBJECTS)
    grp = r.address(["Internal"])
    assert grp.space.covers(AddrSpace.from_network("192.168.50.7/32")) and not grp.uncertain
    ex = r.address(["LAN-minus-servers"]).space
    assert not ex.covers(AddrSpace.from_network("10.10.5.1/32")) and ex.covers(AddrSpace.from_network("10.10.6.1/32"))
    assert r.address(["CloudApp"]).uncertain and r.address(["Nope"]).missing == ["Nope"]
    assert r.address(["Range"]).space.v4.size() == 11
    assert "source ports" in r.service(["SrcRestricted"]).uncertain[0]


# ------------------------------------------------------------------ shadow
def _find(res, later):
    return [f for f in res["findings"] if f["later_policyid"] == later]


def test_full_shadow_deny_above_allow():
    ps = [pol(1, 1, action="deny", srcaddr=["LAN"], service=["ALL"]), pol(2, 2, srcaddr=["LAN-Servers"], service=["HTTPS"])]
    f = _find(analyze(ps, OBJECTS), 2)
    assert len(f) == 1 and f[0]["classification"] == "full_shadow" and f[0]["severity"] == "high" and f[0]["confidence"] == "high"
    assert all(v == "full" for v in f[0]["dimensions"].values())


def test_redundant_same_action():
    ps = [pol(1, 1, service=["Web"]), pol(2, 2, srcaddr=["LAN-Servers"], service=["HTTPS"])]
    f = _find(analyze(ps, OBJECTS), 2)
    assert f[0]["classification"] == "redundant" and f[0]["severity"] == "low"


def test_order_matters_no_shadow_when_specific_first():
    # specific allow above a broad deny is the normal exception pattern, not a shadow
    ps = [pol(1, 1, srcaddr=["LAN-Servers"]), pol(2, 2, action="deny", srcaddr=["LAN"], service=["ALL"])]
    assert analyze(ps, OBJECTS)["findings"] == []


def test_partial_deny_blocks_part_of_later_allow():
    ps = [pol(1, 1, action="deny", srcaddr=["LAN-Servers"], service=["ALL"]), pol(2, 2, srcaddr=["LAN"])]
    f = _find(analyze(ps, OBJECTS), 2)
    assert f[0]["classification"] == "partial_shadow" and f[0]["severity"] == "medium" and f[0]["dimensions"]["source"] == "partial"


def test_partial_shadow_ports():
    ps = [pol(1, 1, action="deny", service=["Web8080"]), pol(2, 2, service=["WebHigh"])]
    f = _find(analyze(ps, OBJECTS), 2)
    assert f[0]["classification"] == "partial_shadow" and f[0]["dimensions"]["service"] == "partial"


def test_shared_destination_only_is_not_shadow():
    ps = [pol(1, 1, srcaddr=["Guest"], dstaddr=["Ext-Web"]), pol(2, 2, srcaddr=["LAN"], dstaddr=["Ext-Web"])]
    assert analyze(ps, OBJECTS)["findings"] == []  # disjoint sources -> no relationship


def test_interfaces_and_zones():
    ps = [pol(1, 1, srcintf=["LAN-ZONE"], action="deny", service=["ALL"]), pol(2, 2, srcintf=["port2"])]
    assert _find(analyze(ps, OBJECTS), 2)[0]["classification"] == "full_shadow"  # zone contains port2
    ps = [pol(1, 1, srcintf=["port3"], action="deny", service=["ALL"]), pol(2, 2, srcintf=["port2"])]
    assert analyze(ps, OBJECTS)["findings"] == []


def test_ipv6_policies():
    ps = [pol(1, 1, srcaddr=[], srcaddr6=["LAN6"], dstaddr=[], dstaddr6=["all6"], action="deny", service=["ALL"]),
          pol(2, 2, srcaddr=[], srcaddr6=["LAN6-sub"], dstaddr=[], dstaddr6=["all6"])]
    assert _find(analyze(ps, OBJECTS), 2)[0]["classification"] == "full_shadow"


def test_disabled_policies_neither_shadow_nor_assessed():
    ps = [pol(1, 1, status="disable", action="deny", service=["ALL"]), pol(2, 2), pol(3, 3, status="disable")]
    res = analyze(ps, OBJECTS)
    assert res["findings"] == [] and res["policy_status"][3]["analysis"] == "disabled"


def test_uncertain_objects_never_full_shadow():
    ps = [pol(1, 1, dstaddr=["CloudApp"], action="deny", service=["ALL"]), pol(2, 2, dstaddr=["CloudApp"])]
    f = _find(analyze(ps, OBJECTS), 2)
    assert f and f[0]["classification"] == "overlap" and f[0]["confidence"] == "low"
    assert any("fqdn" in a for a in f[0]["assumptions"])


def test_schedule_and_identity_uncertainty():
    ps = [pol(1, 1, schedule="business-hours", action="deny", service=["ALL"]), pol(2, 2)]
    f = _find(analyze(ps, OBJECTS), 2)
    assert f[0]["classification"] == "overlap" and any("schedules differ" in a for a in f[0]["assumptions"])
    ps = [pol(1, 1, groups=["Finance"], action="deny", service=["ALL"]), pol(2, 2)]
    assert _find(analyze(ps, OBJECTS), 2)[0]["classification"] == "overlap"
    ps = [pol(1, 1, srcaddr_negate="enable", action="deny", service=["ALL"]), pol(2, 2)]
    assert _find(analyze(ps, OBJECTS), 2)[0]["classification"] == "overlap"


def test_missing_objects_reported_unknown():
    res = analyze([pol(1, 1, srcaddr=["Ghost"])], OBJECTS)
    assert res["policy_status"][1]["analysis"] == "unknown" and res["policy_status"][1]["missing"] == ["Ghost"]


def test_config_hash_ignores_sequence():
    assert config_hash(pol(1, 1)) == config_hash(pol(1, 7)) != config_hash(pol(1, 1, action="deny"))


# ------------------------------------------------------------------ counters + usage
T0 = datetime(2026, 9, 1, tzinfo=timezone.utc)


def cp(days, hits, uuid="u1"):
    return CounterPoint(T0 + timedelta(days=days), uuid, hits, hits * 100 if hits is not None else None, hits)


def test_counter_deltas_handle_resets_and_uuid_reuse():
    d = counter_deltas([cp(0, 100), cp(1, 150), cp(2, 20), cp(3, 50)])  # reboot between day1 and day2
    assert d["hits"] == 50 + 20 + 30 and d["resets"] == 1
    d = counter_deltas([cp(0, 100), cp(1, 120, uuid="u2")])  # policy id reused by a new policy
    assert d["hits"] == 120 and d["uuid_changes"] == 1
    assert counter_deltas([cp(0, None), cp(1, 5)])["hits"] == 0  # missing values are not zeros
    assert counter_deltas([cp(0, 5), cp(0, 5)])["hits"] == 0  # duplicate snapshot


WEND = T0 + timedelta(days=60)
WSTART = WEND - timedelta(days=60)


def a(**kw):
    base = dict(policy={"status": "enable", "type": "firewall", "logtraffic": "all"}, window_start=WSTART, window_end=WEND,
                counters=None, counter_last_used=None, siem_matches=0, siem_last_seen=None, ingest_since=None, min_days=30)
    base.update(kw)
    return assess(**base)


def test_usage_states():
    assert a(policy={"status": "disable"})["state"] == "disabled"
    assert a(counters=counter_deltas([cp(0, 1), cp(10, 9)]))["state"] == "in_use"
    assert a(siem_matches=4, siem_last_seen=WEND)["state"] == "in_use"
    flat = counter_deltas([cp(0, 7), cp(45, 7)])
    assert a(counters=flat) == {**a(counters=flat), "state": "potentially_unused", "confidence": "high"}
    short = counter_deltas([cp(50, 7), cp(55, 7)])
    assert a(counters=short)["state"] == "no_observed_hits"
    assert a(ingest_since=WSTART)["state"] == "potentially_unused"  # 60 days of logs, logtraffic=all
    assert a(ingest_since=WEND - timedelta(days=3))["state"] == "no_observed_hits"
    assert a(policy={"status": "enable", "logtraffic": "utm"}, ingest_since=WSTART)["state"] == "unknown"  # incomplete logging
    assert a()["state"] == "unknown"
