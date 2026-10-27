"""Next-gen features: threat intel, query language, travel, drift, compliance (pure logic). SYNTHETIC TEST FIXTURES."""
from datetime import datetime, timedelta, timezone

import pytest

from app.alerts.travel import find_impossible_travel, haversine_km
from app.analytics.ql import QLError, compile_ql
from app.compliance import evaluate
from app.drift import assess_risks, diff
from app.enrich.enricher import Enricher
from app.enrich.geo import GeoResolver
from app.enrich.ti import IndicatorSet, parse_feed
from app.incidents import compute
from app.notify import build_request, in_quiet_hours


# ------------------------------------------------------------------ threat intel
def test_parse_plain_ip_feed_skips_comments_and_private():
    # public test addresses (documentation ranges are non-routable and deliberately ignored)
    text = "# Feodo blocklist\n1.0.0.7\n10.0.0.1\n198.51.100.7\n1.0.0.9 # comment\n\n"
    assert parse_feed(text, "ip") == [("1.0.0.7", "ip"), ("1.0.0.9", "ip")]


def test_parse_spamhaus_json_cidrs():
    text = '{"cidr":"1.10.16.0/20","sblid":"SBL1"}\n{"cidr":"192.168.0.0/16"}\n{"type":"metadata","timestamp":1}'
    assert parse_feed(text, "cidr") == [("1.10.16.0/20", "cidr")]


def test_parse_hostfile_domains():
    text = "# URLhaus\n127.0.0.1\tlocalhost\n127.0.0.1\tEvil.Example.COM\n127.0.0.1\tbad-site.example.net.\nnot a domain\n"
    assert parse_feed(text, "domain") == [("evil.example.com", "domain"), ("bad-site.example.net", "domain")]


def test_indicator_matching():
    ti = IndicatorSet([("198.51.100.7", "ip", "feodo", "botnet_c2"), ("1.10.16.0/20", "cidr", "drop", "hijacked"),
                       ("1.20.0.0/24", "cidr", "drop", "hijacked"), ("evil.example.com", "domain", "urlhaus", "malware")])
    assert ti.match_ip("198.51.100.7").source == "feodo"
    assert ti.match_ip("1.10.31.255").indicator == "1.10.16.0/20" and ti.match_ip("1.10.32.0") is None
    assert ti.match_ip("1.20.0.5").indicator == "1.20.0.0/24"
    assert ti.match_domain("cdn.evil.example.com").indicator == "evil.example.com"
    assert ti.match_domain("example.com") is None and ti.match_domain("notevil.example.com") is None
    ev = {"src_ip": "10.0.0.5", "dst_ip": "8.8.8.8", "dns_qname": "x.evil.example.com", "hostname": ""}
    assert ti.match_event(ev).category == "malware"


def test_enricher_marks_events_and_keeps_fortigate_country():
    e = Enricher(geo=GeoResolver(None), ti=IndicatorSet([("198.51.100.7", "ip", "feodo", "botnet_c2")]))
    ev = {"src_ip": "10.0.0.5", "dst_ip": "198.51.100.7", "dns_qname": "", "hostname": "", "src_country": "", "dst_country": "United States",
          "ti_match": "", "ti_source": "", "ti_category": ""}
    e.apply(ev)
    assert ev["ti_match"] == "198.51.100.7" and ev["ti_category"] == "botnet_c2" and ev["dst_country"] == "United States"


# ------------------------------------------------------------------ query language
@pytest.mark.parametrize("q", [
    "src_ip:10.0.0.0/8 AND action:deny AND dst_port:445", "port:1-1024 bytes>=1000 OR NOT country:China",
    'firewall:GGN* -user:admin "login failed"', "(src:10.0.0.1 OR dst:10.0.0.1) category:dns qname:example",
    "ti:* proto:tcp", "asn>=13335 as_org:*cloud*", "user!=svc_backup", "",
])
def test_ql_valid(q):
    compile_ql(q)


@pytest.mark.parametrize("q, msg", [
    ("foo:1", "unknown field"), ("src_ip:1.2.3", "invalid IP"), ("(action:deny", "unexpected end"),
    ("action:deny)", "unexpected"), ("dst_port:abc", "expects a number"), ("src_ip>1.2.3.4", "supports ':' only"),
    ("src_ip:1.1.1.1' OR 1=1", "invalid IP"), ("proto:bogus", "unknown protocol"),
])
def test_ql_errors(q, msg):
    with pytest.raises(QLError, match=msg):
        compile_ql(q)


def test_ql_values_are_parameters_never_sql():
    c = compile_ql('msg:"\'; DROP TABLE events; --" user:"x\') OR (1=1"')
    assert "DROP" not in c.sql and "1=1" not in c.sql and len(c.params) == 2


def test_ql_wildcard_escaping():
    c = compile_ql("app:50%_off*")
    assert list(c.params.values()) == ["50\\%\\_off%"]


# ------------------------------------------------------------------ impossible travel
def test_haversine():
    assert 6500 < haversine_km((22.0, 79.0), (52.2, 5.3)) < 7200  # India -> Netherlands


def test_impossible_travel_with_coordinates_and_centroids():
    t = datetime(2026, 10, 23, 10, 0, tzinfo=timezone.utc)
    rows = [{"user": "rahul", "event_time": t, "src_ip": "198.51.100.10", "src_country": "India", "src_lat": None, "src_lon": None, "firewall_id": 1},
            {"user": "rahul", "event_time": t + timedelta(minutes=10), "src_ip": "198.51.100.20", "src_country": "Netherlands",
             "src_lat": None, "src_lon": None, "firewall_id": 2},
            {"user": "priya", "event_time": t, "src_ip": "198.51.100.11", "src_country": "", "src_lat": 28.6, "src_lon": 77.2, "firewall_id": 1},
            {"user": "priya", "event_time": t + timedelta(hours=10), "src_ip": "198.51.100.12", "src_country": "", "src_lat": 19.1, "src_lon": 72.9, "firewall_id": 1}]
    found = find_impossible_travel(rows)
    assert len(found) == 1 and found[0]["user"] == "rahul" and found[0]["approximate"] is True and found[0]["kmh"] > 30000


# ------------------------------------------------------------------ drift
BASE = {"policy": {"1": {"name": "web", "status": "enable", "action": "accept", "srcaddr": ["LAN"], "dstaddr": ["all"], "service": ["HTTPS"], "logtraffic": "all"}},
        "interface": {"wan1": {"name": "wan1", "role": "wan", "allowaccess": ["ping"]}, "port1": {"name": "port1", "role": "lan", "allowaccess": ["https", "ssh"]}},
        "admin": {"admin": {"name": "admin", "accprofile": "super_admin", "trusthost1": "10.0.0.0 255.0.0.0", "two-factor": "fortitoken"}},
        "global": {"admin-https-redirect": "enable", "strong-crypto": "enable"}}


def test_drift_diff_and_risks_only_for_changes():
    import copy
    new = copy.deepcopy(BASE)
    new["policy"]["2"] = {"name": "temp", "status": "enable", "action": "accept", "srcaddr": ["all"], "dstaddr": ["all"], "service": ["ALL"], "logtraffic": "all"}
    new["interface"]["wan1"]["allowaccess"] = ["ping", "https", "http"]
    new["admin"]["vendor"] = {"name": "vendor", "accprofile": "super_admin", "trusthost1": "0.0.0.0 0.0.0.0"}
    new["global"]["strong-crypto"] = "disable"
    ch = diff(BASE, new)
    kinds = {(c["table"], c["key"], c["change"]) for c in ch}
    assert ("policy", "2", "added") in kinds and ("interface", "wan1", "modified") in kinds and ("admin", "vendor", "added") in kinds
    risks = assess_risks(new, ch)
    titles = " | ".join(r["title"] for r in risks)
    assert "any source → any destination" in titles and "WAN interface wan1" in titles and "insecure management" in titles
    assert "no trusted hosts" in titles and "New administrator account vendor" in titles and "strong-crypto" in titles
    assert not any(r["key"] == "port1" for r in risks)  # unchanged LAN interface not re-reported


def test_drift_baseline_reports_existing_risks():
    bad = {**BASE, "interface": {"wan1": {"name": "wan1", "role": "wan", "allowaccess": ["ssh"]}}}
    assert any("WAN interface" in r["title"] for r in assess_risks(bad, None))


# ------------------------------------------------------------------ compliance
def _facts(**kw):
    now = datetime.now(timezone.utc)
    f = {"now": now, "retention": {"traffic": 30, "dns": 30, "web": 90, "security": 365, "system": 365}, "min_retention": 30,
         "ingest_recent": True, "last_ingest": now, "firewalls": 1, "rules": {f"r{i}": True for i in range(12)}, "ti_feeds_ok": 0,
         "incidents": 0, "assets": 0, "critical_assets": 0, "snapshots": 0, "last_policy_review": None, "daily_report": False, "notify_rules": 0}
    f.update(kw)
    return f


def _status(fw, cid):
    return next(c["status"] for x in fw for c in x["controls"] if c["id"] == cid)


def test_compliance_statuses_follow_configuration():
    fw = evaluate(_facts())
    assert _status(fw, "CERT-In 4(iv)") == "not_met" and _status(fw, "10.5.1") == "not_met" and _status(fw, "A.5.7") == "not_met"
    assert _status(fw, "CERT-In 4(i)") == "manual"
    fw = evaluate(_facts(min_retention=400, ti_feeds_ok=2, snapshots=3, daily_report=True, last_policy_review=datetime.now(timezone.utc)))
    assert _status(fw, "CERT-In 4(iv)") == "met" and _status(fw, "10.5.1") == "met" and _status(fw, "A.5.7") == "met"
    assert _status(fw, "10.4.1") == "met" and _status(fw, "1.2.7") == "met" and _status(fw, "A.8.9") == "met"


# ------------------------------------------------------------------ incidents (pure)
class A:
    def __init__(self, sev, tactic, key, crit=""):
        now = datetime.now(timezone.utc)
        self.severity, self.mitre, self.rule_key, self.asset_criticality = sev, {"tactic": tactic, "techniques": ["T1"]}, key, crit
        self.first_seen = self.last_seen = now
        self.name = key


def test_incident_severity_escalates_with_tactics():
    from app.db.models import Incident
    inc = Incident(entity="10.0.0.5", entity_type="ip", created_at=datetime.now(timezone.utc))
    compute(inc, [A("medium", "TA0007", "port_scan")])
    assert inc.severity == "medium"
    compute(inc, [A("medium", "TA0007", "port_scan"), A("medium", "TA0006", "admin_login_fail")])
    assert inc.severity == "high" and "multi-stage" in inc.title
    compute(inc, [A("low", "TA0007", "a"), A("low", "TA0006", "b"), A("low", "TA0005", "c")])
    assert inc.severity == "critical" and inc.sla_ack_due - inc.created_at == timedelta(minutes=15)


# ------------------------------------------------------------------ notifications (pure)
class R:
    quiet_start, quiet_end, quiet_tz = "22:00", "07:00", "Asia/Kolkata"


def test_quiet_hours_wrap_midnight_in_timezone():
    assert in_quiet_hours(R(), datetime(2026, 10, 23, 18, 0, tzinfo=timezone.utc))  # 23:30 IST
    assert not in_quiet_hours(R(), datetime(2026, 10, 23, 6, 0, tzinfo=timezone.utc))  # 11:30 IST


def test_payload_builders():
    from app.db.models import NotificationChannel
    p = {"title": "T", "text": "x", "fields": {"Source": "10.0.0.1"}, "url": "https://siem/alerts?id=1", "severity": "high"}
    slack = build_request(NotificationChannel(type="slack", config={}), p, {"url": "https://hooks.slack.com/x"})
    assert "*T*" in slack["json"]["text"] and "Open in SIEM" in slack["json"]["text"]
    teams = build_request(NotificationChannel(type="teams", config={}), p, {"url": "https://x.webhook.office.com/y"})
    assert teams["json"]["attachments"][0]["content"]["type"] == "AdaptiveCard"
    import hashlib
    import hmac
    wh = build_request(NotificationChannel(type="webhook", config={}), p, {"url": "https://h/x", "hmac_secret": "k"})
    assert wh["headers"]["X-SIEM-Signature"] == "sha256=" + hmac.new(b"k", wh["content"], hashlib.sha256).hexdigest()
    em = build_request(NotificationChannel(type="email", config={"from_addr": "siem@x", "to": ["soc@x"]}), p, {})
    assert em["message"]["To"] == "soc@x" and em["message"]["Subject"] == "T"
