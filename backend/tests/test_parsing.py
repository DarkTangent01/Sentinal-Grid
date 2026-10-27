"""Parsing and normalization tests (fixtures are sanitized TEST DATA)."""
from datetime import datetime, timezone

import pytest

from app.ingest.normalize import fingerprint, normalize, parse_event_time, shannon_entropy
from app.ingest.parser import ParseError, parse_kv

from .conftest import fixture_lines


def test_parse_quoted_values_and_envelope():
    f = parse_kv('<189>Oct 21 10:00:00 fw1 date=2026-10-21 time=10:00:00 type="traffic" msg="a \\"quoted\\" value" x=1')
    assert f["type"] == "traffic" and f["msg"] == 'a "quoted" value' and f["x"] == "1"


def test_parse_rfc5424_envelope():
    f = parse_kv('<189>1 2026-10-21T10:00:00Z fw1 - - - - logid="0000000013" type="traffic" srcip=10.0.0.1')
    assert f["srcip"] == "10.0.0.1"


@pytest.mark.parametrize("line", ["", "hello world", "<13>just text", "foo=bar baz=1"])
def test_parse_rejects_non_fortigate(line):
    with pytest.raises(ParseError):
        parse_kv(line)


def test_traffic_normalization():
    line = fixture_lines()[0]
    ev = normalize(parse_kv(line), source="syslog", raw=line)
    assert ev["category"] == "traffic"
    assert ev["src_ip"] == "10.1.1.10" and ev["dst_port"] == 443 and ev["proto"] == 6 and ev["proto_name"] == "TCP"
    assert ev["action"] == "close" and ev["policy_id"] == 5 and ev["policy_name"] == "LAN-to-WAN"
    assert ev["sent_bytes"] == 1500 and ev["rcvd_bytes"] == 9000 and ev["session_id"] == 1001
    assert ev["nat_src_ip"] == "198.51.100.1" and ev["nat_src_port"] == 40001
    assert ev["app"] == "HTTPS.BROWSER" and ev["service"] == "HTTPS"
    assert ev["event_time"].tzinfo == timezone.utc and ev["event_time"].year == 2026
    assert ev["raw"].startswith("<189>")


def test_deny_normalization():
    ev = normalize(parse_kv(fixture_lines()[1]), source="syslog")
    assert ev["action"] == "deny" and ev["policy_id"] == 0


def test_dns_normalization():
    ev = normalize(parse_kv(fixture_lines()[2]), source="syslog")
    assert ev["category"] == "dns" and ev["dns_qname"] == "www.example.com" and ev["dns_qtype"] == "A"
    assert ev["dns_resolved"] == ["203.0.113.80", "203.0.113.81"] and ev["dst_ip"] == "10.1.0.53"
    assert ev["action"] == "allow" and ev["dns_rcode"] == ""  # not logged -> not invented


def test_web_hostname_and_path_not_merged_into_url():
    ev = normalize(parse_kv(fixture_lines()[3]), source="syslog")
    assert ev["category"] == "web" and ev["hostname"] == "bad.example.net"
    assert ev["url"] == "/login.php" and ev["url_is_full"] == 0  # never manufacture a full URL
    assert ev["action"] == "block" and ev["url_category"] == "Phishing"


def test_full_url_flagged():
    ev = normalize({"type": "utm", "subtype": "webfilter", "url": "https://x.example.com/a", "hostname": "x.example.com"}, source="syslog")
    assert ev["url_is_full"] == 1


def test_event_log_and_severity():
    ev = normalize(parse_kv(fixture_lines()[4]), source="syslog")
    assert ev["category"] == "system" and ev["severity"] == "critical" and ev["orig_severity"] == "alert"
    assert ev["user"] == "admin" and "failed" in ev["msg"]


def test_ips_direct_severity():
    ev = normalize({"type": "utm", "subtype": "ips", "severity": "high", "level": "alert", "attack": "X"}, source="syslog")
    assert ev["category"] == "security" and ev["severity"] == "high" and ev["threat"] == "X"


@pytest.mark.parametrize("et,expected", [
    ("1792577730123456789", 1792577730.123456),
    ("1792577730123456", 1792577730.123456),
    ("1792577730123", 1792577730.123),
    ("1792577730", 1792577730.0),
])
def test_eventtime_units(et, expected):
    dt, trusted = parse_event_time({"eventtime": et})
    assert trusted and abs(dt.timestamp() - expected) < 0.001


def test_date_time_with_tz_offset():
    dt, trusted = parse_event_time({"date": "2026-10-21", "time": "15:45:00", "tz": "+0530"})
    assert trusted and dt == datetime(2026, 10, 21, 10, 15, tzinfo=timezone.utc)


def test_missing_and_invalid_fields_do_not_crash():
    ev = normalize({"type": "traffic", "srcport": "abc", "dstport": "99999", "proto": "-1", "sentbyte": "", "policyid": "x"}, source="syslog")
    assert ev["src_port"] is None and ev["dst_port"] is None and ev["proto"] is None
    assert ev["sent_bytes"] == 0 and ev["policy_id"] is None
    assert ev["parser_version"].endswith("+ingest-ts")  # no timestamp: flagged as ingest time


def test_unknown_action_kept():
    ev = normalize({"type": "traffic", "action": "weird"}, source="syslog")
    assert ev["action"] == "other" and ev["orig_action"] == "weird"


def test_interim_delta_bytes():
    ev = normalize({"type": "traffic", "sentbyte": "10000", "sentdelta": "500", "rcvdbyte": "2000", "rcvddelta": "100"}, source="syslog")
    assert ev["sent_bytes"] == 500 and ev["rcvd_bytes"] == 100


def test_fingerprint_stable_across_formats():
    a = {"devid": "FG1", "eventtime": "123", "logid": "13", "sessionid": "9", "srcip": "10.0.0.1"}
    b = {"devid": "FG1", "eventtime": 123, "logid": "13", "sessionid": 9, "srcip": "10.0.0.1"}
    assert fingerprint(a) == fingerprint(b)
    assert fingerprint(a) != fingerprint({**a, "sessionid": "10"})  # distinct sessions are never merged


def test_entropy_and_tunnel_fields():
    ev = normalize({"type": "utm", "subtype": "dns", "qname": "a8f3k2l9q0z7x6c5v4b3n2m1.t.example.net"}, source="syslog")
    assert ev["dns_qname_len"] > 30 and ev["dns_entropy"] > 3.5
    assert shannon_entropy("aaaa") == 0
