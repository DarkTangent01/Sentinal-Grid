"""Parser test framework: every sample in fixtures/parser_samples.yml must normalize to the listed fields.
Also the properties every parser must keep: the raw line is preserved, a line is never lost, ids are stable."""
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from app.db.ch_schema import EVENT_COLUMNS
from app.ingest import formats
from app.ingest.generic import KINDS, parse

SAMPLES = yaml.safe_load((Path(__file__).parent / "fixtures" / "parser_samples.yml").read_text())


def src(kind):
    return {"id": 7, "name": "lab-source", "kind": kind, "site": "LAB"}


@pytest.mark.parametrize("sample", SAMPLES, ids=[s["name"] for s in SAMPLES])
def test_sample_normalizes(sample):
    ev = parse(src(sample["kind"]), sample["line"])
    assert ev is not None
    got = {k: ev[k] for k in sample["expect"]}
    assert got == sample["expect"]
    assert set(EVENT_COLUMNS) <= set(ev), "every event carries every column"
    assert ev["raw"] == sample["line"].strip(), "the original line is preserved"
    assert ev["firewall_name"] == "lab-source" and ev["site"] == "LAB" and ev["devid"] == sample["kind"]
    assert ev["event_id"] == parse(src(sample["kind"]), sample["line"])["event_id"], "same line, same id (dedupe)"


def test_every_kind_has_samples_and_falls_back_to_plain():
    assert {s["kind"] for s in SAMPLES} >= {"zeek", "json", "leef", "linux", "netdev", "syslog"}
    for kind in KINDS:
        ev = parse(src(kind), "this is not in any known format ~~~")
        assert ev is not None and ev["event_type"] == "syslog" and ev["msg"].startswith("this is not")
    for kind in ("zeek", "json"):
        assert parse(src(kind), '{"broken": ')["event_type"] == "syslog"       # truncated JSON is kept, not dropped
        assert parse(src(kind), "[1, 2, 3]")["event_type"] == "syslog"


def test_zeek_logs_of_one_connection_share_the_uid():
    conn = parse(src("zeek"), SAMPLES[0]["line"])
    dns = parse(src("zeek"), SAMPLES[1]["line"])
    assert conn["log_id"] == dns["log_id"] and conn["session_id"] == dns["session_id"] and conn["session_id"] > 0
    assert formats.zeek_uid_num("CHhAvVGS1DHFjwGM9") == str(conn["session_id"])


def test_zeek_is_not_counted_as_firewall_traffic_and_is_never_severe_by_itself():
    for s in SAMPLES:
        if s["kind"] == "zeek":
            ev = parse(src("zeek"), s["line"])
            assert ev["category"] == "zeek" and ev["severity"] in ("informational", "low", "medium")


def test_syslog_header():
    h = formats.syslog_header('<34>1 2026-11-14T10:00:00.003Z host1 su 123 ID1 [x@1 a="b\\]c"][y@2] hello')
    assert (h["rfc"], h["host"], h["app"], h["msgid"], h["msg"], h["facility"], h["severity"]) == ("5424", "host1", "su", "ID1", "hello", 4, "critical")
    assert h["ts"] == datetime(2026, 11, 14, 10, 0, 0, 3000, tzinfo=timezone.utc)
    h = formats.syslog_header("<13>Feb  5 17:32:18 10.0.0.99 myapp[77]: Use the BFG!")
    assert (h["rfc"], h["host"], h["app"], h["procid"], h["msg"], h["severity"]) == ("3164", "10.0.0.99", "myapp", "77", "Use the BFG!", "low")
    assert formats.syslog_header("no header here")["rfc"] == "" and formats.syslog_header("<999>1 x")["pri"] is None
