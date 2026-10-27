"""Pipeline query language: compilation safety and results against embedded ClickHouse."""
import pytest

from app.analytics.filters import EventFilter
from app.analytics.pipeline import PipelineError, compile_pipeline, run_pipeline, watchlist_names

from .test_storage_analytics import _load, traffic


def dns(i, client, qname, rcode="NOERROR"):
    from datetime import datetime, timedelta, timezone
    ts = datetime.now(timezone.utc) - timedelta(minutes=2)
    return {"type": "utm", "subtype": "dns", "devid": "FGTEST0000000001", "eventtime": str(int(ts.timestamp() * 1e9) + i),
            "logid": "1501054802", "srcip": client, "dstip": "8.8.8.8", "dstport": "53", "proto": "17", "qname": qname,
            "qtype": "A", "action": "pass", "sessionid": str(9000 + i), "msg": "DNS query"}


@pytest.fixture
async def loaded(clean_ch):
    recs = [traffic(i, src="10.0.0.1", dst="203.0.113.1", dport=443, sent=100, rcvd=200) for i in range(10)]
    recs += [traffic(100 + i, src="10.0.0.2", dst=f"203.0.113.{10 + i}", dport=22, action="deny", sent=0, rcvd=0) for i in range(4)]
    recs += [traffic(200, src="192.168.1.5", dst="198.51.100.7", dport=3389, sent=5000, rcvd=10)]
    recs += [dns(300 + i, "10.0.0.1", f"h{i}.evil.example") for i in range(3)]
    await _load(clean_ch, recs)
    return clean_ch


async def run(ch, q, **wl):
    return await run_pipeline(ch, q, EventFilter(range="1h"), wl or None)


async def test_stats_sort_head(loaded):
    r = await run(loaded, "category:traffic | stats count, dc(dst_ip) as dsts, sum(sent_bytes) as sent by src_ip | sort -count | head 2")
    assert r["kind"] == "table"
    assert [x["src_ip"] for x in r["rows"]] == ["10.0.0.1", "10.0.0.2"]
    assert r["rows"][0]["count"] == 10 and r["rows"][0]["sent"] == 1000
    assert r["rows"][1]["dsts"] == 4


async def test_where_eval_and_alias_fields(loaded):
    r = await run(loaded, "| where category = \"traffic\" | eval total = sent_bytes + rcvd_bytes | where total > 1000 | fields src, dst_ip, total")
    assert r["columns"] == ["src", "dst_ip", "total"]
    assert r["rows"] == [{"src": "192.168.1.5", "dst_ip": "198.51.100.7", "total": 5010}]


async def test_where_after_stats_uses_outputs(loaded):
    r = await run(loaded, "action:deny | stats count by src_ip, dst_port | where count >= 4")
    assert r["rows"] == [{"src_ip": "10.0.0.2", "dst_port": 22, "count": 4}]
    with pytest.raises(PipelineError, match="unknown field 'dst_ip'"):
        await run(loaded, "| stats count by src_ip | where dst_ip = \"1.1.1.1\"")


async def test_top_rare_percent(loaded):
    r = await run(loaded, "category:traffic | top 2 dst_port")
    assert r["rows"][0] == {"dst_port": 443, "count": 10, "percent": pytest.approx(66.67, 0.01)}
    r = await run(loaded, "category:traffic | rare dst_port limit=1")
    assert r["rows"][0]["dst_port"] == 3389


async def test_timechart_pivots_series(loaded):
    r = await run(loaded, "category:traffic | timechart span=1m count by action")
    assert r["kind"] == "timechart" and set(r["series"]) == {"close", "deny"}
    assert sum(row["close"] for row in r["rows"]) == 11 and sum(row["deny"] for row in r["rows"]) == 4


async def test_functions_cidr_private_case(loaded):
    r = await run(loaded, "category:traffic | where cidrmatch(\"192.168.0.0/16\", src_ip) | eval zone = case(isprivate(dst_ip), \"internal\", true, \"external\") | fields src_ip, zone")
    assert r["rows"] == [{"src_ip": "192.168.1.5", "zone": "external"}]
    r = await run(loaded, "category:dns | eval d = domain(dns_qname) | stats dc(dns_qname) as names by d")
    assert r["rows"] == [{"d": "evil.example", "names": 3}]


async def test_dedup_and_rename(loaded):
    r = await run(loaded, "category:traffic | dedup src_ip | rename src_ip as client | fields client")
    assert sorted(x["client"] for x in r["rows"]) == ["10.0.0.1", "10.0.0.2", "192.168.1.5"]


async def test_watchlist_lookup_and_inwatchlist(loaded):
    wl = {"crown": {"kind": "ip", "values": ["10.0.0.2", "192.168.0.0/16"], "labels": ["jump host", "lab"]},
          "bad": {"kind": "domain", "values": ["evil.example"], "labels": ["c2"]}}
    r = await run(loaded, "category:traffic | lookup crown src_ip | stats count by src_ip, crown_match, crown_label | sort src_ip", **wl)
    got = {x["src_ip"]: (x["crown_match"], x["crown_label"]) for x in r["rows"]}
    assert got == {"10.0.0.1": (0, ""), "10.0.0.2": (1, "jump host"), "192.168.1.5": (1, "lab")}
    r = await run(loaded, "| where inwatchlist(dns_qname, \"bad\") | stats count", **wl)
    assert r["rows"] == [{"count": 3}]
    assert watchlist_names('x | lookup crown src_ip | where inwatchlist(dns_qname, "bad")') == {"crown", "bad"}
    with pytest.raises(PipelineError, match="unknown watchlist"):
        compile_pipeline("| lookup nope src_ip")


async def test_truncation_flag(loaded):
    r = await run(loaded, "category:traffic | head 3")
    assert len(r["rows"]) == 3 and r["truncated"] is False
    r = await run_pipeline(loaded, "category:traffic", EventFilter(range="1h"), max_rows=5)
    assert len(r["rows"]) == 5 and r["truncated"] is True


@pytest.mark.parametrize("q,msg", [
    ("| drop table events", "unknown command"),
    ("| where src_ip = 1; DROP TABLE x", "unexpected character"),
    ("| eval x = system(\"id\")", "unknown function"),
    ("| stats count by `raw`", "unexpected character"),
    ("| where nosuchfield = 1", "unknown field"),
    ("| sort", "expected a field"),
    ("| timechart span=1s count", "at least 10s"),
    ("| stats count by src_ip | timechart count", "needs event_time"),
    ("| where src_ip = \"x", "unterminated"),
])
def test_rejects_unsafe_or_invalid(q, msg):
    with pytest.raises(PipelineError, match=msg):
        compile_pipeline(q)


def test_literals_are_parameters():
    p = compile_pipeline("| where msg = \"') OR 1=1 --\" | stats count")
    assert "OR 1=1" not in p.sql and "') OR 1=1 --" in p.params.values()
