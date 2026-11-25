"""HTTP ingestion (token per log source, acknowledged batches), ingestion accounting (nothing rejected without a record
of who and why), ingestion health, the parser test endpoint and ECS search aliases."""
import json
from datetime import datetime, timedelta, timezone

from app.analytics.ql import compile_ql
from app.ingest.pipeline import DeviceRegistry, EventSink
from app.ingest.schema_map import ECS, ocsf_class, to_ecs
from app.db.ch_schema import EVENT_COLUMNS

from .test_api import api, login  # noqa: F401  (fixture)


async def _source(api, h, kind="json", name="portal", ip="10.50.0.9"):  # noqa: F811
    r = await api.post("/api/log-sources", headers=h, json={"name": name, "kind": kind, "source_ips": [ip]})
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def test_http_ingest_acknowledges_parses_and_accounts(api, ch):  # noqa: F811
    ch.command("TRUNCATE TABLE ingest_rejects")
    h = await login(api, "admin1")
    sid = await _source(api, h)
    assert (await api.post(f"/api/ingest/{sid}", content=b"{}", headers={"Authorization": "Bearer nope"})).status_code == 401   # HTTP ingest is off
    tok = (await api.post(f"/api/log-sources/{sid}/token", headers=h)).json()
    assert tok["token"].startswith("sgi_") and tok["url"] == f"/api/ingest/{sid}"
    auth = {"Authorization": f"Bearer {tok['token']}"}
    now = datetime.now(timezone.utc)
    recs = [{"@timestamp": (now - timedelta(seconds=30)).isoformat(), "event": {"category": "authentication", "action": "login", "outcome": "failure"},
             "source": {"ip": "203.0.113.5"}, "user": {"name": "alice"}, "message": "bad password", "n": i} for i in range(3)]
    future = {"@timestamp": (now + timedelta(days=30)).isoformat(), "message": "clock is wrong", "src_ip": "10.1.1.1"}
    body = "\n".join(json.dumps(r) for r in recs + [recs[0], future]) + "\nnot json at all\n"
    r = await api.post(f"/api/ingest/{sid}", content=body.encode(), headers=auth)
    assert r.status_code == 200, r.text
    # the non-JSON line is kept as a plain event (never dropped); the repeated record is not stored twice
    assert r.json() == {"received": 6, "accepted": 5, "duplicates": 1, "rejected": 0, "bad_timestamp": 1}
    rows = ch.query("SELECT user, action, source, parser_version, event_type FROM events FINAL WHERE firewall_name = 'portal' ORDER BY event_type, parser_version")
    assert len(rows) == 5 and {x["source"] for x in rows} == {"http"}
    assert sum(1 for x in rows if x["user"] == "alice" and x["action"] == "logon-fail") == 3
    assert sum(1 for x in rows if x["parser_version"].endswith("+bad-ts")) == 1 and sum(1 for x in rows if x["event_type"] == "syslog") == 1
    # a retry of the same batch is safe: same ids
    assert (await api.post(f"/api/ingest/{sid}", content=body.encode(), headers=auth)).status_code == 200
    assert ch.query("SELECT count() AS n FROM events FINAL WHERE firewall_name = 'portal'")[0]["n"] == 5
    # JSON array form, wrong token, other source's token, oversized batch
    assert (await api.post(f"/api/ingest/{sid}", content=json.dumps([{"message": "a"}, "plain line"]).encode(), headers=auth)).json()["accepted"] == 2
    assert (await api.post(f"/api/ingest/{sid}", content=b"x", headers={"Authorization": "Bearer sgi_wrong"})).status_code == 401
    other = await _source(api, h, name="other", ip="10.50.0.10")
    assert (await api.post(f"/api/ingest/{other}", content=b"x", headers=auth)).status_code == 401
    big = "\n".join(f'{{"n":{i}}}' for i in range(2001)).encode()
    assert (await api.post(f"/api/ingest/{sid}", content=big, headers=auth)).status_code == 413
    # health: the source, its accounting and the reasons
    hl = (await api.get("/api/log-sources/health")).json()
    me = next(x for x in hl["sources"] if x["name"] == "portal")
    assert me["http_ingest"] and me["events_24h"] >= 5 and me["duplicates_24h"] >= 1 and me["bad_timestamps_24h"] >= 1 and me["status"] == "degraded"
    assert hl["not_stored_24h"]["duplicate"] >= 1 and any(s["reason"] == "bad_timestamp" and "clock is wrong" in s["sample"] for s in hl["samples"])
    # revoke: the token stops working; an analyst can read health but not manage tokens
    assert (await api.delete(f"/api/log-sources/{sid}/token", headers=h)).status_code == 200
    assert (await api.post(f"/api/ingest/{sid}", content=b"x", headers=auth)).status_code == 401
    await api.post("/api/auth/logout", headers=h)
    ha = await login(api, "analyst1")
    assert (await api.get("/api/log-sources/health")).status_code == 200
    assert (await api.post(f"/api/log-sources/{sid}/token", headers=ha)).status_code == 403
    assert (await api.post("/api/log-sources/parse-test", headers=ha, json={"kind": "linux", "line": "x"})).status_code == 403


async def test_parse_test_shows_normalized_and_ecs(api):  # noqa: F811
    h = await login(api, "admin1")
    line = "<38>Nov 14 10:00:01 web-1 sshd[2211]: Failed password for invalid user admin from 203.0.113.90 port 52100 ssh2"
    r = (await api.post("/api/log-sources/parse-test", headers=h, json={"kind": "linux", "line": line})).json()
    assert r["parsed"] and not r["fell_back_to_plain"] and r["parser_version"] == "linux-auth-1.0"
    assert r["normalized"]["user"] == "admin" and r["ecs"]["source"]["ip"] == "203.0.113.90" and r["ecs"]["event"]["outcome"] == "failure"
    assert r["ecs"]["ocsf"]["class_name"] == "Authentication"
    r = (await api.post("/api/log-sources/parse-test", headers=h, json={"kind": "leef", "line": "something else"})).json()
    assert r["fell_back_to_plain"]


class _CH:
    def __init__(self):
        self.inserts = []

    async def ainsert(self, table, rows, cols):
        self.inserts.append((table, rows))


async def test_sink_records_every_reject_with_sender_and_reason():
    ch = _CH()
    reg = DeviceRegistry()
    reg.load([{"id": 1, "name": "fw1", "site": "", "serial": "FGT1", "hostname": "fw1", "host": "10.0.0.1", "syslog_source_ips": [], "is_demo": False,
               "vendor": "fortinet", "log_tz": "UTC"}])
    reg.generic_by_ip = {"10.0.0.50": {"id": 3, "name": "linux-1", "kind": "linux", "site": ""}}
    sink = EventSink(ch, reg, batch_size=100)
    ts = int(datetime.now(timezone.utc).timestamp())
    ok = f'date=2026-11-14 time=10:00:00 devname="fw1" devid="FGT1" eventtime={ts} logid="0000000013" type="traffic" subtype="forward" srcip=10.1.1.1 dstip=8.8.8.8 sessionid=1'
    assert sink.add_line(ok, peer_ip="10.0.0.1") is not None
    assert sink.add_line(ok, peer_ip="10.0.0.1") is None                                        # duplicate
    assert sink.add_line(ok.replace("sessionid=1", "sessionid=2"), peer_ip="198.51.100.66") is None    # names fw1 from a foreign address
    assert sink.add_line('devname="ghost" devid="FGTX" type="traffic" subtype="forward" password=hunter2', peer_ip="198.51.100.77") is None  # unknown device
    future = ok.replace(f"eventtime={ts}", f"eventtime={ts + 90 * 86400}").replace("sessionid=1", "sessionid=3")
    assert sink.add_line(future, peer_ip="10.0.0.1")["parser_version"].endswith("+bad-ts")
    assert sink.add_line("<38>Nov 14 10:00:01 web-1 sshd[1]: Accepted password for bob from 10.9.9.9 port 1 ssh2", peer_ip="10.0.0.50")["user"] == "bob"
    await sink.flush()
    assert sink.counters["duplicates"] == 1 and sink.counters["source_mismatch"] == 1 and sink.counters["unknown_device"] == 1 and sink.counters["bad_timestamp"] == 1
    events = next(rows for t, rows in ch.inserts if t == "events")
    rej = {(r["reason"], r["sender"]): r for t, rows in ch.inserts if t == "ingest_rejects" for r in rows}
    assert len(events) == 3 and set(rej) == {("duplicate", "10.0.0.1"), ("source_mismatch", "198.51.100.66"), ("unknown_device", "198.51.100.77"), ("bad_timestamp", "10.0.0.1")}
    assert rej[("source_mismatch", "198.51.100.66")]["source_name"] == "fw1" and rej[("duplicate", "10.0.0.1")]["sample"] == ""
    assert "devname" in rej[("unknown_device", "198.51.100.77")]["sample"]
    await sink.flush()
    assert sum(1 for t, _ in ch.inserts if t == "ingest_rejects") == 1                             # written once, then reset


def test_ecs_view_and_search_aliases():
    ev = {c: "" for c in EVENT_COLUMNS} | {"src_ip": "10.0.0.5", "dst_port": 443, "action": "deny", "category": "traffic", "user": "alice", "raw": "secret line",
                                           "event_time": datetime(2026, 11, 14, tzinfo=timezone.utc)}
    doc = to_ecs(ev)
    assert doc["source"]["ip"] == "10.0.0.5" and doc["destination"]["port"] == 443 and doc["event"]["outcome"] == "failure" and doc["user"]["name"] == "alice"
    assert doc["@timestamp"].startswith("2026-11-14") and "original" not in doc["event"] and to_ecs(ev, include_raw=True)["event"]["original"] == "secret line"
    assert doc["ocsf"] == {"class_uid": 4001, "class_name": "Network Activity", "category_name": "Network Activity"}
    assert ocsf_class({"category": "system", "action": "logon-fail"})["class_name"] == "Authentication"
    assert set(ECS) <= set(EVENT_COLUMNS) | {"ingest_time"}
    a, b = compile_ql("source.ip:10.0.0.5 AND destination.port:443 AND user.name:alice"), compile_ql("src_ip:10.0.0.5 AND dst_port:443 AND user:alice")
    assert a.sql == b.sql
