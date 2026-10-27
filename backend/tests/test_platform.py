"""Analyst UX (event context, tasks, links, workload), detection depth (tuning, Sigma, peer anomaly),
non-FortiGate sources (Windows / CEF) with their detections, and the AI assistant (API mocked)."""
import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app import ai
from app.alerts.engine import ensure_default_rules, run_rules
from app.db.models import Alert, AlertRule, Incident, LogSource
from app.ingest.generic import SOURCE_ID_BASE, cef, windows
from app.ingest.pipeline import DeviceRegistry, EventSink
from app.sigma import SigmaError, convert
from app.tuning import suggestions

from .test_api import api, login  # noqa: F401
from .test_storage_analytics import FW, _load, traffic

NOW = datetime.now(timezone.utc).replace(microsecond=0)
SRC = {"id": 1, "name": "DC01", "kind": "windows", "site": "HQ"}


_rec = iter(range(1, 10**9))


def win(eid, ts, **kw):
    return "<14>Oct 26 12:00:00 dc01 NXLOG: " + json.dumps({"EventID": eid, "Hostname": "DC01.corp.local", "EventTime": ts.strftime("%Y-%m-%d %H:%M:%S"),
                                                             "RecordNumber": next(_rec), **kw})


# ------------------------------------------------------------------ parsers
def test_windows_and_cef_parsers():
    ev = windows(SRC, win(4625, NOW, TargetUserName="alice", IpAddress="10.0.0.9", WorkstationName="PC9", Status="0xC000006D"))
    assert (ev["event_type"], ev["event_subtype"], ev["action"], ev["user"], ev["src_ip"]) == ("windows", "4625", "logon-fail", "alice", "10.0.0.9")
    assert ev["firewall_id"] == SOURCE_ID_BASE + 1 and ev["firewall_name"] == "DC01" and ev["severity"] == "medium" and ev["hostname"] == "DC01.corp.local"
    g = windows(SRC, win(4732, NOW, TargetUserName="Administrators", MemberName="CN=mallory,OU=Users"))
    assert g["action"] == "group-add" and g["app"] == "Administrators" and "mallory" in g["user"]
    c = cef({"id": 2, "name": "pan", "kind": "cef"}, "CEF:0|Palo Alto|PAN-OS|10|TRAFFIC|end|3|src=10.1.1.1 dst=8.8.8.8 spt=5555 dpt=443 proto=TCP act=allow out=100 in=2000")
    assert (c["category"], c["src_ip"], c["dst_port"], c["action"], c["sent_bytes"], c["rcvd_bytes"]) == ("traffic", "10.1.1.1", 443, "accept", 100, 2000)
    w = cef({"id": 2, "name": "proxy", "kind": "cef"}, "CEF:0|X|Proxy|1|1|blocked|7|src=10.1.1.2 request=https://bad.example/x act=blocked dhost=bad.example")
    assert w["category"] == "web" and w["severity"] == "high" and w["url"] == "https://bad.example/x"


async def test_generic_source_ingest_and_windows_rules(clean_ch, db):
    reg = DeviceRegistry()
    reg.load([FW])
    reg.generic_by_ip = {"10.0.5.10": SRC}
    sink = EventSink(clean_ch, reg)
    lines = [win(4625, NOW - timedelta(minutes=5), TargetUserName=f"user{i % 12}", IpAddress="10.66.0.5") for i in range(25)]
    lines += [win(4740, NOW - timedelta(minutes=3), TargetUserName="user1"),
              win(4728, NOW - timedelta(minutes=2), TargetUserName="Domain Admins", MemberName="CN=eve"),
              win(1102, NOW - timedelta(minutes=1), SubjectUserName="eve"),
              win(7045, NOW - timedelta(minutes=1), ServiceName="PSEXESVC")]
    for ln in lines:
        assert sink.add_line(ln, peer_ip="10.0.5.10") is not None
    assert sink.add_line("garbage that is not windows", peer_ip="10.0.5.10")["event_type"] == "syslog"  # nothing is dropped
    await sink.flush()
    db.add(LogSource(id=1, name="DC01", kind="windows", source_ips=["10.0.5.10"]))
    await db.commit()
    await ensure_default_rules(db)
    keys = ("win_bruteforce", "win_password_spray", "win_lockout", "win_priv_group", "win_log_cleared", "win_new_service")
    for r in (await db.execute(select(AlertRule))).scalars():
        r.enabled = r.key in keys
    await db.commit()
    res = await run_rules(clean_ch, db)
    assert res["win_password_spray"]["created"] == 1 and res["win_lockout"]["created"] == 1
    assert res["win_priv_group"]["created"] == 1 and res["win_log_cleared"]["created"] == 1 and res["win_new_service"]["created"] == 1
    a = (await db.execute(select(Alert).where(Alert.rule_key == "win_priv_group"))).scalars().one()
    assert "Domain Admins" in a.explanation


# ------------------------------------------------------------------ Sigma
def test_sigma_conversion_and_rejections():
    r = convert("""
title: Outbound SMB
logsource: {category: firewall}
detection:
  sel: {dst_port: 445}
  internal: {dst_ip|cidr: 10.0.0.0/8}
  condition: sel and not internal
level: critical
tags: [attack.exfiltration, attack.t1048]
""")
    assert r["severity"] == "critical" and r["tactic"] == "TA0010" and r["techniques"] == ["T1048"]
    assert r["query"].startswith("category:traffic | where dst_port = 445 AND NOT")
    with pytest.raises(SigmaError, match="no equivalent"):
        convert("title: x\nlogsource: {product: windows}\ndetection:\n  s: {CommandLine|contains: mimikatz}\n  condition: s\n")
    with pytest.raises(SigmaError, match="modifier"):
        convert("title: x\ndetection:\n  s: {user|base64: abc}\n  condition: s\n")


# ------------------------------------------------------------------ tuning
async def test_tuning_suggestions(db):
    await ensure_default_rules(db)
    now = datetime.now(timezone.utc)
    mk = lambda g, disp, metric, seq=0: Alert(rule_key="port_scan", name="scan", severity="high", status="resolved", group_key=g, src_ip=g,  # noqa: E731
                                              open_seq=seq, first_seen=now, last_seen=now, event_count=metric, evidence={"metric": metric},
                                              disposition=disp, created_at=now)
    db.add_all([mk("10.0.0.50", "false_positive", 60 + i, i) for i in range(4)] + [mk("10.0.0.66", "true_positive", 400)])
    await db.commit()
    s = await suggestions(db)
    thr = next(x for x in s if x["type"] == "raise_threshold")
    assert thr["param"] == "min_unique_ports" and thr["current"] == 50 and 69 <= thr["proposed"] <= 400
    sup = next(x for x in s if x["type"] == "suppress_entity")
    assert sup["group_key"] == "10.0.0.50"


# ------------------------------------------------------------------ peer anomaly
async def test_peer_anomaly(clean_ch, db):
    recs = []
    for h in range(2, 10):  # 8 normal peers
        recs += [traffic(h * 100 + i, src=f"10.20.30.{h}", dst="203.0.113.5", sent=1_000_000) for i in range(3)]
    recs += [traffic(5000 + i, src="10.20.30.99", dst="203.0.113.5", sent=200_000_000) for i in range(3)]
    await _load(clean_ch, recs)
    await ensure_default_rules(db)
    for r in (await db.execute(select(AlertRule))).scalars():
        r.enabled = r.key == "peer_anomaly"
        if r.key == "peer_anomaly":
            r.params = {**r.params, "min_sent_bytes": 100_000_000}
    await db.commit()
    res = await run_rules(clean_ch, db)
    assert res["peer_anomaly"]["created"] == 1
    a = (await db.execute(select(Alert))).scalars().one()
    assert a.src_ip == "10.20.30.99" and "10.20.30.0/24" in a.explanation


# ------------------------------------------------------------------ analyst UX via API
async def test_event_context_tasks_links_workload(api, clean_ch, db):
    await _load(clean_ch, [traffic(1, src="10.9.9.9", dst="198.51.100.4", dport=443)])
    h = await login(api, "analyst1")
    eid = (await api.get("/api/events", params={"range": "1h"}, headers=h)).json()["items"][0]["event_id"]
    c = (await api.get(f"/api/events/{eid}/context", headers=h)).json()
    assert c["entities"]["source"]["ip"] == "10.9.9.9" and c["entities"]["destination"]["ip"] == "198.51.100.4"
    a, b = Incident(title="a", entity_type="ip", entity="10.9.9.9", status="open", evidence=[], tasks=[], linked=[], assignee="analyst1"), \
        Incident(title="b", entity_type="ip", entity="10.9.9.8", status="open", evidence=[], tasks=[], linked=[])
    db.add_all([a, b])
    await db.commit()
    t = (await api.post(f"/api/incidents/{a.id}/tasks", json={"text": "Check DNS"}, headers=h)).json()
    assert (await api.patch(f"/api/incidents/{a.id}/tasks/{t['id']}", json={"done": True}, headers=h)).json()["done_by"] == "analyst1"
    assert (await api.post(f"/api/incidents/{a.id}/links", json={"incident_id": b.id}, headers=h)).json()["linked"] == [b.id]
    assert (await api.get(f"/api/incidents/{b.id}", headers=h)).json()["linked"] == [a.id]
    w = {r["analyst"]: r for r in (await api.get("/api/incident-analysts", headers=h)).json()}
    assert w["analyst1"]["open"] == 1 and w["(unassigned)"]["open"] == 1


async def test_log_source_api_validation(api, clean_ch, db):
    from app.db.models import Firewall
    db.add(Firewall(name="fw", host="10.1.0.1", serial="S1", syslog_source_ips=[], capabilities={}, health={}, api_log_cursor={}, tags=[]))
    await db.commit()
    h = await login(api, "admin1")
    ok = await api.post("/api/log-sources", json={"name": "DC01", "kind": "windows", "source_ips": ["10.0.5.10"]}, headers=h)
    assert ok.status_code == 201 and ok.json()["firewall_id"] == SOURCE_ID_BASE + ok.json()["id"]
    clash = await api.post("/api/log-sources", json={"name": "x", "kind": "cef", "source_ips": ["10.1.0.1"]}, headers=h)
    assert clash.status_code == 422 and "firewall" in clash.json()["detail"]
    ha = await login(api, "analyst1")
    assert (await api.post("/api/log-sources", json={"name": "y", "source_ips": ["10.0.0.1"]}, headers=ha)).status_code == 403


# ------------------------------------------------------------------ AI (Claude API mocked; nothing leaves the test)
async def test_ai_query_and_privacy_gate(api, clean_ch, db, monkeypatch):
    from app.config import get_settings
    h = await login(api, "analyst1")
    assert (await api.get("/api/ai/status", headers=h)).json()["enabled"] is False
    assert (await api.post("/api/ai/query", json={"question": "x"}, headers=h)).status_code == 422  # not configured
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    get_settings.cache_clear()
    calls = []

    async def fake_call(system, messages, schema, max_tokens, effort):
        calls.append(messages)
        if len(calls) == 1:  # first answer does not compile → the assistant must repair it
            return json.dumps({"query": "| bogus", "explanation": "x", "visualisation": "auto"}), "claude-opus-5-5"
        return json.dumps({"query": "action:deny | top 5 src_ip", "explanation": "Top denied sources", "visualisation": "bar"}), "claude-opus-5-5"
    monkeypatch.setattr(ai, "_call", fake_call)
    r = await api.post("/api/ai/query", json={"question": "who is denied most?"}, headers=h)
    assert r.status_code == 200 and r.json()["query"] == "action:deny | top 5 src_ip" and r.json()["repaired"] is True
    assert "does not compile" in calls[1][-1]["content"]
    inc = Incident(title="t", entity_type="ip", entity="10.0.0.1", status="open", evidence=[], tasks=[], linked=[])
    db.add(inc)
    await db.commit()
    r = await api.post(f"/api/ai/incidents/{inc.id}/summary", headers=h)
    assert r.status_code == 422 and "AI_ALLOW_DATA_SHARING" in r.json()["detail"]  # data never sent without the opt-in
    assert len(calls) == 2
    get_settings.cache_clear()
