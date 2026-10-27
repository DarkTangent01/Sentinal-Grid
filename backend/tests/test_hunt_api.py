"""Search, custom detections, watchlists, hunting, workbooks, automation and entity graph through the HTTP API."""
from sqlalchemy import select

from app.alerts.engine import run_rules
from app.content import ensure_content
from app.db.models import Alert, AlertRule, AutomationRun, Incident, IncidentComment, WatchlistItem

from .test_api import api, login  # noqa: F401  (fixture)
from .test_storage_analytics import _load, traffic


async def _data(ch):
    recs = [traffic(i, src="10.9.0.5", dst=f"198.51.100.{i}", dport=3389, sent=10, rcvd=0) for i in range(30)]
    recs += [traffic(100 + i, src="10.9.0.6", dst="203.0.113.9", dport=443) for i in range(5)]
    await _load(ch, recs)


async def test_search_endpoint_and_errors(api, clean_ch):
    await _data(clean_ch)
    h = await login(api, "analyst1")
    r = await api.post("/api/search", json={"query": "category:traffic | stats dc(dst_ip) as dsts by src_ip | sort -dsts", "range": "1h"}, headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["rows"][0] == {"src_ip": "10.9.0.5", "dsts": 30}
    r = await api.post("/api/search", json={"query": "| bogus", "range": "1h"}, headers=h)
    assert r.status_code == 422 and "unknown command" in r.json()["detail"]
    r = await api.post("/api/search/validate", json={"query": "| stats count by"}, headers=h)
    assert r.json()["valid"] is False
    r = await api.post("/api/search/export.csv", json={"query": "| stats count by src_ip", "range": "1h"}, headers=h)
    assert r.status_code == 200 and r.text.startswith("src_ip,count")


async def test_custom_detection_creates_alert_and_incident(api, clean_ch, db):
    await _data(clean_ch)
    h = await login(api, "admin1")
    body = {"name": "RDP fan-out", "severity": "high", "query": "dst_port:3389 | stats dc(dst_ip) as dsts by src_ip | where dsts >= 20",
            "lookback_minutes": 60, "interval_minutes": 5, "explanation": "{src_ip} reached {dsts} hosts over RDP",
            "tactic": "TA0008", "techniques": ["T1021.001"]}
    r = await api.post("/api/detections/preview", json=body, headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["fired"] and r.json()["alerts"][0]["explanation"] == "10.9.0.5 reached 30 hosts over RDP"
    r = await api.post("/api/detections", json=body, headers=h)
    assert r.status_code == 201, r.text
    key = r.json()["key"]
    # analysts may preview but not create
    ha = await login(api, "analyst1")
    assert (await api.post("/api/detections", json=body, headers=ha)).status_code == 403
    for rule in (await db.execute(select(AlertRule))).scalars():
        rule.enabled = rule.key == key
    await db.commit()
    res = await run_rules(clean_ch, db)
    assert res[key]["created"] == 1
    a = (await db.execute(select(Alert).where(Alert.rule_key == key))).scalars().one()
    assert a.src_ip == "10.9.0.5" and a.mitre["tactic"] == "TA0008" and a.severity == "high"
    assert a.incident_id is not None  # high severity opens an incident
    r = await api.get("/api/detections", headers=h)
    assert r.json()[0]["alerts_7d"] == 1


async def test_watchlist_items_lookup_and_rbac(api, clean_ch, db):
    await _data(clean_ch)
    h = await login(api, "admin1")
    r = await api.post("/api/watchlists", json={"name": "jump_hosts", "kind": "ip", "description": "admin jump hosts"}, headers=h)
    assert r.status_code == 201, r.text
    wid = r.json()["id"]
    r = await api.post(f"/api/watchlists/{wid}/items", json={"text": "value,label\n10.9.0.5,jump-1\n10.8.0.0/16,lab\nnot-an-ip\n"}, headers=h)
    assert r.json()["added"] == 2 and r.json()["error_count"] == 1
    r = await api.post("/api/search", json={"query": "| lookup jump_hosts src_ip | stats count by src_ip, jump_hosts_label | sort src_ip", "range": "1h"}, headers=h)
    assert [x["jump_hosts_label"] for x in r.json()["rows"]] == ["jump-1", ""]
    assert (await api.post("/api/watchlists", json={"name": "bad-name", "kind": "ip"}, headers=h)).status_code == 422
    ha = await login(api, "analyst1")
    assert (await api.post(f"/api/watchlists/{wid}/items", json={"text": "1.2.3.4"}, headers=ha)).status_code == 403
    assert (await api.get(f"/api/watchlists/{wid}/items", headers=ha)).json()["total"] == 2


async def test_hunting_library_and_bookmark_to_incident(api, clean_ch, db):
    await _data(clean_ch)
    await ensure_content(db)
    h = await login(api, "analyst1")
    hunts = (await api.get("/api/hunting", headers=h)).json()
    assert len(hunts) >= 10 and all(x["builtin"] for x in hunts)
    lat = next(x for x in hunts if x["key"] == "lateral_movement_ports")
    assert (await api.put(f"/api/hunting/{lat['id']}", json={"name": "x", "query": "| stats count"}, headers=h)).status_code == 403
    results = (await api.post("/api/hunting/run-all", params={"range": "1h"}, headers=h)).json()
    assert all(r["error"] is None for r in results), [r for r in results if r["error"]]
    # every built-in hunt compiles and runs; the lateral-movement hunt needs internal destinations, so none here
    inc = Incident(title="t", entity_type="ip", entity="10.9.0.5", status="open", evidence=[])
    db.add(inc)
    await db.commit()
    r = await api.post("/api/bookmarks", json={"name": "RDP sweep", "query": "dst_port:3389", "columns": ["src_ip"],
                                               "rows": [{"src_ip": "10.9.0.5"}], "incident_id": inc.id}, headers=h)
    assert r.status_code == 201, r.text
    await db.refresh(inc)
    assert inc.evidence[-1]["type"] == "bookmark"


async def test_workbooks_templates_clone_and_permissions(api, clean_ch, db):
    await ensure_content(db)
    h = await login(api, "analyst1")
    books = (await api.get("/api/workbooks", headers=h)).json()
    soc = next(b for b in books if b["key"] == "soc_overview")
    assert soc["template"] and not soc["can_edit"]
    assert (await api.put(f"/api/workbooks/{soc['id']}", json={"name": "x"}, headers=h)).status_code == 403
    c = (await api.post(f"/api/workbooks/{soc['id']}/clone", headers=h)).json()
    assert c["can_edit"] and c["shared"] is False
    bad = {"name": "b", "panels": [{"id": "a", "title": "t", "query": "| nope", "viz": "table", "width": 6}]}
    assert (await api.put(f"/api/workbooks/{c['id']}", json=bad, headers=h)).status_code == 422
    for b in books:  # every template panel compiles
        for p in b["panels"]:
            r = await api.post("/api/search", json={"query": p["query"], "range": "1h"}, headers=h)
            assert r.status_code == 200, (b["name"], p["title"], r.text)


async def test_automation_playbook_runs_on_incident(api, clean_ch, db):
    await _data(clean_ch)
    h = await login(api, "admin1")
    wl = (await api.post("/api/watchlists", json={"name": "auto_block", "kind": "ip"}, headers=h)).json()
    rule = {"name": "Triage high incidents", "trigger": "incident.created", "conditions": {"min_severity": "high"},
            "actions": [{"type": "assign", "user": "analyst1"}, {"type": "set_status", "status": "in_progress"},
                        {"type": "enrich"}, {"type": "add_to_watchlist", "watchlist_id": wl["id"], "ttl_hours": 24},
                        {"type": "suggest_block"}, {"type": "run_query", "query": "src:$entity$ | stats dc(dst_ip) as dsts"}]}
    r = await api.post("/api/automation/rules", json=rule, headers=h)
    assert r.status_code == 201, r.text
    bad = {**rule, "actions": [{"type": "rm -rf"}]}
    assert (await api.post("/api/automation/rules", json=bad, headers=h)).status_code == 422
    det = {"name": "RDP fan-out", "severity": "high", "query": "dst_port:3389 | stats dc(dst_ip) as dsts by src_ip | where dsts >= 20"}
    key = (await api.post("/api/detections", json=det, headers=h)).json()["key"]
    for x in (await db.execute(select(AlertRule))).scalars():
        x.enabled = x.key == key
    await db.commit()
    await run_rules(clean_ch, db)
    inc = (await db.execute(select(Incident))).scalars().one()
    assert inc.assignee == "analyst1" and inc.status == "in_progress"
    run = (await db.execute(select(AutomationRun))).scalars().one()
    assert run.status == "ok", run.results
    notes = [c.body for c in (await db.execute(select(IncidentComment).where(IncidentComment.incident_id == inc.id))).scalars()]
    assert any("Enrichment for 10.9.0.5" in n for n in notes)
    assert any("NOT applied" in n and "SIEM-BLOCKLIST" in n for n in notes)
    assert any("dsts" in n and "30" in n for n in notes)
    item = (await db.execute(select(WatchlistItem))).scalars().one()
    assert item.value == "10.9.0.5" and item.expires_at is not None
    # dry-run test endpoint changes nothing
    r = await api.post(f"/api/automation/rules/{run.rule_id}/test", json={"target_type": "incident", "target_id": inc.id}, headers=h)
    assert r.json()["status"] == "dry_run" and r.json()["conditions_match"]
    assert len((await db.execute(select(AutomationRun))).scalars().all()) == 1


async def test_entity_graph(api, clean_ch, db):
    await _data(clean_ch)
    h = await login(api, "analyst1")
    r = await api.get("/api/entity/graph", params={"kind": "ip", "value": "10.9.0.5", "range": "1h"}, headers=h)
    assert r.status_code == 200, r.text
    g = r.json()
    assert g["root"] == "ip:10.9.0.5"
    assert sum(1 for n in g["nodes"] if n["type"] == "ip") == 16  # root + top 15 peers
    assert any(n["type"] == "firewall" for n in g["nodes"])
    assert (await api.get("/api/entity/graph", params={"kind": "ip", "value": "nope"}, headers=h)).status_code == 422
