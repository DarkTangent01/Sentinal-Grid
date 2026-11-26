"""SOC capabilities on the real persistence path (SQLite + embedded ClickHouse): Zeek network analytics, ATT&CK coverage,
explainable entity risk with analyst feedback, SOC metrics, the investigation brief, response actions (four eyes,
idempotency, verification from logs, read-only actions), AI hunt validation and the incident lifecycle.
Synthetic test data only: documentation / private address ranges, sources named 'lab-*'."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from app import ai, mitre, response, risk, socmetrics, zeek
from app.db.ch_schema import EVENT_COLUMNS
from app.db.models import Alert, AlertRule, Asset, Firewall, Incident, ResponseAction, User
from app.ingest.generic import parse

from .test_api import api, login  # noqa: F401  (fixture)

NOW = datetime.now(timezone.utc)
SRC = {"id": 9, "name": "lab-zeek", "kind": "zeek", "site": "LAB"}


def zeek_line(log: str, ts: datetime, **f) -> str:
    return json.dumps({"_path": log, "ts": ts.timestamp(), **f})


async def _insert(ch, lines: list[str]):
    rows = [parse(SRC, ln) for ln in lines]
    await ch.ainsert("events", rows, EVENT_COLUMNS)
    return rows


async def test_zeek_analytics_scans_beacons_dns_tls_ports_and_one_connection(clean_ch):
    ch = clean_ch
    t = NOW - timedelta(hours=3)
    lines = []
    # an internal scanner: 40 refused ports
    lines += [zeek_line("conn", t + timedelta(seconds=i), uid=f"Cs{i:03d}", **{"id.orig_h": "10.20.1.99", "id.orig_p": 40000 + i, "id.resp_h": "10.20.2.1",
                                                                             "id.resp_p": i + 1}, proto="tcp", conn_state="REJ") for i in range(40)]
    # a beacon: every 300 s, similar size, to the internet
    lines += [zeek_line("conn", t + timedelta(seconds=300 * i + (i % 3)), uid=f"Cb{i:03d}", **{"id.orig_h": "10.20.1.15", "id.orig_p": 50000 + i,
              "id.resp_h": "198.51.100.77", "id.resp_p": 443}, proto="tcp", conn_state="SF", service="ssl", orig_bytes=900 + i % 5, resp_bytes=4000) for i in range(30)]
    # irregular browsing to another host: not a beacon
    gaps = [7, 300, 31, 900, 2, 1500, 45, 600, 13, 2000, 90, 400, 5, 1200]
    acc = 0
    for i, g in enumerate(gaps):
        acc += g
        lines.append(zeek_line("conn", t + timedelta(seconds=acc), uid=f"Cw{i:03d}", **{"id.orig_h": "10.20.1.16", "id.orig_p": 51000 + i, "id.resp_h": "198.51.100.88",
                                                                                         "id.resp_p": 443}, proto="tcp", conn_state="SF", orig_bytes=100 * (i + 1)))
    # DNS: one rare domain, NXDOMAIN burst, popular name
    lines += [zeek_line("dns", t + timedelta(seconds=i), uid=f"Cd{i}", **{"id.orig_h": f"10.20.1.{20 + i % 5}", "id.resp_h": "10.20.0.53", "id.resp_p": 53},
                        query="www.example.com", qtype_name="A", rcode_name="NOERROR") for i in range(10)]
    lines.append(zeek_line("dns", t, uid="Cr1", **{"id.orig_h": "10.20.1.15", "id.resp_h": "10.20.0.53", "id.resp_p": 53}, query="x9.rare-tld-example.net", rcode_name="NOERROR"))
    lines += [zeek_line("dns", t + timedelta(seconds=i), uid=f"Cn{i}", **{"id.orig_h": "10.20.1.30", "id.resp_h": "10.20.0.53", "id.resp_p": 53},
                        query=f"q{i}.dga-example.org", rcode_name="NXDOMAIN") for i in range(25)]
    # TLS validation failure and SSH on 443 to the internet (with the same uid's ssl record, to test the connection view)
    lines.append(zeek_line("ssl", t, uid="Cb000", **{"id.orig_h": "10.20.1.15", "id.resp_h": "198.51.100.77", "id.resp_p": 443}, server_name="bad.example.net",
                           validation_status="self signed certificate", established=True))
    lines.append(zeek_line("conn", t, uid="Cssh1", **{"id.orig_h": "10.20.1.40", "id.orig_p": 40100, "id.resp_h": "203.0.113.9", "id.resp_p": 443},
                           proto="tcp", conn_state="SF", service="ssh"))
    await _insert(ch, lines)
    t0, t1 = NOW - timedelta(hours=24), NOW
    ov = await zeek.overview(ch, t0, t1)
    assert ov["has_data"] and {x["log"] for x in ov["logs"]} >= {"conn", "dns", "ssl"} and ov["connections"]["failed"] == 40
    sc = await zeek.scanners(ch, t0, t1)
    assert [x["src_ip"] for x in sc] == ["10.20.1.99"] and sc[0]["kind"] == "port scan" and sc[0]["internal"]
    bc = await zeek.beacons(ch, t0, t1)
    assert [(x["src_ip"], x["dst_ip"]) for x in bc] == [("10.20.1.15", "198.51.100.77")] and 295 < bc[0]["interval_s"] < 305 and bc[0]["score"] >= 80
    d = await zeek.dns(ch, t0, t1)
    assert any(x["domain"] == "rare-tld-example.net" for x in d["rare_domains"]) and not any(x["domain"] == "example.com" for x in d["rare_domains"])
    assert d["nxdomain"][0]["src_ip"] == "10.20.1.30" and d["top"][0]["name"] == "www.example.com"
    tl = await zeek.tls(ch, t0, t1)
    assert tl["invalid"][0]["server_name"] == "bad.example.net"
    ports = await zeek.unusual_ports(ch, t0, t1)
    assert [(p["service"], p["dst_port"], p["direction"]) for p in ports] == [("ssh", 443, "to the internet")]
    conn = await zeek.connection(ch, "Cb000")
    assert conn["summary"]["logs"] == ["conn", "ssl"] and conn["summary"]["dst_ip"] == "198.51.100.77"


def _alert(rule="vpn_bruteforce", sev="high", ip="203.0.113.5", age_h=1, status="new", disp=None, conf=None, n=0, tech=("T1110",), tactic="TA0006"):
    t = NOW - timedelta(hours=age_h)
    return Alert(rule_key=rule, name=rule.replace("_", " "), severity=sev, status=status, group_key=f"{ip}:{n}", open_seq=n, src_ip=ip, first_seen=t - timedelta(minutes=5),
                 last_seen=t, event_count=10, explanation=f"{ip} did things", evidence={"confidence": conf} if conf else {}, disposition=disp,
                 mitre={"tactic": tactic, "tactic_name": "Credential Access", "techniques": list(tech)}, created_at=t)


async def test_risk_is_explainable_and_learns_from_verdicts(db):
    db.add(Asset(ip="10.1.1.50", hostname="db-1", criticality="critical", users=[], firewall_ids=[], tags=[]))
    db.add_all([_alert(ip="10.1.1.50", sev="high", conf="high", n=0), _alert(rule="beaconing", ip="10.1.1.50", sev="medium", age_h=100, n=0, tech=("T1071",), tactic="TA0011"),
                _alert(ip="10.1.1.60", sev="high", conf="high", n=0)])
    # five closed false positives of one rule for one host: that rule barely counts for it any more
    db.add_all([_alert(rule="port_scan", ip="10.1.1.70", sev="high", n=i, status="resolved", disp="false_positive", tech=("T1046",)) for i in range(5)])
    db.add(_alert(rule="port_scan", ip="10.1.1.70", sev="high", n=9, tech=("T1046",)))
    await db.commit()
    r = await risk.ranking(db)
    by = {x["entity"]: x for x in r["items"]}
    assert by["10.1.1.50"]["score"] > by["10.1.1.60"]["score"]             # critical asset weighs 1.5×
    d = await risk.detail(db, "ip", "10.1.1.50")
    assert d["asset_weight"] == 1.5 and [f["rule_key"] for f in d["factors"]] == ["vpn_bruteforce", "beaconing"]
    assert d["factors"][0]["points"] == 22.0 and d["factors"][1]["points"] == 4.8     # 22 × 1.0 (high) × 1.0 (last 24 h); 10 × 0.8 (no confidence) × 0.6 (1-7 days)
    fp = await risk.detail(db, "ip", "10.1.1.70")
    assert fp["factors"][0]["feedback"].startswith("reduced") and fp["score"] < by["10.1.1.60"]["score"] / 2


async def test_risk_ranking_batches_assets_and_skips_nms_alerts(db, monkeypatch):
    """Production had >32,767 alerting IPs: one IN list over every IP exceeded PostgreSQL's parameter limit and the
    executive summary failed. Assets are looked up in batches, and NMS alerts never enter the Grid ranking."""
    monkeypatch.setattr(risk, "ASSET_BATCH", 2)
    db.add_all([Asset(ip=f"10.9.0.{i}", hostname=f"h{i}", criticality="critical", users=[], firewall_ids=[], tags=[]) for i in range(5)])
    db.add_all([_alert(ip=f"10.9.0.{i}", sev="high", conf="high", n=0) for i in range(5)])
    db.add(_alert(rule="wireless_retry_high", ip="10.9.9.9", sev="high", n=0))
    await db.commit()
    r = await risk.ranking(db)
    by = {x["entity"]: x for x in r["items"]}
    assert all(by[f"10.9.0.{i}"]["hostname"] == f"h{i}" for i in range(5))      # every batch resolved
    assert "10.9.9.9" not in by
    ops = await socmetrics.operations(db, 30)
    assert ops["alerts"]["total"] == 5 and "wireless_retry_high" not in {x["rule_key"] for x in ops["alerts"]["top_rules"]}


async def test_mitre_coverage_counts_rules_alerts_precision_and_gaps(db):
    db.add_all([AlertRule(key="vpn_bruteforce", name="VPN brute force", severity="high", enabled=True, params={}, mitre={"tactic": "TA0006", "techniques": ["T1110"]}),
                AlertRule(key="dns_tunnel", name="DNS tunnel", severity="medium", enabled=False, params={}, mitre={"tactic": "TA0011", "techniques": ["T1071.004"]}),
                AlertRule(key="win_password_spray", name="Spray", severity="high", enabled=True, params={}, mitre={"tactic": "TA0006", "techniques": ["T1110.003"]}),
                AlertRule(key="nothing_mapped", name="Unmapped", severity="low", enabled=True, params={}, mitre={})])
    db.add_all([_alert(n=1, disp="true_positive"), _alert(n=2, disp="false_positive"), _alert(n=3)])
    await db.commit()
    c = await mitre.coverage(db)
    t = {x["id"]: x for x in c["techniques"]}
    assert t["T1110"]["status"] == "covered" and t["T1110"]["alerts"] == 3 and t["T1110"]["precision"] == 50.0
    assert t["T1071.004"]["status"] == "disabled" and t["T1046"]["status"] == "gap" and t["T1110.003"]["status"] == "covered"
    assert t["T1071"]["status"] == "gap"                                     # the sub-technique's rule is disabled
    assert c["summary"]["rules_unmapped"] == 1 and c["catalog"]["source"] == "built-in"
    assert next(x for x in c["tactics"] if x["id"] == "TA0006")["alerts"] == 3
    assert mitre.technique("T1110.003")["name"].startswith("Brute Force") and mitre.technique("T9999")["unknown"]
    out = mitre.import_stix({"objects": [{"type": "x-mitre-collection", "x_mitre_version": "17.0"},
                                         {"type": "attack-pattern", "name": "Brute Force", "external_references": [{"source_name": "mitre-attack", "external_id": "T1110"}],
                                          "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}]},
                                         {"type": "attack-pattern", "name": "Password Spraying", "external_references": [{"source_name": "mitre-attack", "external_id": "T1110.003"}],
                                          "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}]},
                                         {"type": "attack-pattern", "name": "Old", "revoked": True, "external_references": [{"source_name": "mitre-attack", "external_id": "T1000"}]}]})
    assert out["version"] == "17.0" and set(out["techniques"]) == {"T1110", "T1110.003"} and out["techniques"]["T1110.003"]["name"] == "Brute Force: Password Spraying"


async def test_soc_metrics_measure_only_what_happened(db):
    t = NOW - timedelta(days=1)
    db.add_all([Alert(rule_key="port_scan", name="scan", severity="high", status="resolved", group_key="a", src_ip="10.0.0.1", first_seen=t - timedelta(minutes=10),
                      last_seen=t, created_at=t, disposition="false_positive", evidence={}, mitre={}),
                Alert(rule_key="port_scan", name="scan", severity="critical", status="new", group_key="b", src_ip="10.0.0.2", first_seen=t - timedelta(minutes=2),
                      last_seen=t, created_at=t, evidence={}, mitre={})])
    db.add_all([Incident(title="a", entity_type="ip", entity="10.0.0.1", severity="high", status="closed", created_at=t, acknowledged_at=t + timedelta(minutes=30),
                         resolved_at=t + timedelta(hours=2), closure_reason="false_positive", sla_resolve_due=t + timedelta(hours=24), category="security"),
                Incident(title="b", entity_type="ip", entity="10.0.0.2", severity="critical", status="open", created_at=t, sla_ack_due=t + timedelta(minutes=15),
                         sla_resolve_due=t + timedelta(hours=4), category="security")])
    await db.commit()
    m = await socmetrics.operations(db, 30)
    assert m["mttd"]["n"] == 2 and m["mttd"]["mean_s"] == 360.0 and m["mtta"]["mean_s"] == 1800.0 and m["mttr"]["mean_s"] == 7200.0
    assert m["alerts"]["false_positive_pct"] == 100.0 and m["incidents"]["open"] == 1 and m["incidents"]["unassigned"] == 1
    assert m["sla"]["ack_breached_open"] == 1 and m["sla"]["resolved_within_sla_pct"] == 100.0 and m["incidents"]["by_priority"] == {"P1": 1}
    empty = await socmetrics.operations(db, 30) if False else None
    assert empty is None


async def _users(db):
    db.add_all([User(username="req", password_hash="x", role="analyst", products=["grid"]), User(username="boss", password_hash="x", role="admin"),
                User(username="peer", password_hash="x", role="analyst", products=["grid"], iac_roles=["approver"])])
    db.add(Firewall(name="lab-fgt", host="10.200.1.1", vendor="fortinet"))
    await db.commit()
    return {u.username: u for u in (await db.execute(__import__("sqlalchemy").select(User))).scalars()}


async def test_response_four_eyes_idempotency_and_verification(db, clean_ch):
    u = await _users(db)
    a, created = await response.request(db, u["req"], "block_ip", "93.184.216.66", reason="C2 confirmed by TI", hours=24)
    assert created and a.status == "pending" and a.requires_approval and a.expires_at is not None
    assert "SENTINEL-BLOCK" in a.plan["steps"][0]["apply"] and "unselect member" in a.plan["steps"][0]["rollback"]
    again, created2 = await response.request(db, u["peer"], "block_ip", "93.184.216.66", reason="same thing again")
    assert not created2 and again.id == a.id                                   # one open action per target
    with pytest.raises(response.ResponseError, match="second person"):
        await response.decide(db, a, u["req"], True, "self-approval")         # never the requester
    with pytest.raises(response.ResponseError, match="approved"):
        await response.record_applied(db, a, u["req"], "")                     # not before approval
    await response.decide(db, a, u["peer"], True, "ok")
    await response.record_applied(db, a, u["req"], "applied on lab-fgt")
    # inconclusive until traffic shows the block; a deny proves it; an accept after the change disproves it
    assert (await response.verify(clean_ch, a))["outcome"] == "inconclusive" and a.status == "applied"
    later = datetime.now(timezone.utc) + timedelta(seconds=30)   # after the recorded apply time
    rec = {"type": "traffic", "subtype": "forward", "devid": "FGT1", "devname": "lab-fgt", "srcip": "93.184.216.66", "dstip": "10.1.1.1", "dstport": "443",
           "action": "deny", "eventtime": str(int(later.timestamp() * 1e9)), "sessionid": "1", "logid": "0000000013"}
    from app.ingest.normalize import normalize
    await clean_ch.ainsert("events", [normalize(rec, source="syslog", firewall={"id": 1, "name": "lab-fgt"})], EVENT_COLUMNS)
    assert (await response.verify(clean_ch, a))["outcome"] == "verified" and a.status == "verified"
    await clean_ch.ainsert("events", [normalize({**rec, "action": "accept", "sessionid": "2"}, source="syslog", firewall={"id": 1, "name": "lab-fgt"})], EVENT_COLUMNS)
    assert (await response.verify(clean_ch, a))["outcome"] == "not_verified"
    await response.record_rollback(db, a, u["boss"], "removed")
    assert a.status == "rolled_back" and [e["event"] for e in a.log][:4] == ["requested", "approved", "applied", "verification: inconclusive"]
    for bad in ("10.1.1.1", "0.0.0.0/0", "203.0.113.0/16", "not-an-ip"):
        with pytest.raises(response.ResponseError):
            await response.request(db, u["req"], "block_ip", bad, reason="nope")
    with pytest.raises(response.ResponseError):
        await response.request(db, u["req"], "disable_account", "bob; rm -rf /", reason="injection attempt")


async def test_response_api_read_only_runs_and_containment_waits(api, db, clean_ch):  # noqa: F811
    h = await login(api, "analyst1")
    r = await api.post("/api/response/actions", headers=h, json={"kind": "enrich_ip", "target": "203.0.113.70", "reason": "what is this address"})
    assert r.status_code == 201 and r.json()["status"] == "done" and "events_7d" in r.json()["result"]
    r = await api.post("/api/response/actions", headers=h, json={"kind": "disable_account", "target": "CORP\\alice", "reason": "credential stuffing succeeded"})
    act = r.json()
    assert act["status"] == "pending" and "Disable-ADAccount -Identity 'alice'" in act["plan"]["steps"][0]["apply"] and not act["can_decide"]
    assert (await api.post(f"/api/response/actions/{act['id']}/decision", headers=h, json={"approve": True})).status_code == 403
    await api.post("/api/auth/logout", headers=h)
    ha = await login(api, "admin1")
    lst = (await api.get("/api/response/actions?status=pending")).json()
    assert lst["items"][0]["can_decide"]
    assert (await api.post(f"/api/response/actions/{act['id']}/decision", headers=ha, json={"approve": False, "comment": "service account"})).json()["status"] == "rejected"


async def test_ai_hunts_drop_queries_that_do_not_compile(monkeypatch):
    async def fake_call(system, messages, schema, max_tokens, effort):
        assert "198.51" not in messages[0]["content"]                         # no entities are sent
        return json.dumps({"hunts": [{"title": "ok", "why": "w", "query": "category:traffic | stats count by src_ip | sort -count | head 10", "technique": "T1046"},
                                     {"title": "bad", "why": "w", "query": "category:traffic | bogus_command x", "technique": ""}]}), "claude-opus-5-5"
    monkeypatch.setattr(ai, "_call", fake_call)
    out = await ai.suggest_hunts({"recent_detections": [{"name": "Port scan", "techniques": ["T1046"], "count": 3}]}, [])
    assert [h["title"] for h in out["hunts"]] == ["ok"] and out["dropped"][0]["title"] == "bad"


async def test_brief_and_incident_lifecycle_api(api, db, clean_ch):  # noqa: F811
    db.add(AlertRule(key="vpn_bruteforce", name="VPN brute force", description="Many VPN login failures", severity="high", enabled=True, params={},
                     mitre={"tactic": "TA0006", "techniques": ["T1110"]}))
    a = _alert()
    a.event_filter = {"category": ["system"], "src_ip": "203.0.113.5"}
    a.evidence = {"falsepositives": ["users with a stale password"], "confidence": "high"}
    inc = Incident(title="VPN brute force from 203.0.113.5", entity_type="ip", entity="203.0.113.5", severity="high", status="open", category="security")
    db.add_all([a, inc])
    await db.commit()
    a.incident_id = inc.id
    await db.commit()
    h = await login(api, "analyst1")
    b = (await api.get(f"/api/alerts/{a.id}/brief")).json()
    assert b["why_detected"]["description"] == "Many VPN login failures" and b["attack"]["techniques"][0]["name"] == "Brute Force"
    assert b["impact"]["statement"].startswith("Credential access") and b["evidence"]["events"] == [] and "no stored events" in b["evidence"]["note"]
    p = await api.patch(f"/api/incidents/{inc.id}", headers=h, json={"stage": "triage", "priority": "P1", "tags": ["VPN", "vpn", " brute "]})
    assert p.status_code == 200 and p.json()["stage"] == "triage" and p.json()["status"] == "in_progress" and p.json()["priority"] == "P1" and p.json()["tags"] == ["brute", "vpn"]
    assert (await api.patch(f"/api/incidents/{inc.id}", headers=h, json={"stage": "closed"})).status_code == 422          # needs a closure reason
    for st in ("containment", "eradication", "recovery"):
        assert (await api.patch(f"/api/incidents/{inc.id}", headers=h, json={"stage": st})).json()["stage"] == st
    e = await api.post(f"/api/incidents/{inc.id}/escalate", headers=h, json={"to": "tier2", "reason": "credentials confirmed working"})
    assert e.json()["escalated_to"] == "tier2"
    done = (await api.patch(f"/api/incidents/{inc.id}", headers=h, json={"stage": "closed", "closure_reason": "true_positive"})).json()
    assert done["status"] == "closed" and done["stage"] == "closed"
    tl = (await api.get(f"/api/incidents/{inc.id}/timeline")).json()
    texts = [x["text"] for x in tl["items"]]
    assert any(t.startswith("Stage new → triage") for t in texts) and any(t.startswith("Escalated to tier2") for t in texts)
    assert tl["items"][0]["kind"] in ("detection", "created") and any(x["kind"] == "detection" for x in tl["items"])
    assert len((await api.get("/api/incidents?stage=closed")).json()["items"]) == 1
