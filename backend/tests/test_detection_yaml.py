"""YAML detection engine: rule pack validity and embedded tests (same SQL as production), compiler safety, engine
integration (alerts, grouping, run statistics), network-device syslog → rule end to end, and the API.

All events are LABELLED SYNTHETIC FIXTURES (RFC 5737 / RFC 1918 addresses, fake names)."""
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.alerts.engine import ensure_default_rules, run_rules
from app.db.ch_schema import EVENT_COLUMNS
from app.db.models import Alert, AlertRule
from app.detection.compiler import compile_rule
from app.detection.loader import RuleError, builtin, parse_rule
from app.detection.runner import run_tests
from app.ingest import generic

from .test_api import api, login  # noqa: F401
from .test_iac import As
from .test_storage_analytics import traffic

PACK = sorted(builtin().items())

CUSTOM = """
id: LAB-1001
name: Lab failed logins per user
description: Several failed logins for one user on network devices.
version: {version}
severity: low
category: credential_access
log_source: {{category: security, event_type: netdev}}
detection:
  selection: {{event_subtype: login_failed}}
  condition: {{group_by: [user], count: {count}, timeframe: 10m}}
data_sources: [network device syslog]
falsepositives: [typos]
investigation: [check the user]
tests:
  - name: three failures
    events: [{{event_subtype: login_failed, user: bob, repeat: 3}}]
    expect_alerts: {expect}
"""


def test_pack_loads_with_unique_ids_and_complete_metadata():
    assert len(PACK) >= 13
    ids = [r.id for _, (r, _) in PACK]
    assert len(ids) == len(set(ids))
    for _, (r, _) in PACK:
        assert r.tests and r.data_sources and r.falsepositives and r.investigation
        assert any(t.expect_alerts > 0 for t in r.tests) and any(t.expect_alerts == 0 for t in r.tests) or r.id in ("NET-2005", "NET-2006", "NET-2007", "NET-2009")


@pytest.mark.parametrize("key", [k for k, _ in PACK])
async def test_every_pack_rule_passes_its_embedded_tests(ch, key):
    rule = builtin()[key][0]
    res = await run_tests(ch, rule)
    assert all(r["passed"] for r in res), res


def test_compiler_rejects_unknown_fields_and_operators():
    base = CUSTOM.format(version=1, count=3, expect=1)
    for bad, msg in ((base.replace("event_subtype: login_failed}", "password: x}"), "unknown field"),
                     (base.replace("{event_subtype: login_failed}", "{event_subtype: {sql: x}}"), "unknown operator"),
                     (base.replace("group_by: [user]", "group_by: [\"user`; DROP TABLE events; --\"]"), "unknown field"),
                     (base.replace("{event_subtype: login_failed}", "{src_ip: {cidr: [not-a-net]}}"), "invalid CIDR"),
                     (base.replace("{event_subtype: login_failed}", "{msg: {internal: true}}"), "only applies to IP fields"),
                     ("- just\n- a list\n", "YAML mapping"), ("a: [unclosed", "YAML syntax")):
        with pytest.raises(RuleError) as e:
            parse_rule(bad)
        assert msg in str(e.value), (msg, e.value)


async def test_compiler_binds_values_as_parameters(ch):
    hostile = "x'); DROP TABLE events; --"
    r = parse_rule(CUSTOM.format(version=1, count=3, expect=1).replace("{event_subtype: login_failed}", "{user: \"" + hostile + "\"}"))
    q = compile_rule(r, t0=datetime(2026, 1, 1, tzinfo=timezone.utc), t1=datetime(2026, 1, 2, tzinfo=timezone.utc), cidrs=["10.0.0.0/8"])
    assert hostile not in q.sql and hostile in q.params.values()
    assert await ch.aquery(q.sql, q.params) == []      # runs, matches nothing, table intact
    assert ch.query("SELECT count() AS n FROM system.tables WHERE database = currentDatabase() AND name = 'events'")[0]["n"] == 1


async def _enable_only(db, *keys):
    await ensure_default_rules(db)
    for r in (await db.execute(select(AlertRule))).scalars():
        r.enabled = r.key in keys
    await db.commit()


async def test_engine_runs_yaml_rule_groups_alerts_and_records_stats(clean_ch, db):
    await _enable_only(db, "yml_net_1002")
    now = datetime.now(timezone.utc)
    recs = []
    for i in range(60):
        t = traffic(i, src="203.0.113.9", dport=1000 + i, action="deny")
        t["dstip"] = "10.1.1.10"
        recs.append(t)
    from app.ingest.normalize import normalize
    clean_ch.insert("events", [normalize(r, source="syslog", firewall={"id": 1, "name": "fw1", "site": "Lab"}) for r in recs], EVENT_COLUMNS)
    res = await run_rules(clean_ch, db, now=now)
    assert res["yml_net_1002"]["created"] == 1
    a = (await db.execute(select(Alert))).scalar_one()
    assert a.src_ip == "203.0.113.9" and "60 distinct ports" in a.explanation and a.mitre["tactic"] == "TA0043"
    assert a.evidence["rule_id"] == "NET-1002" and a.evidence["troubleshooting"] and a.firewall_ids == [1] and a.sites == ["Lab"]
    rule = (await db.execute(select(AlertRule).where(AlertRule.key == "yml_net_1002"))).scalar_one()
    assert rule.params["_stats"]["matches"] == 1 and rule.params["_stats"]["duration_ms"] >= 0 and rule.params["rule_version"] == 1
    res = await run_rules(clean_ch, db, now=now)          # interval not elapsed → skipped, nothing duplicated
    assert res["yml_net_1002"] == {"skipped": "interval"}


async def test_network_device_syslog_drives_yaml_rule_end_to_end(clean_ch, db):
    await _enable_only(db, "yml_net_2007", "yml_net_2001")
    src = {"id": 3, "name": "core-switches", "kind": "netdev", "site": "WH1"}
    lines = ["<189>Nov  2 10:00:01 WH1-CORE 812: %SYS-5-CONFIG_I: Configured from console by netadmin on vty0 (192.0.2.50)",
             "<189>820: %DHCP_SNOOPING-5-DHCP_SNOOPING_UNTRUSTED_PORT: DHCP_SNOOPING drop message on untrusted port, message type: DHCPOFFER, MAC sa: 00aa.bbcc.ddee"]
    clean_ch.insert("events", [generic.parse(src, ln) for ln in lines], EVENT_COLUMNS)
    res = await run_rules(clean_ch, db)
    assert res["yml_net_2007"]["created"] == 1 and res["yml_net_2001"]["created"] == 1
    alerts = {a.rule_key: a for a in (await db.execute(select(Alert))).scalars()}
    assert "netadmin" in alerts["yml_net_2007"].explanation and alerts["yml_net_2007"].sites == ["WH1"]
    assert alerts["yml_net_2007"].firewall_ids == []        # a log source, not a firewall
    assert "00:aa:bb:cc:dd:ee" in alerts["yml_net_2001"].explanation


async def test_yaml_rules_api(api, db, ch):  # noqa: F811
    admin = await As.login(api, "admin1")
    analyst = await As.login(api, "analyst1")
    await ensure_default_rules(db)
    lst = (await analyst.get("/api/detections/yaml")).json()["items"]
    assert {"NET-1002", "NET-3003"} <= {x["id"] for x in lst} and all(x["origin"] == "builtin" for x in lst)
    d = (await analyst.get("/api/detections/yaml/yml_net_3001")).json()
    assert d["yaml"].startswith("id: NET-3001") and d["mitre"]["tactic"] == "TA0010"
    t = (await analyst.post("/api/detections/yaml/yml_net_3001/test")).json()
    assert t["passed"] and len(t["results"]) == 5
    states = {x["id"]: x["enabled"] for x in lst}
    assert states["NET-3001"] is False and states["NET-1002"] is True     # experimental rules are seeded disabled
    v = (await analyst.post("/api/detections/yaml/validate", json={"yaml": "id: bad\nname: x\n"})).json()
    assert v["valid"] is False and v["errors"]
    v = (await analyst.post("/api/detections/yaml/validate", json={"yaml": CUSTOM.format(version=1, count=3, expect=1)})).json()
    assert v["valid"] and "{p" in v["sql"] and "login_failed" not in v["sql"]
    dr = (await analyst.post("/api/detections/yaml/yml_net_1002/dry-run", params={"hours": 24})).json()
    assert dr["rule_id"] == "NET-1002" and "results" in dr
    # custom rules: admin only, tests must pass, versions must increase, rollback, delete
    body = {"yaml": CUSTOM.format(version=1, count=3, expect=1)}
    assert (await analyst.post("/api/detections/yaml", json=body)).status_code == 403
    bad = await admin.post("/api/detections/yaml", json={"yaml": CUSTOM.format(version=1, count=3, expect=0)})
    assert bad.status_code == 422 and "embedded tests failed" in bad.text
    r = await admin.post("/api/detections/yaml", json=body)
    assert r.status_code == 201 and r.json()["origin"] == "custom" and r.json()["enabled"] is True
    assert (await admin.post("/api/detections/yaml", json=body)).status_code == 409              # same version
    r = await admin.post("/api/detections/yaml", json={"yaml": CUSTOM.format(version=2, count=2, expect=1)})
    assert r.json()["version"] == 2 and [h["version"] for h in r.json()["history"]] == [2, 1]
    r = await admin.post("/api/detections/yaml/yml_lab_1001/rollback/1")
    assert r.json()["version"] == 3 and r.json()["default_threshold"] == 3
    assert (await admin.put("/api/alert-rules/yml_lab_1001", json={"params": {"threshold": 5}})).json()["params"]["threshold"] == 5
    assert (await admin.put("/api/alert-rules/yml_net_1002", json={"enabled": False})).json()["enabled"] is False
    pack = await admin.post("/api/detections/yaml", json={"yaml": builtin()["yml_net_1002"][1].replace("version: 1", "version: 9")})
    assert pack.status_code == 409 and "built-in" in pack.text
    assert (await admin.delete("/api/detections/yaml/yml_net_1002")).status_code == 409
    assert (await analyst.delete("/api/detections/yaml/yml_lab_1001")).status_code == 403
    assert (await admin.delete("/api/detections/yaml/yml_lab_1001")).status_code == 200
    assert (await analyst.get("/api/detections/yaml/yml_lab_1001")).status_code == 404
