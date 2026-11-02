"""Infrastructure as Code: schema, rendering, diff, rules, plans, approvals (separation of duties), deployments with a
mocked FortiGate (success, failure, stale, dry run, locks), drift, backups / recovery, redaction, audit chain, API."""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.config import get_settings
from app.db.models import Alert, AlertRule, Firewall, IacAudit, IacBackup, IacDevice, IacJob, IacPlan, User
from app.fortigate.client import TokenBucket
from app.iac import adapters, executor, service as S
from app.iac.adapters import FortiGateAdapter
from app.iac.diff import compute, order_moves
from app.iac.resources import redact
from app.iac.rules import evaluate, load_ruleset
from app.iac.schema import ConfigError, import_yaml, parse, render, variables_for
from app.security import TokenCipher, hash_password

from .iac_fake import FakeFortiGate
from .test_api import PW, api, login  # noqa: F401

DOC = """apiVersion: iac.sentinelgrid/v1
kind: FirewallConfig
metadata: {name: lab}
variables: {lan: 10.20.0.0/16}
resources:
  addresses:
    - {name: LAN, subnet: "${lan}"}
    - {name: SRV, subnet: 10.30.0.10/32}
  address_groups:
    - {name: INTERNAL, members: [LAN, SRV]}
  services:
    - {name: APP-8443, tcp: ["8443"]}
  policies:
    - {id: 10, name: lan-out, srcintf: [port1], dstintf: [wan1], srcaddr: [LAN], dstaddr: [all], service: [HTTPS, APP-8443], action: accept, nat: enable, logtraffic: all}
    - {id: 20, name: to-srv, srcintf: [port1], dstintf: [port2], srcaddr: [INTERNAL], dstaddr: [SRV], service: [SSH], action: accept, logtraffic: all}
  system_global: {admintimeout: 10}
"""


# ------------------------------------------------------------------ schema / render
def test_schema_errors_have_lines():
    with pytest.raises(ConfigError) as e:
        parse("apiVersion: iac.sentinelgrid/v1\nkind: FirewallConfig\nmetadata: {name: x}\nresources:\n  addresses:\n    - {name: A, subnett: 1.2.3.4}\n")
    err = e.value.errors[0]
    assert err["line"] == 6 and "subnett" in err["message"]
    with pytest.raises(ConfigError) as e:
        parse("apiVersion: iac.sentinelgrid/v1\nkind: FirewallConfig\nmetadata: {name: x}\nresources:\n  vpn_ipsec_phase1: []\n")
    assert "unsupported resource type" in e.value.errors[0]["message"] and e.value.errors[0]["line"] == 5
    with pytest.raises(ConfigError) as e:
        parse("apiVersion: iac.sentinelgrid/v1\nkind: [unclosed\n")
    assert "YAML syntax error" in e.value.errors[0]["message"] and e.value.errors[0]["line"]


def test_render_variables_and_errors():
    doc = parse(DOC.replace("devices_placeholder", ""))
    desired, order, errs = render(doc, variables_for(doc, "FW1", "Site-A", {"lan": "10.99.0.0/16"}))
    assert not errs and desired["address"]["LAN"]["subnet"] == "10.99.0.0/16" and order == ["10", "20"]
    assert desired["address_group"]["INTERNAL"]["members"] == ["LAN", "SRV"]
    bad = parse(DOC.replace('"${lan}"', '"${missing}"'))
    _, _, errs = render(bad, variables_for(bad, "", ""))
    assert any("undefined variable ${missing}" in e["message"] for e in errs)


def test_diff_prune_previous_and_moves():
    desired = {"address": {"A": {"type": "ipmask", "subnet": "10.0.0.0/24", "comment": ""}}, "policy": {}}
    observed = {"address": {"A": {"type": "ipmask", "subnet": "10.0.1.0/24", "comment": ""}, "OLD": {"type": "ipmask", "subnet": "10.9.0.0/24"},
                            "OTHER": {"type": "ipmask", "subnet": "10.8.0.0/24"}}}
    ch = compute(desired, observed, managed_types={"address"}, prune_types=set(), previously_managed={"address": ["OLD"]})
    assert [(c["action"], c["key"]) for c in ch] == [("update", "A"), ("delete", "OLD")]  # OTHER is not ours: left alone
    ch = compute(desired, observed, managed_types={"address"}, prune_types={"address"}, previously_managed={})
    assert {c["key"] for c in ch if c["action"] == "delete"} == {"OLD", "OTHER"}
    moves = order_moves(["3", "1", "2"], ["1", "2", "3"])
    assert [(m["key"], m["desired"]) for m in moves] == [("3", {"before": "1"})]
    assert order_moves(["1", "2"], ["1", "2"]) == []


@pytest.mark.asyncio
async def test_security_rules_and_exceptions(db):
    rs = await load_ruleset(db)
    doc = parse(DOC + """    # appended policies
""".replace("    # appended policies\n", ""))
    desired, order, _ = render(doc, variables_for(doc, "", ""))
    desired["policy"]["30"] = {**desired["policy"]["10"], "name": "dup"}           # redundant behind policy 10
    desired["policy"]["40"] = {**desired["policy"]["10"], "srcaddr": ["all"], "service": ["ALL"], "logtraffic": "disable", "name": "any"}
    desired["policy"]["50"] = {**desired["policy"]["10"], "srcaddr": ["NOPE"], "name": "bad-ref"}
    desired["system_global"] = {"": {"admin-telnet": "enable"}}
    f = evaluate(rs, desired, order + ["30", "40", "50"], "production")
    ids = {(x["rule_id"], x["resource"]) for x in f}
    assert ("IAC-SEC-007", "policy:30") in ids and ("IAC-SEC-001", "policy:40") in ids and ("IAC-SEC-002", "policy:40") in ids
    assert ("IAC-SEC-003", "policy:40") in ids and ("IAC-SEC-006", "policy:50") in ids and ("IAC-SEC-004", "system_global") in ids
    assert next(x for x in f if x["rule_id"] == "IAC-SEC-001")["blocks"]
    assert not next(x for x in evaluate(rs, desired, order + ["40"], "development") if x["rule_id"] == "IAC-SEC-001")["blocks"]
    from app.db.models import IacException
    db.add(IacException(rule_id="IAC-SEC-001", resource="policy:40", owner="netops", justification="temporary migration rule",
                        expires_at=datetime.now(timezone.utc) + timedelta(days=7), created_by="admin1"))
    await db.commit()
    rs2 = await load_ruleset(db)
    x = next(x for x in evaluate(rs2, desired, order + ["40"], "production") if x["rule_id"] == "IAC-SEC-001")
    assert not x["blocks"] and x["exception"]["owner"] == "netops" and rs2["hash"] != rs["hash"]


def test_redaction():
    r = redact({"password": "hunter2", "psksecret": "abc", "nested": [{"api_key": "k"}], "note": "set password ENC SH2abcdefghij== token=abcdef0123"})
    assert r["password"] == "***" and r["psksecret"] == "***" and r["nested"][0]["api_key"] == "***"
    assert "SH2abc" not in r["note"] and "abcdef0123" not in r["note"]


# ------------------------------------------------------------------ fixtures
@pytest.fixture
def fake(monkeypatch):
    fg = FakeFortiGate()
    fg.add("address", {"name": "LAN", "type": "ipmask", "subnet": "10.20.0.0 255.255.255.0"})
    fg.add("policy", {"policyid": 5, "name": "legacy", "srcintf": [{"name": "port1"}], "dstintf": [{"name": "wan1"}], "srcaddr": [{"name": "LAN"}],
                      "dstaddr": [{"name": "all"}], "service": [{"name": "HTTPS"}], "action": "accept", "schedule": "always", "nat": "enable",
                      "logtraffic": "all", "status": "enable"})

    def make(fw, *, integration="fortigate_api", writes_allowed=False):
        ad = FortiGateAdapter(fw, writes_allowed=writes_allowed and integration == "fortigate_api", transport=fg.transport())
        ad.client._bucket = TokenBucket(10000)
        return ad
    monkeypatch.setattr(adapters, "make_adapter", make)
    return fg


@pytest.fixture
def writes_on(monkeypatch):
    monkeypatch.setenv("IAC_DEVICE_WRITES", "true")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


class As:
    """One HTTP client per user (separate session cookie + CSRF token)."""

    def __init__(self, client, headers):
        self.c, self.h = client, headers

    @classmethod
    async def login(cls, api, user):  # noqa: F811
        import httpx
        c = httpx.AsyncClient(transport=api._transport, base_url=str(api.base_url))
        return cls(c, await login(c, user))

    def get(self, url, **kw):
        return self.c.get(url, headers=self.h, **kw)

    def post(self, url, **kw):
        return self.c.post(url, headers=self.h, **kw)

    def put(self, url, **kw):
        return self.c.put(url, headers=self.h, **kw)

    def delete(self, url, **kw):
        return self.c.delete(url, headers=self.h, **kw)


async def _setup(api, db, env="production"):  # noqa: F811
    db.add_all([User(username=u, password_hash=hash_password(PW), role="analyst", products=["grid", "nms"], iac_roles=r)
                for u, r in (("editor1", ["editor"]), ("approver1", ["approver"]), ("deployer1", ["deployer"]))])
    db.add(Firewall(name="FW-LAB-01", host="10.0.0.1", token_ciphertext=TokenCipher().encrypt("test-token"), site="Lab", vendor="fortinet"))
    await db.commit()
    fw = (await db.execute(select(Firewall).where(Firewall.name == "FW-LAB-01"))).scalars().one()
    h = {}
    for u in ("admin1", "analyst1", "editor1", "approver1", "deployer1"):
        h[u] = await As.login(api, u)
    rp = await h["admin1"].post("/api/iac/projects", json={"name": "lab", "environment": env})
    assert rp.status_code == 201, rp.text
    pid = rp.json()["id"]
    r = await h["admin1"].post(f"/api/iac/projects/{pid}/devices", json={"firewall_id": fw.id})
    assert r.status_code == 201, r.text
    r = await h["editor1"].post(f"/api/iac/projects/{pid}/versions", json={"content": DOC, "message": "baseline"})
    assert r.status_code == 201 and r.json()["valid"], r.text
    return h, pid, r.json()["id"], fw


async def _plan(api, h, pid, vid, who="editor1"):  # noqa: F811
    r = await h[who].post(f"/api/iac/projects/{pid}/plans", json={"version_id": vid})
    assert r.status_code == 201, r.text
    return (await h[who].get(f"/api/iac/plans/{r.json()['id']}")).json()


async def _approve(api, h, plan, who="approver1"):  # noqa: F811
    assert (await h["editor1"].post(f"/api/iac/plans/{plan['id']}/submit")).status_code == 200
    r = await h[who].post(f"/api/iac/plans/{plan['id']}/decision", json={"decision": "approve", "plan_hash": plan["plan_hash"],
                                                                       "acknowledge_destructive": True})
    assert r.status_code == 200, r.text


# ------------------------------------------------------------------ workflow
@pytest.mark.asyncio
async def test_plan_approve_deploy_drift_recover(api, db, fake, writes_on):  # noqa: F811
    h, pid, vid, fw = await _setup(api, db)
    plan = await _plan(api, h, pid, vid)
    assert plan["status"] == "ready_for_review" and not plan["blocking"], plan["errors"]
    acts = {(c["type"], c["key"], c["action"]) for c in plan["changes"]}
    assert ("address", "LAN", "update") in acts and ("address", "SRV", "create") in acts and ("policy", "10", "create") in acts
    assert ("system_global", "", "update") in acts and not any(c["key"] == "5" for c in plan["changes"])  # unmanaged policy untouched
    assert next(c for c in plan["changes"] if c["key"] == "10")["risk"] in ("high", "critical")
    assert plan["changes"][0]["type"] in ("address", "service") and plan["summary"]["create"] >= 5
    # roles and separation of duties
    assert (await h["analyst1"].post(f"/api/iac/plans/{plan['id']}/submit")).status_code == 403
    assert (await h["editor1"].post(f"/api/iac/plans/{plan['id']}/submit")).status_code == 200
    body = {"decision": "approve", "plan_hash": plan["plan_hash"], "acknowledge_destructive": True}
    assert (await h["editor1"].post(f"/api/iac/plans/{plan['id']}/decision", json=body)).status_code == 403
    assert (await h["approver1"].post(f"/api/iac/plans/{plan['id']}/decision", json={**body, "plan_hash": "0" * 64})).status_code == 409
    assert (await h["approver1"].post(f"/api/iac/plans/{plan['id']}/decision", json=body)).status_code == 200
    # deployment gates
    assert (await h["approver1"].post(f"/api/iac/plans/{plan['id']}/jobs", json={})).status_code == 403
    r = await h["deployer1"].post(f"/api/iac/plans/{plan['id']}/jobs", json={})
    assert r.status_code == 409 and "disabled in the IaC settings" in r.text
    assert (await h["deployer1"].put("/api/iac/settings", json={"writes_enabled": True})).status_code == 403
    assert (await h["admin1"].put("/api/iac/settings", json={"writes_enabled": True})).json()["writes_effective"]
    r = await h["deployer1"].post(f"/api/iac/plans/{plan['id']}/jobs", json={"acknowledge_destructive": True})
    assert r.status_code == 201, r.text
    assert (await h["deployer1"].post(f"/api/iac/plans/{plan['id']}/jobs", json={})).status_code == 409  # already queued
    jid = r.json()["id"]
    assert await executor.claim_next() == jid
    await executor.run(jid)
    j = (await h["analyst1"].get(f"/api/iac/jobs/{jid}")).json()
    assert j["status"] == "succeeded", j
    d = j["devices"][0]
    assert d["status"] == "succeeded" and d["verification"]["ok"] and d["health"]["after"]["reachable"] and d["backup_id"]
    assert fake.tables["address"]["SRV"]["subnet"] == "10.30.0.10 255.255.255.255" and fake.singletons["system_global"]["admintimeout"] == 10
    assert fake.order == ["5", "10", "20"]
    b = (await h["analyst1"].get("/api/iac/backups")).json()[0]
    assert b["validated"] and b["full_config"] and b["objects"]["address"] >= 2
    raw = await db.get(IacBackup, b["id"])
    assert "SH2abc" not in str(raw.snapshot) and "SH2abc" not in (raw.full_config_ciphertext or "")  # full config only encrypted
    assert (await h["analyst1"].get(f"/api/iac/plans/{plan['id']}")).json()["status"] == "succeeded"
    # drift: in sync, then a manual GUI change
    dev = (await db.execute(select(IacDevice))).scalars().one()
    rec = await S.drift_check(db, dev)
    assert rec.status == "in_sync", rec.findings
    fake.tables["policy"]["10"]["action"] = "deny"
    fake.add("policy", {"policyid": 99, "name": "temp-any", "srcintf": [{"name": "port1"}], "dstintf": [{"name": "wan1"}], "srcaddr": [{"name": "all"}],
                        "dstaddr": [{"name": "all"}], "service": [{"name": "ALL"}], "action": "accept", "schedule": "always", "status": "enable"})
    rec = await S.drift_check(db, dev)
    rules = {f["rule_id"] for f in rec.findings}
    assert rec.status == "drift" and "DRIFT-POLICY-ACTION" in rules and any(f["key"] == "99" and f["change"] == "unmanaged" for f in rec.findings)
    assert not any(f["key"] == "5" for f in rec.findings)  # policy 5 was already there at deployment: baseline, not drift
    from app.alerts.engine import ensure_default_rules, run_rules
    await ensure_default_rules(db)
    for ar in (await db.execute(select(AlertRule))).scalars():
        ar.enabled = ar.key == "iac_drift"
        if ar.enabled:
            ar.params = {**ar.params, "interval_minutes": 0}
    await db.commit()
    from app.db.ch import get_ch
    assert (await run_rules(get_ch(), db))["iac_drift"]["created"] == 1
    assert "differs from its approved IaC configuration" in (await db.execute(select(Alert))).scalars().one().explanation
    # recovery plan from the pre-change backup: undo IaC's own changes, leave the manual policy 99 alone
    r = await h["deployer1"].post(f"/api/iac/backups/{b['id']}/recovery-plan")
    assert r.status_code == 201, r.text
    rp = (await h["analyst1"].get(f"/api/iac/plans/{r.json()['id']}")).json()
    ra = {(c["type"], c["key"], c["action"]) for c in rp["changes"]}
    assert rp["kind"] == "recovery" and ("address", "SRV", "delete") in ra and ("policy", "20", "delete") in ra and ("address", "LAN", "update") in ra
    assert not any(c["key"] == "99" for c in rp["changes"])
    order = [c["type"] for c in rp["changes"] if c["action"] == "delete"]
    assert order.index("policy") < order.index("address")


@pytest.mark.asyncio
async def test_failed_deployment_reports_actual_state(api, db, fake, writes_on):  # noqa: F811
    h, pid, vid, fw = await _setup(api, db, env="development")
    plan = await _plan(api, h, pid, vid)
    await _approve(api, h, plan)
    await h["admin1"].put("/api/iac/settings", json={"writes_enabled": True})
    fake.fail_on = ("POST", "firewall/policy")
    jid = (await h["deployer1"].post(f"/api/iac/plans/{plan['id']}/jobs", json={"acknowledge_destructive": True})).json()["id"]
    await executor.run(jid)
    j = (await h["analyst1"].get(f"/api/iac/jobs/{jid}")).json()
    d = j["devices"][0]
    assert j["status"] == "failed" and "No automatic rollback" in j["error"] and d["status"] == "failed"
    assert any(not r["ok"] for r in d["results"]) and any(r["ok"] for r in d["results"])  # partial: objects created, policy failed
    assert "SRV" in fake.tables["address"] and "10" not in fake.tables["policy"]
    assert (await h["analyst1"].get(f"/api/iac/plans/{plan['id']}")).json()["status"] == "failed"
    assert (await db.execute(select(IacDevice))).scalars().one().last_deploy_status == "failed"


@pytest.mark.asyncio
async def test_stale_plan_rejected(api, db, fake, writes_on):  # noqa: F811
    h, pid, vid, fw = await _setup(api, db, env="development")
    plan = await _plan(api, h, pid, vid)
    await _approve(api, h, plan)
    await h["admin1"].put("/api/iac/settings", json={"writes_enabled": True})
    fake.add("address", {"name": "NEW-MANUAL", "type": "ipmask", "subnet": "10.77.0.0 255.255.0.0"})  # someone changed the device
    jid = (await h["deployer1"].post(f"/api/iac/plans/{plan['id']}/jobs", json={"acknowledge_destructive": True})).json()["id"]
    writes_before = len(fake.writes)
    await executor.run(jid)
    j = (await h["analyst1"].get(f"/api/iac/jobs/{jid}")).json()
    assert j["status"] == "failed" and "changed since planning" in j["error"] and len(fake.writes) == writes_before
    p = (await h["analyst1"].get(f"/api/iac/plans/{plan['id']}")).json()
    assert p["status"] == "stale" and p["stale_reason"]
    # a fresh plan for the new version of reality works; refresh endpoint also detects staleness
    plan2 = await _plan(api, h, pid, vid)
    fake.add("address", {"name": "NEW-MANUAL-2", "type": "ipmask", "subnet": "10.78.0.0 255.255.0.0"})
    assert (await h["editor1"].post(f"/api/iac/plans/{plan2['id']}/refresh")).json()["status"] == "stale"


@pytest.mark.asyncio
async def test_dry_run_never_writes_and_locks(api, db, fake):  # noqa: F811
    h, pid, vid, fw = await _setup(api, db, env="development")
    plan = await _plan(api, h, pid, vid)
    assert (await h["analyst1"].post(f"/api/iac/plans/{plan['id']}/jobs", json={"dry_run": True})).status_code == 403
    jid = (await h["editor1"].post(f"/api/iac/plans/{plan['id']}/jobs", json={"dry_run": True})).json()["id"]
    await executor.run(jid)
    j = (await h["analyst1"].get(f"/api/iac/jobs/{jid}")).json()
    assert j["status"] == "succeeded" and fake.writes == []
    reqs = [r["request"] for r in j["devices"][0]["results"]]
    assert {"method": "POST", "path": "/api/v2/cmdb/firewall/address"} == {k: reqs[0][k] for k in ("method", "path")} or reqs
    assert any(r["method"] == "PUT" and r["path"].endswith("/firewall/address/LAN") for r in reqs)
    fid = fw.id
    assert await S.acquire_locks([fid], 101, 60) and not await S.acquire_locks([fid, 999], 102, 60)
    await S.release_locks(101)
    assert await S.acquire_locks([fid], 102, 60)


@pytest.mark.asyncio
async def test_fortimanager_managed_device_blocked(api, db, fake):  # noqa: F811
    h, pid, vid, fw = await _setup(api, db, env="development")
    fake.central = {"type": "fortimanager", "fmg": "10.0.0.200"}
    did = (await db.execute(select(IacDevice))).scalars().one().id
    caps = (await h["editor1"].post(f"/api/iac/devices/{did}/capabilities")).json()
    assert caps["fortimanager"] and not caps["writable"] and "FortiManager" in caps["reason"]
    assert (await db.get(IacDevice, did)).integration == "fortimanager"


@pytest.mark.asyncio
async def test_api_validation_import_export_audit(api, db, fake):  # noqa: F811
    h, pid, vid, fw = await _setup(api, db, env="development")
    assert (await h["admin1"].post("/api/iac/projects", json={"name": "../etc", "environment": "dev"})).status_code == 422
    assert (await h["analyst1"].post("/api/iac/projects", json={"name": "x"})).status_code == 403
    r = await h["editor1"].post(f"/api/iac/projects/{pid}/validate", json={"content": "apiVersion: iac.sentinelgrid/v1\nkind: FirewallConfig\nmetadata: {name: x}\nresources:\n  policies:\n    - {id: 1}\n"})
    rep = r.json()
    assert not rep["valid"] and all(e["line"] for e in rep["errors"])
    r = await h["editor1"].post(f"/api/iac/projects/{pid}/versions", json={"content": DOC, "message": "same"})
    assert r.status_code == 409  # no changes since the last version
    fake.add_real_world_variants()
    imp = (await h["editor1"].post(f"/api/iac/projects/{pid}/import", json={"firewall_id": fw.id})).json()
    doc = parse(imp["content"])  # importable YAML round-trips through the schema
    assert {(x["type"], x["key"]) for x in imp["skipped"]} >= {("address", "EMS-TAG"), ("policy", "60")} and "policy:60" in doc.manage.ignore
    assert any(a.name == "LAN" for a in doc.resources.addresses) and any(p.id == 5 for p in doc.resources.policies)
    assert "Not imported" in imp["content"]
    ex = await h["analyst1"].get(f"/api/iac/projects/{pid}/export")
    import io
    import zipfile
    names = zipfile.ZipFile(io.BytesIO(ex.content)).namelist()
    assert "iac/inventory/devices.yaml" in names and any(n.startswith("iac/environments/development/history/") for n in names)
    assert b"test-token" not in ex.content
    a = (await h["analyst1"].get("/api/iac/audit", params={"verify": True})).json()
    assert a["chain"]["ok"] and a["total"] >= 4
    row = (await db.execute(select(IacAudit).order_by(IacAudit.id))).scalars().first()
    row.detail = {"tampered": True}
    await db.commit()
    assert not (await S.verify_audit(db))["ok"]
    assert (await h["editor1"].get("/api/iac/roles")).status_code == 403
    assert (await h["admin1"].put(f"/api/iac/roles/{(await db.execute(select(User).where(User.username == 'analyst1'))).scalars().one().id}",
                          json={"roles": ["root"]})).status_code == 422


@pytest.mark.asyncio
async def test_queue_cancel(api, db, fake, writes_on):  # noqa: F811
    h, pid, vid, fw = await _setup(api, db, env="development")
    plan = await _plan(api, h, pid, vid)
    await _approve(api, h, plan)
    await h["admin1"].put("/api/iac/settings", json={"writes_enabled": True})
    jid = (await h["deployer1"].post(f"/api/iac/plans/{plan['id']}/jobs", json={"acknowledge_destructive": True})).json()["id"]
    r = (await h["deployer1"].post(f"/api/iac/jobs/{jid}/cancel")).json()
    assert r["status"] == "cancelled" and (await db.get(IacPlan, plan["id"])).status == "approved"
    assert (await db.get(IacJob, jid)).status == "cancelled" and fake.writes == []


@pytest.mark.asyncio
async def test_worker_refuses_locked_device(api, db, fake, writes_on):  # noqa: F811
    h, pid, vid, fw = await _setup(api, db, env="development")
    fid = fw.id
    plan = await _plan(api, h, pid, vid)
    await _approve(api, h, plan)
    await h["admin1"].put("/api/iac/settings", json={"writes_enabled": True})
    jid = (await h["deployer1"].post(f"/api/iac/plans/{plan['id']}/jobs", json={"acknowledge_destructive": True})).json()["id"]
    assert await S.acquire_locks([fid], 4242, 600)  # another deployment (e.g. another worker replica) holds the device
    await executor.run(jid)
    j = (await h["analyst1"].get(f"/api/iac/jobs/{jid}")).json()
    assert j["status"] == "failed" and "lock" in j["error"] and fake.writes == []
    assert (await h["analyst1"].get(f"/api/iac/plans/{plan['id']}")).json()["status"] == "approved"  # can be retried later


# ------------------------------------------------------------------ import of real-world object variants
def _observed(fake: FakeFortiGate) -> tuple[dict, list[str]]:
    from app.iac.resources import from_cmdb
    state = {t: dict(from_cmdb(t, o) for o in tbl.values()) for t, tbl in fake.tables.items()}
    for t, o in fake.singletons.items():
        state[t] = {"": from_cmdb(t, o)[1]}
    return state, list(fake.order)


def test_import_real_world_variants_is_schema_valid():
    fake = FakeFortiGate()
    fake.add_real_world_variants()
    state, order = _observed(fake)
    types = ["address", "address_group", "service", "service_group", "policy", "static_route", "system_global", "syslog"]
    text, skipped = import_yaml(state, order, "lab-import", types)
    doc = parse(text)  # must never raise
    desired, dorder, errs = render(doc, {})
    assert errs == []
    got = {(x["type"], x["key"]) for x in skipped}
    assert got == {("address", "EMS-TAG"), ("address", "IN"), ("service", "webproxy"), ("policy", "60"), ("policy", "61")}
    assert all(x["reason"] for x in skipped)
    assert set(doc.manage.ignore) == {f"{t}:{k}" for t, k in got}
    # supported variants are imported with their meaning intact
    assert desired["address"]["MGMT-LOOP"] == {"type": "interface-subnet", "subnet": "172.16.3.100/32", "interface": "port1", "comment": ""}
    assert desired["address"]["PRINTER-MAC"]["macaddr"] == ["94:b6:09:00:00:01"]
    assert desired["static_route"]["1"]["sdwan_zone"] == ["virtual-wan-link"] and desired["static_route"]["2"]["blackhole"] == "enable"
    assert desired["policy"]["59"]["internet_service_name"] == ["Example-SaaS.Cloud"] and desired["policy"]["59"]["dstaddr"] == []
    assert dorder == ["59"]
    assert desired["address"]["PUSH-WILD"]["fqdn"] == "*.push.*"
    # importing and planning against the same device is a no-op, and the skipped objects are neither changed nor drift
    managed = {"address", "address_group", "service", "service_group", "policy", "static_route", "system_global", "syslog"}
    ign = doc.manage.ignored()
    ch = compute(desired, state, managed_types=managed, prune_types=set(managed) - {"system_global", "syslog"},
                 previously_managed={}, desired_order=dorder, observed_order=order, ignored=ign)
    assert ch == []
    obs = {"state": state, "order": order}
    assert S.drift_findings(desired, dorder, obs, managed, set(), {}, {}, None, ign) == []
    assert any(f["key"] == "60" and f["change"] == "unmanaged" for f in S.drift_findings(desired, dorder, obs, managed, set(), {}, {}, None, {}))
    # canonical -> cmdb keeps the variant fields
    from app.iac.resources import to_cmdb
    assert to_cmdb("static_route", "1", desired["static_route"]["1"])["sdwan-zone"] == [{"name": "virtual-wan-link"}]
    b = to_cmdb("policy", "59", desired["policy"]["59"])
    assert b["internet-service"] == "enable" and b["internet-service-name"] == [{"name": "Example-SaaS.Cloud"}] and b["dstaddr"] == []
    assert to_cmdb("address", "MGMT-LOOP", desired["address"]["MGMT-LOOP"])["interface"] == "port1"


def test_schema_variant_rules():
    head = "apiVersion: iac.sentinelgrid/v1\nkind: FirewallConfig\nmetadata: {name: x}\n"
    bad = {
        "resources:\n  static_routes:\n    - {id: 1, dst: 0.0.0.0/0}\n": "needs 'device'",
        "resources:\n  static_routes:\n    - {id: 1, dst: 0.0.0.0/0, device: wan1, sdwan_zone: [z]}\n": "only one of",
        "resources:\n  policies:\n    - {id: 1, srcintf: [a], dstintf: [b], srcaddr: [all], service: [HTTPS]}\n": "dstaddr",
        "resources:\n  policies:\n    - {id: 1, srcintf: [a], dstintf: [b], srcaddr: [all], internet_service: enable}\n": "internet_service_name",
        "resources:\n  policies:\n    - {id: 1, srcintf: [a], dstintf: [b], srcaddr: [all], dstaddr: [all], service: [ALL], internet_service: enable, internet_service_name: [X]}\n": "leave dstaddr",
        "resources:\n  addresses:\n    - {name: M, type: mac, macaddr: [nope]}\n": "MAC address",
        "manage:\n  ignore: [vip:x]\n": "must be <type>",
    }
    for body, msg in bad.items():
        with pytest.raises(ConfigError) as e:
            parse(head + body)
        assert msg in str(e.value), (body, str(e.value))
    doc = parse(head + "manage: {ignore: ['policy:7']}\nresources:\n  policies:\n    - {id: 7, srcintf: [a], dstintf: [b], srcaddr: [all], dstaddr: [all], service: [ALL]}\n")
    assert any("manage.ignore" in e["message"] for e in render(doc, {})[2])
