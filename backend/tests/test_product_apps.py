"""Phase 4 of the product separation: one source tree builds the combined app or either product alone
(docs/architecture/MIGRATION_PLAN.md)."""
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.alerts import engine
from app.main import create_app
from app.reports import runs_here
from app.worker import LOOP_PRODUCT, loop_plan, shared_jobs, worker_product, worker_roles


def _prefixes(app) -> set[str]:
    return {"/".join(r.path.split("/")[:3]) for r in app.routes if r.path.startswith("/api/")}


def test_each_product_app_mounts_only_its_own_routers():
    grid, nms, both = (_prefixes(create_app(product=p)) for p in ("grid", "nms", None))
    shared = {"/api/auth", "/api/alerts", "/api/alert-rules", "/api/notifications", "/api/reports", "/api/health", "/api/ready"}
    assert shared <= grid and shared <= nms
    assert {"/api/incidents", "/api/searches", "/api/identity", "/api/log-sources"} <= grid
    assert not {"/api/switches", "/api/wireless", "/api/bgp", "/api/drift", "/api/fwhealth", "/api/isp"} & grid
    assert {"/api/switches", "/api/wireless", "/api/bgp", "/api/drift", "/api/fwhealth", "/api/isp", "/api/firewalls"} <= nms
    assert not {"/api/incidents", "/api/searches", "/api/identity", "/api/log-sources"} & nms
    assert grid | nms == both          # the combined app is exactly the two products together


def test_unknown_product_is_refused():
    with pytest.raises(ValueError):
        create_app(product="siem")
    with pytest.raises(SystemExit):
        worker_product("siem")


@pytest.mark.asyncio
async def test_health_names_the_product():
    from httpx import ASGITransport, AsyncClient
    for product, want in (("grid", "grid"), ("nms", "nms"), (None, "combined")):
        async with AsyncClient(transport=ASGITransport(app=create_app(product=product)), base_url="http://t") as c:
            assert (await c.get("/api/health")).json() == {"status": "ok", "product": want}


def test_worker_plan_per_product():
    both = worker_roles(None)
    combined = loop_plan(both, 0)
    grid = loop_plan(both, 0, "grid", shared=True)
    nms = loop_plan(both, 0, "nms", shared=False)
    assert set(grid) | set(nms) == set(combined)                    # nothing lost, nothing new
    assert grid == ["loop_monitor", "alert_evaluation", "retention", "ngen_jobs", "identity_index", "soc_summaries"]
    assert "retention" not in nms and "switch_polling" in nms and "alert_evaluation" in nms
    assert all(LOOP_PRODUCT[x] in ("any", "nms") for x in nms)
    assert loop_plan(worker_roles("snmp"), 0, "grid") == ["loop_monitor"]   # no SNMP polling in a Grid process


def test_shared_jobs_default_only_in_the_combined_worker():
    assert shared_jobs(None, None) is True
    assert shared_jobs("grid", None) is False and shared_jobs("nms", "") is False
    assert shared_jobs("grid", "1") is True and shared_jobs(None, "off") is False


def test_report_definitions_run_in_one_product_process():
    d = lambda secs: SimpleNamespace(sections=secs)   # noqa: E731
    cases = {
        "nms only": (["nms_availability", "bgp"], "nms"),
        "grid only": (["alerts", "incidents"], "grid"),
        "mixed": (["alerts", "bgp"], "grid"),
        "default (all)": ([], "grid"),
    }
    for name, (secs, owner) in cases.items():
        assert [p for p in ("grid", "nms") if runs_here(d(secs), p)] == [owner], name


@pytest.mark.asyncio
async def test_run_rules_scoped_to_one_product(db, clean_ch):
    await engine.ensure_default_rules(db)
    now = datetime.now(timezone.utc)
    res = await engine.run_rules(clean_ch, db, now=now, correlate=False, product="nms")
    ran = {k for k in res if not k.startswith("_")}
    assert ran and all(engine.product_of(k).name == "nms" for k in ran)
    res = await engine.run_rules(clean_ch, db, now=now, correlate=False, product="grid")
    ran = {k for k in res if not k.startswith("_")}
    assert ran and all(engine.product_of(k).name == "grid" for k in ran)


@pytest.mark.asyncio
async def test_separated_after_run_hooks_stay_in_their_product(db, clean_ch, monkeypatch):
    """With the products apart, each pass hands its alerts only to its own product's after-run step."""
    calls = {}

    def hook(name):
        async def fn(s, ch, touched, now, result):
            calls[name] = [a.rule_key for a, _ in touched]
        return fn

    def det(key):
        return engine.Detection(group_key=key, count=1, first_seen=datetime.now(timezone.utc),
                                last_seen=datetime.now(timezone.utc), explanation="test")

    async def grid_rule(ch, now, p):
        return [det("g")]

    async def nms_rule(ch, now, p):
        return [det("n")]
    monkeypatch.setattr(engine, "PRODUCTS", {})
    monkeypatch.setattr(engine, "COMBINED_AFTER_RUN", None)
    mk = lambda key, sev="low": {"key": key, "name": key, "severity": sev, "mitre": {}, "description": "", "params": {}}  # noqa: E731
    engine.register("grid", rules={"t_grid": grid_rule}, defaults=[mk("t_grid")], after_run=hook("grid"))
    engine.register("nms", rules={"t_nms": nms_rule}, defaults=[mk("t_nms")], after_run=hook("nms"))
    await engine.ensure_default_rules(db)
    await engine.run_rules(clean_ch, db)
    assert calls == {"grid": ["t_grid"], "nms": ["t_nms"]}
    calls.clear()
    await engine.run_rules(clean_ch, db, product="nms")
    assert calls == {"nms": ["t_nms"]}   # an NMS-only pass: the open NMS alert is updated; the Grid step never runs
