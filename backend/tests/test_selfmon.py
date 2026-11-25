"""Monitoring the monitor (app/selfmon.py): process figures in ClickHouse, objectives, the breach rule and /api/metrics."""
from datetime import datetime, timedelta, timezone

import pytest

from app import selfmon as M
from app.db.models import Switch
from app.nms.alerts import rule_nms_self_slo_breach

from .test_api import api  # noqa: F401  (fixture)


@pytest.fixture
def mch(ch):
    ch.command("TRUNCATE TABLE nms_self_metrics")
    return ch


async def test_process_figures_objectives_and_rule(db, mch, monkeypatch):
    monkeypatch.setenv("WORKER_ROLES", "snmp")
    now = datetime.now(timezone.utc)
    M.put("loop_lag_p95_s", 0.9)                          # a starved poller
    M.put("loop_last_run:wireless client rollup", now.timestamp() - 60)
    assert await M.flush(mch, now) >= 3
    (p,) = await M.latest(mch)
    assert p["service"] == "poller" and p["metrics"]["loop_lag_p95_s"] == 0.9 and "cpu_pct" in p["metrics"]
    db.add_all([Switch(name="FRESH", address="192.0.2.1", monitoring="active", state="up", last_success_at=now - timedelta(seconds=30),
                       capabilities={}, group_state={}, health={}, thresholds={}),
                Switch(name="STALE", address="192.0.2.2", monitoring="active", state="up", last_success_at=now - timedelta(hours=2),
                       capabilities={}, group_state={}, health={}, thresholds={})])
    await db.commit()
    st = await M.slo_status(db, mch, now)
    slo = {o["key"]: o for o in st["slos"]}
    assert slo["switch_freshness_pct"]["value"] == 50.0 and slo["switch_freshness_pct"]["ok"] is False
    assert slo["loop_lag_p95_s"]["ok"] is False and slo["rollup_age_s"]["ok"] is True and slo["wlc_freshness_pct"]["value"] is None
    assert st["stale_devices"][0]["name"] == "STALE"
    keys = {d.evidence["objective"] for d in await rule_nms_self_slo_breach(mch, now, {})}
    assert keys == {"switch_freshness_pct", "loop_lag_p95_s"}
    M.SELF.clear()


async def test_metrics_endpoint_exports_objectives(api, db, mch):  # noqa: F811
    from .test_iac import As
    M.put("loop_lag_p95_s", 0.01)
    await M.flush(mch)
    A = await As.login(api, "admin1")
    text = (await A.get("/api/metrics")).text
    assert 'nms_slo_value{objective="loop_lag_p95_s"} 0.01' in text and 'nms_process_metric{service=' in text
    N = await As.login(api, "analyst1")
    assert (await N.get("/api/nms/selfmon")).json()["slos"]
    M.SELF.clear()
