"""ICMP reachability: damped up/down state machine, results, availability, alert rule and API (pinger mocked)."""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app import icmp
from app.alerts.engine import ensure_default_rules, run_rules
from app.db.models import Alert, AlertRule, IcmpEvent, IcmpTarget
from app.icmp import ProbeResult, evaluate, run_due

from .test_api import api, login  # noqa: F401

T0 = datetime(2026, 10, 27, 10, 0, tzinfo=timezone.utc)


def target(**kw):
    return IcmpTarget(id=1, name="Airtel WAN", address="203.0.113.10", state="unknown", fail_streak=0, ok_streak=0, probes=3,
                      timeout_ms=1000, interval_seconds=30, down_after=3, up_after=2, rtt_warn_ms=150, loss_warn_pct=20, **kw)


def ok(rtt=5.0, received=3):
    return ProbeResult(3, received, [rtt] * received)


FAIL = ProbeResult(3, 0, [])


def test_state_machine_damping():
    t = target()
    assert evaluate(t, ok(), T0).to_state == "up"
    assert evaluate(t, FAIL, T0 + timedelta(seconds=30)) is None and t.state == "up"       # 1 failure: still up
    assert evaluate(t, FAIL, T0 + timedelta(seconds=60)) is None
    ev = evaluate(t, FAIL, T0 + timedelta(seconds=90))                                       # 3rd failure: DOWN
    assert (ev.from_state, ev.to_state, ev.previous_duration_s) == ("up", "down", 90)
    assert evaluate(t, ok(), T0 + timedelta(seconds=120)) is None and t.state == "down"     # 1 good check: still down
    ev = evaluate(t, ok(), T0 + timedelta(seconds=150))
    assert (ev.to_state, ev.previous_duration_s) == ("up", 60)
    assert evaluate(t, ok(rtt=300), T0 + timedelta(seconds=180)).to_state == "degraded"    # reachable but slow
    assert evaluate(t, ok(received=2), T0 + timedelta(seconds=210)) is None                # 33 % loss: still degraded
    assert evaluate(t, ok(), T0 + timedelta(seconds=240)).to_state == "up"


@pytest.mark.asyncio
async def test_run_due_overview_and_alert(clean_ch, db):
    db.add(target())
    await db.commit()
    script = [ok(), ok(), FAIL, FAIL, FAIL, FAIL, ok(), ok(), ok()]
    now = datetime.now(timezone.utc) - timedelta(minutes=10)

    async def fake(addr, count, timeout):
        return script.pop(0)
    for i in range(6):  # 2 good, 4 failed (DOWN after the 3rd failure)
        await run_due(db, clean_ch, now + timedelta(seconds=30 * i), pinger=fake)
    t = (await db.execute(select(IcmpTarget))).scalars().one()
    assert t.state == "down" and t.fail_streak == 4
    await ensure_default_rules(db)
    for r in (await db.execute(select(AlertRule))).scalars():
        r.enabled = r.key == "icmp_down"
        if r.key == "icmp_down":
            r.params = {"min_down_minutes": 0}
    await db.commit()
    res = await run_rules(clean_ch, db)
    assert res["icmp_down"]["created"] == 1
    assert "203.0.113.10" in (await db.execute(select(Alert))).scalars().one().explanation
    for i in range(6, 9):  # recovers after up_after=2 good checks
        await run_due(db, clean_ch, now + timedelta(seconds=30 * i), pinger=fake)
    await db.refresh(t)
    assert t.state == "up"
    assert [(e.from_state, e.to_state) for e in (await db.execute(select(IcmpEvent).order_by(IcmpEvent.id))).scalars()] == \
        [("unknown", "up"), ("up", "down"), ("down", "up")]
    o = await icmp.overview(db, clean_ch, now - timedelta(minutes=1), now + timedelta(minutes=10))
    r = o["targets"][0]
    assert r["outages"] == 1 and 85 <= r["downtime_s"] <= 95 and r["checks"] == 9 and r["loss_pct"] == pytest.approx(100 * 12 / 27, 0.01)
    assert r["availability"] < 100 and o["events"][0]["to"] == "up"


def test_validate_address():
    assert icmp.validate_address(" 203.0.113.10 ") == "203.0.113.10"
    assert icmp.validate_address("dns.google") == "dns.google"
    for bad in ("127.0.0.1", "169.254.169.254", "224.0.0.1", "0.0.0.0", "bad host;rm"):
        with pytest.raises(ValueError):
            icmp.validate_address(bad)


@pytest.mark.asyncio
async def test_icmp_api(api, clean_ch, db):
    h = await login(api, "admin1")
    r = await api.post("/api/isp/icmp/targets", json={"name": "Airtel WAN", "address": "203.0.113.10", "isp_name": "Airtel"}, headers=h)
    assert r.status_code == 201, r.text
    assert (await api.post("/api/isp/icmp/targets", json={"name": "dup", "address": "203.0.113.10"}, headers=h)).status_code == 409
    assert (await api.post("/api/isp/icmp/targets", json={"name": "x", "address": "169.254.169.254"}, headers=h)).status_code == 422
    ha = await login(api, "analyst1")
    assert (await api.post("/api/isp/icmp/targets", json={"name": "y", "address": "198.51.100.1"}, headers=ha)).status_code == 403
    o = (await api.get("/api/isp/icmp/overview", params={"range": "24h"}, headers=ha)).json()
    assert o["targets"][0]["isp"] == "Airtel" and o["targets"][0]["state"] == "unknown"
