"""WAN observability: state machine, outage records, incidents, correlation, metrics, collector health, alerts,
notifications and APIs. Probes are mocked; no traffic is sent anywhere."""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app import icmp, wan, wan_metrics as WM
from app.alerts.engine import ensure_default_rules, run_rules
from app.db.models import (AlertRule, IcmpEvent, IcmpTarget, Incident, IspLink, NotificationChannel, NotificationOutbox, NotificationRule,
                           WanCollector, WanMaintenance, WanOutage)
from app.icmp import ProbeResult, evaluate, run_due

from .test_api import api, login  # noqa: F401
from .test_iac import As
from .test_isp import _ingest

REAL_NOW = datetime.now(timezone.utc).replace(microsecond=0)
T0 = REAL_NOW - timedelta(hours=2)          # simulated clock: always in the past, so windows end at "now"


def ok(rtts=(10.0, 12.0, 11.0)):
    return ProbeResult(len(rtts) or 3, len(rtts), list(rtts))


FAIL = ProbeResult(3, 0, [])
LOCAL = ProbeResult(3, 0, [], "cannot resolve: x", "local")


class Script:
    """Pinger returning scripted results per address."""

    def __init__(self, **per_addr):
        self.per = {k.replace("_", "."): list(v) for k, v in per_addr.items()}
        self.calls = []

    async def __call__(self, addr, count, timeout):
        self.calls.append(addr)
        seq = self.per.get(addr) or []
        return seq.pop(0) if seq else ok()


def mk(id_, addr, link=None, site="WH1", **kw):
    return IcmpTarget(id=id_, name=f"tgt-{id_}", address=addr, isp_link_id=link, site=site, state="unknown", fail_streak=0, ok_streak=0, probes=3,
                      timeout_ms=1000, interval_seconds=30, down_after=3, up_after=2, rtt_warn_ms=150, loss_warn_pct=20, enabled=True,
                      degrade_after=kw.pop("degrade_after", 1), clear_after=kw.pop("clear_after", 1), poor_streak=0, healthy_streak=0,
                      created_at=T0 - timedelta(minutes=5), **kw)


async def _setup(db, ch, targets, links=()):
    ch.command("TRUNCATE TABLE icmp_results")
    for lk in links:
        db.add(lk)
    await db.flush()
    for t in targets:
        db.add(t)
    await db.commit()


async def _run(db, ch, pinger, cycles, start=T0, every=30):
    for i in range(cycles):
        await run_due(db, ch, start + timedelta(seconds=every * i), pinger=pinger)


# ------------------------------------------------------------------ state machine
def test_state_machine_thresholds_degraded_jitter_and_local_errors():
    t = mk(1, "203.0.113.1", jitter_warn_ms=5.0)
    assert evaluate(t, ok(), T0).to_state == "up" and t.last_ok_at == T0
    for i in (1, 2):
        assert evaluate(t, FAIL, T0 + timedelta(seconds=30 * i)) is None and t.state == "up"
    assert t.fail_since == T0 + timedelta(seconds=30)
    assert evaluate(t, LOCAL, T0 + timedelta(seconds=75)) is None and t.fail_streak == 2   # local error: no evidence either way
    ev = evaluate(t, FAIL, T0 + timedelta(seconds=90))
    assert ev.to_state == "down" and t.fail_streak == 3
    assert evaluate(t, ok(), T0 + timedelta(seconds=120)) is None and t.state == "down"     # recovery needs up_after=2
    assert t.ok_since == T0 + timedelta(seconds=120)
    assert evaluate(t, ok(), T0 + timedelta(seconds=150)).to_state == "up"
    assert evaluate(t, ok((10.0, 30.0, 10.0)), T0 + timedelta(seconds=180)).to_state == "degraded"   # jitter 20 ms >= 5 ms
    assert t.last_jitter_ms == 20.0


def test_alternating_target_never_goes_down_below_threshold():
    t = mk(1, "203.0.113.1")
    evaluate(t, ok(), T0)
    for i in range(1, 20):
        evaluate(t, FAIL if i % 2 else ok(), T0 + timedelta(seconds=30 * i))
    assert t.state == "up"


# ------------------------------------------------------------------ outages, incidents, timestamps
@pytest.mark.asyncio
async def test_outage_record_timestamps_incident_and_recovery(db, ch):
    lk = IspLink(id=7, firewall_id=None, interface="", isp_name="TTSL", site="ASF Gurugram", circuit_id="TT-123", name="TTSL 1G")
    await _setup(db, ch, [mk(1, "203.0.113.1", link=7, site="")], [lk])
    p = Script(**{"203_0_113_1": [ok(), ok(), FAIL, FAIL, FAIL, FAIL, ok(), ok(), ok()]})
    await _run(db, ch, p, 6)
    o = (await db.execute(select(WanOutage))).scalars().one()
    assert o.recovered_at is None and o.site == "ASF Gurugram" and o.isp_name == "TTSL"
    assert wan.aware(o.last_ok_at) == T0 + timedelta(seconds=30)
    assert wan.aware(o.started_at) == T0 + timedelta(seconds=60) and wan.aware(o.detected_at) == T0 + timedelta(seconds=120)
    inc = (await db.execute(select(Incident))).scalars().one()
    assert inc.category == "wan" and inc.status == "open" and inc.isp_link_id == 7 and inc.correlation_key == "circuit:7"
    assert inc.severity == "high" and "TTSL" in inc.title and inc.probable_cause
    # worker restart in the middle of the outage: state is persisted, the outage is not duplicated
    t = await db.get(IcmpTarget, 1)
    again = await wan.open_outage(db, t, await wan.Ctx.load(db), kind="down", started_at=T0, detected_at=T0, last_ok_at=None,
                                  failed_checks=3, evidence={})
    assert again.id == o.id
    await db.commit()
    await _run(db, ch, p, 3, start=T0 + timedelta(seconds=180))
    await db.refresh(o)
    await db.refresh(inc)
    assert wan.aware(o.recovered_at) == T0 + timedelta(seconds=180) and wan.aware(o.recovery_detected_at) == T0 + timedelta(seconds=210)
    assert o.duration_s == 120
    assert inc.status == "resolved" and wan.aware(inc.resolved_at) == T0 + timedelta(seconds=180)   # default recovery_action
    assert len((await db.execute(select(WanOutage))).scalars().all()) == 1


@pytest.mark.asyncio
async def test_circuit_correlation_dedup_and_distinct_outages(db, ch):
    lk = IspLink(id=3, firewall_id=None, interface="", isp_name="Jio", site="ZFSL-PS")
    await _setup(db, ch, [mk(1, "203.0.113.1", link=3), mk(2, "203.0.113.2", link=3)], [lk])
    down = [ok()] + [FAIL] * 4
    p = Script(**{"203_0_113_1": down + [ok()] * 3, "203_0_113_2": down + [ok()] * 3})
    await _run(db, ch, p, 5)
    incs = (await db.execute(select(Incident))).scalars().all()
    outs = (await db.execute(select(WanOutage))).scalars().all()
    assert len(outs) == 2 and len(incs) == 1 and {o.incident_id for o in outs} == {incs[0].id}   # overlapping: one incident
    await _run(db, ch, p, 3, start=T0 + timedelta(seconds=150))
    await db.refresh(incs[0])
    assert incs[0].status == "resolved"
    # a later, separate outage of the same circuit opens a new incident (not merged because it was close in time)
    p2 = Script(**{"203_0_113_1": [FAIL] * 4})
    await _run(db, ch, p2, 4, start=T0 + timedelta(seconds=600))
    incs = (await db.execute(select(Incident).order_by(Incident.id))).scalars().all()
    assert len(incs) == 2 and incs[1].status == "open"


@pytest.mark.asyncio
async def test_site_correlation_and_recovery_while_investigating(db, ch):
    await wan.save_settings(db, {"correlation": "site"}, "admin1")
    a = IspLink(id=1, firewall_id=None, interface="", isp_name="TATA", site="WH9")
    b = IspLink(id=2, firewall_id=None, interface="", isp_name="Airtel", site="WH9")
    await _setup(db, ch, [mk(1, "203.0.113.1", link=1, site=""), mk(2, "203.0.113.2", link=2, site="")], [a, b])
    p = Script(**{"203_0_113_1": [ok()] + [FAIL] * 4, "203_0_113_2": [ok()] + [FAIL] * 4})
    await _run(db, ch, p, 5)
    inc = (await db.execute(select(Incident))).scalars().one()
    assert inc.entity_type == "site" and inc.correlation_key == "site:wh9"
    inv = await wan.investigate(db, at=T0 + timedelta(seconds=140), target_id=1)
    assert inv["classification"] == "site_wide" and any(e["kind"] == "site" for e in inv["evidence"])
    inc.status = "in_progress"  # someone is investigating
    await db.commit()
    await _run(db, ch, Script(), 3, start=T0 + timedelta(seconds=150))
    await db.refresh(inc)
    assert inc.status == "monitoring" and inc.resolved_at is None   # recovered, case kept for investigation


@pytest.mark.asyncio
async def test_maintenance_window_records_outage_without_incident_or_downtime(db, ch):
    db.add(WanMaintenance(name="ISP work", scope="site", scope_value="WH1", starts_at=T0 - timedelta(minutes=1), ends_at=T0 + timedelta(hours=1)))
    await _setup(db, ch, [mk(1, "203.0.113.1")])
    await _run(db, ch, Script(**{"203_0_113_1": [ok()] + [FAIL] * 4}), 5)
    o = (await db.execute(select(WanOutage))).scalars().one()
    assert o.maintenance_id is not None and o.incident_id is None
    assert not (await db.execute(select(Incident))).scalars().all()
    m = await WM.target_metrics(db, ch, [await db.get(IcmpTarget, 1)], T0 - timedelta(minutes=1), T0 + timedelta(minutes=5))
    assert m[1]["outages"] == 0 and m[1]["downtime_s"] == 0


# ------------------------------------------------------------------ metrics
@pytest.mark.asyncio
async def test_metrics_rtt_percentiles_jitter_loss_and_local_errors(db, ch):
    await _setup(db, ch, [mk(1, "203.0.113.1")])
    rtts = [(10.0, 20.0, 30.0), (40.0, 50.0, 60.0), (70.0, 80.0, 90.0), (100.0, 110.0, 120.0)]
    p = Script(**{"203_0_113_1": [ok(r) for r in rtts] + [ProbeResult(3, 2, [5.0, 9.0]), LOCAL]})
    await _run(db, ch, p, 6)
    m = (await WM.target_metrics(db, ch, [await db.get(IcmpTarget, 1)], T0, T0 + timedelta(seconds=200)))[1]
    samples = sorted([x for r in rtts for x in r] + [5.0, 9.0])     # 14 replies
    assert m["rtt_samples"] == 14 and m["rtt_ms"] == pytest.approx(sum(samples) / 14, 0.01)
    assert m["rtt_p95_ms"] == samples[int(14 * 0.95)] and m["rtt_p50_ms"] == samples[7] and m["rtt_p99_ms"] is None   # nearest rank
    assert m["rtt_min_ms"] == 5.0 and m["rtt_max_ms"] == 120.0
    assert m["jitter_ms"] == pytest.approx((10 * 8 + 4) / 9, 0.01)   # within-check pairs only: 8 pairs of 10 ms, one of 4 ms
    assert m["probes_sent"] == 15 and m["replies"] == 14 and m["loss_pct"] == pytest.approx(100 / 15, 0.01)   # local error excluded
    assert m["local_errors"] == 1 and m["checks"] == 6


@pytest.mark.asyncio
async def test_availability_excludes_gaps_and_pauses_and_open_outage(db, ch):
    await _setup(db, ch, [mk(1, "203.0.113.1")])
    p = Script(**{"203_0_113_1": [ok()] * 4 + [FAIL] * 6})
    await _run(db, ch, p, 4)                                         # 0..90 s healthy
    await _run(db, ch, p, 6, start=T0 + timedelta(seconds=600))      # collector gap 90 → 600 s, then 6 failures (open outage)
    t = await db.get(IcmpTarget, 1)
    m = (await WM.target_metrics(db, ch, [t], T0, T0 + timedelta(seconds=750)))[1]
    assert m["unobserved_s"] == 510 and m["ongoing_outage"] and m["outages"] == 1
    assert m["downtime_s"] == 150                                     # first failure at 600 s → window end 750 s
    assert m["availability"] == pytest.approx(100 * (240 - 150) / 240, 0.01) and m["coverage_pct"] == pytest.approx(100 * 240 / 750, 0.01)
    await icmp.set_paused(db, t, True, "circuit decommissioning", now=T0 + timedelta(seconds=760))
    await db.commit()
    o = (await db.execute(select(WanOutage))).scalars().one()
    assert o.recovered_at is not None and o.evidence["recovery"]["closed_by"] == "pause"
    m = (await WM.target_metrics(db, ch, [t], T0, T0 + timedelta(seconds=900)))[1]
    assert m["paused_s"] == 140 and t.state == "paused"


@pytest.mark.asyncio
async def test_lease_prevents_duplicate_probing_and_stale_results(db, ch):
    await _setup(db, ch, [mk(1, "203.0.113.1")])
    p = Script()
    t = await db.get(IcmpTarget, 1)
    t.lease_until = REAL_NOW + timedelta(minutes=5)   # another worker holds it
    await db.commit()
    await run_due(db, ch, T0, pinger=p)
    assert p.calls == []
    t.lease_until = None
    t.last_check = T0 + timedelta(seconds=100)           # a newer observation is already applied
    await db.commit()
    await run_due(db, ch, T0 + timedelta(seconds=140), pinger=p)
    assert p.calls == ["203.0.113.1"]
    await db.refresh(t)
    assert wan.aware(t.last_check) == T0 + timedelta(seconds=140)


@pytest.mark.asyncio
async def test_collector_health_and_stale_alert(db, ch):
    await _setup(db, ch, [mk(1, "203.0.113.1")])
    await run_due(db, ch, T0, pinger=Script())
    row = await db.get(WanCollector, 1)
    st = wan.collector_status(row, datetime.now(timezone.utc), 180)
    assert st["status"] == "ok" and st["last_checked"] == 1
    row.heartbeat_at = datetime.now(timezone.utc) - timedelta(minutes=10)
    await db.commit()
    assert wan.collector_status(row, datetime.now(timezone.utc), 180)["status"] == "stale"
    await ensure_default_rules(db)
    for r in (await db.execute(select(AlertRule))).scalars():
        r.enabled = r.key == "wan_collector_stale"
    await db.commit()
    assert (await run_rules(ch, db))["wan_collector_stale"]["created"] == 1
    row.heartbeat_at = datetime.now(timezone.utc)
    await db.commit()
    assert (await run_rules(ch, db))["wan_collector_stale"].get("resolved", 0) == 1


# ------------------------------------------------------------------ analytics, time zones, notifications
@pytest.mark.asyncio
async def test_incident_analytics_daily_buckets_in_viewer_timezone(db, ch):
    day = datetime(2026, 10, 10, tzinfo=timezone.utc)
    for i, (ts, isp, site, rc) in enumerate([(day + timedelta(hours=20), "TTSL", "ASF", None), (day + timedelta(hours=3), "Jio", "ZFSL", "isp_outage"),
                                             (day + timedelta(days=2, hours=1), "TTSL", "ASF", None)]):
        db.add(Incident(category="wan", title=f"i{i}", entity_type="circuit", entity="c", status="resolved", severity="high", site=site, isp_name=isp,
                        first_seen=ts, last_seen=ts, created_at=ts, resolved_at=ts + timedelta(minutes=30 * (i + 1)), root_cause_category=rc))
    await db.commit()
    a = await WM.incident_analytics(db, day, day + timedelta(days=4), tz="Asia/Kolkata")
    d = a["daily"]
    assert d["days"][0] == "2026-10-10" and len(d["days"]) == 5                 # zero-incident days are present
    ttsl = next(x for x in d["series"] if x["isp"] == "TTSL")["counts"]
    assert ttsl == [0, 1, 1, 0, 0]                                              # 20:00 UTC on the 10th is the 11th in IST
    t = a["totals"]
    assert t["incidents"] == 3 and t["missing_root_cause"] == 2 and t["sites_affected"] == 2 and t["avg_resolve_s"] == 3600
    assert a["by_location"][0] == {"site": "ASF", "incidents": 2}


@pytest.mark.asyncio
async def test_outage_and_recovery_notifications_with_duration(db, ch):
    chn = NotificationChannel(name="noc", type="webhook", config={})
    db.add(chn)
    await db.flush()
    db.add(NotificationRule(name="wan", channel_id=chn.id, event_types=["wan.outage", "wan.recovered"], min_severity="low", dedupe_minutes=30))
    await _setup(db, ch, [mk(1, "203.0.113.1")])
    await _run(db, ch, Script(**{"203_0_113_1": [ok()] + [FAIL] * 4 + [ok()] * 3}), 8)
    rows = (await db.execute(select(NotificationOutbox).order_by(NotificationOutbox.id))).scalars().all()
    assert [r.event_type for r in rows] == ["wan.outage", "wan.recovered"]
    assert "2m" in rows[1].payload["title"] and rows[1].payload["fields"]["Duration"] == "2m"


# ------------------------------------------------------------------ SD-WAN integration
@pytest.mark.asyncio
async def test_sdwan_outages_become_outage_records(db, clean_ch):
    await _ingest(clean_ch)
    r = await wan.sync_sdwan(db, clean_ch, hours=3)
    outs = (await db.execute(select(WanOutage).where(WanOutage.source == "sdwan").order_by(WanOutage.started_at))).scalars().all()
    assert r["opened"] == 2 and len(outs) == 2
    assert outs[0].recovered_at is not None and 590 <= outs[0].duration_s <= 610    # the 10-minute full outage
    assert outs[1].recovered_at is None                                              # port2 still down
    assert len((await db.execute(select(Incident))).scalars().all()) == 2
    assert await wan.sync_sdwan(db, clean_ch, hours=3) == {}                         # idempotent


# ------------------------------------------------------------------ API
@pytest.mark.asyncio
async def test_wan_api_inventory_incidents_rbac_and_views(api, clean_ch, db):
    clean_ch.command("TRUNCATE TABLE icmp_results")
    A = await As.login(api, "admin1")
    N = await As.login(api, "analyst1")
    r = await A.post("/api/wan/circuits", json={"isp_name": "TTSL", "site": "ASF Gurugram", "circuit_id": "TT-9", "name": "TTSL 1G", "role": "primary"})
    assert r.status_code == 201, r.text
    cid = r.json()["id"]
    assert (await N.post("/api/wan/circuits", json={"isp_name": "X"})).status_code == 403
    r = await A.post("/api/isp/icmp/targets", json={"name": "TTSL gw", "address": "203.0.113.50", "isp_link_id": cid, "retries": 1,
                                                    "jitter_warn_ms": 40})
    assert r.status_code == 201, r.text
    tid = r.json()["id"]
    t = await db.get(IcmpTarget, tid)
    assert t.retries == 1 and t.jitter_warn_ms == 40
    await run_due(db, clean_ch, T0, pinger=Script(**{"203_0_113_50": [ok()]}))
    for i in range(1, 5):
        await run_due(db, clean_ch, T0 + timedelta(seconds=30 * i), pinger=Script(**{"203_0_113_50": [FAIL, FAIL]}))
    c = (await N.get("/api/wan/circuits")).json()
    assert c["items"][0]["targets"][0]["id"] == tid and c["items"][0]["isp_name"] == "TTSL"
    tg = (await N.get("/api/wan/targets", params={"range": "6h", "q": "ttsl"})).json()
    row = tg["items"][0]
    assert row["state"] == "down" and row["circuit_id"] == "TT-9" and row["site"] == "ASF Gurugram" and tg["totals"]["down"] == 1
    assert row["outages"] == 1 and row["checks"] == 5
    ov = (await N.get("/api/wan/overview", params={"range": "6h"})).json()
    assert ov["totals"]["down"] == 1 and ov["totals"]["open"] == 1 and ov["summary"][0]["isp"] == "TTSL"
    assert ov["collector"]["status"] in ("ok", "degraded")
    incs = (await N.get("/api/wan/incidents", params={"range": "7d"})).json()
    iid = incs["items"][0]["id"]
    assert incs["items"][0]["ongoing"] and incs["items"][0]["status"] == "open"
    # analysts run the incident workflow; closing needs a root cause and a finished outage
    r = await N.c.patch(f"/api/wan/incidents/{iid}", json={"root_cause_category": "made_up"}, headers=N.h)
    assert r.status_code == 422
    r = await N.c.patch(f"/api/wan/incidents/{iid}", json={"status": "closed"}, headers=N.h)
    assert r.status_code == 422
    r = await N.c.patch(f"/api/wan/incidents/{iid}", json={"root_cause_category": "last_mile", "root_cause_detail": "fibre cut", "assignee": "analyst1"}, headers=N.h)
    assert r.status_code == 200 and r.json()["root_cause_category"] == "last_mile" and r.json()["status"] == "in_progress"
    assert (await N.c.patch(f"/api/wan/incidents/{iid}", json={"status": "closed"}, headers=N.h)).status_code == 422   # outage still running
    det = (await N.get(f"/api/wan/incidents/{iid}")).json()
    assert det["outages"][0]["target"] == "TTSL gw" and det["investigation"]["classification"] in ("single_target", "circuit")
    assert any(x["kind"] == "detected" for x in det["timeline"])
    # security incident list stays free of ISP incidents
    assert (await N.get("/api/incidents")).json()["total"] == 0
    # pause / resume are admin actions
    assert (await N.post(f"/api/wan/targets/{tid}/pause", json={"reason": "x"})).status_code == 403
    r = await A.post(f"/api/wan/targets/{tid}/pause", json={"reason": "provider work"})
    assert r.json()["state"] == "paused"
    assert (await A.post(f"/api/wan/targets/{tid}/resume")).json()["state"] == "unknown"
    hist = (await N.get(f"/api/wan/targets/{tid}/history", params={"range": "6h"})).json()
    assert any(p.get("gap") for p in hist["points"]) and hist["outages"] and [x["state"] for x in hist["timeline"]][-1] == "unknown"
    ev = (await N.get("/api/wan/events", params={"range": "6h", "target_id": tid})).json()
    assert {e["to"] for e in ev["items"]} >= {"down", "paused"}
    an = (await N.get("/api/wan/analytics", params={"range": "7d", "tz": "Asia/Kolkata"})).json()
    assert an["totals"]["incidents"] == 1 and an["by_isp"][0]["group"] == "TTSL"
    r = await A.put("/api/wan/settings", json={"correlation": "planet"})
    assert r.status_code == 422
    assert (await N.put("/api/wan/settings", json={"recovery_action": "monitoring"})).status_code == 403
    r = await A.post("/api/wan/maintenance", json={"name": "w", "scope": "site", "scope_value": "", "starts_at": T0.isoformat(),
                                                  "ends_at": (T0 + timedelta(hours=1)).isoformat()})
    assert r.status_code == 422
    csv = await N.get("/api/wan/outages.csv")
    assert csv.status_code == 200 and "TTSL gw" in csv.text


@pytest.mark.asyncio
async def test_target_already_down_before_upgrade_gets_an_outage(db, ch):
    t = mk(1, "203.0.113.1")
    t.state, t.state_since, t.fail_streak = "down", T0 - timedelta(minutes=30), 60
    await _setup(db, ch, [t])
    await run_due(db, ch, T0, pinger=Script(**{"203_0_113_1": [FAIL]}))
    o = (await db.execute(select(WanOutage))).scalars().one()
    assert o.evidence["reconciled"] and wan.aware(o.detected_at) == T0 - timedelta(minutes=30) and o.incident_id
    await run_due(db, ch, T0 + timedelta(seconds=30), pinger=Script(**{"203_0_113_1": [FAIL]}))
    assert len((await db.execute(select(WanOutage))).scalars().all()) == 1


SLOW = ok((200.0, 210.0, 190.0))   # reachable, RTT over the 150 ms threshold


def test_degraded_damping_ignores_single_slow_checks():
    t = mk(1, "203.0.113.1", degrade_after=3, clear_after=2)
    assert evaluate(t, ok(), T0).to_state == "up"
    assert evaluate(t, SLOW, T0 + timedelta(seconds=30)) is None and t.state == "up"      # the production flap: one slow check
    assert evaluate(t, ok(), T0 + timedelta(seconds=60)) is None and t.poor_streak == 0
    evaluate(t, SLOW, T0 + timedelta(seconds=90))
    evaluate(t, FAIL, T0 + timedelta(seconds=120))                                         # a failure does not reset the poor streak
    assert t.state == "up" and t.poor_streak == 1
    assert evaluate(t, SLOW, T0 + timedelta(seconds=150)) is None
    ev = evaluate(t, SLOW, T0 + timedelta(seconds=180))                                     # third poor check in a row
    assert ev.to_state == "degraded" and t.poor_since == T0 + timedelta(seconds=90)
    assert evaluate(t, ok(), T0 + timedelta(seconds=210)) is None and t.state == "degraded"
    assert evaluate(t, ok(), T0 + timedelta(seconds=240)).to_state == "up"


@pytest.mark.asyncio
async def test_degraded_episode_timing_with_damping(db, ch):
    await _setup(db, ch, [mk(1, "203.0.113.1", degrade_after=3, clear_after=2)])
    await _run(db, ch, Script(**{"203_0_113_1": [ok(), SLOW, ok(), SLOW, SLOW, SLOW, ok(), ok()]}), 8)
    o = (await db.execute(select(WanOutage))).scalars().one()
    assert o.kind == "degraded" and o.incident_id is None                                   # degradation opens no incident by default
    assert wan.aware(o.started_at) == T0 + timedelta(seconds=90) and wan.aware(o.detected_at) == T0 + timedelta(seconds=150)
    assert wan.aware(o.recovered_at) == T0 + timedelta(seconds=180) and o.duration_s == 90
    assert [(e.from_state, e.to_state) for e in (await db.execute(select(IcmpEvent).order_by(IcmpEvent.id))).scalars()] == \
        [("unknown", "up"), ("up", "degraded"), ("degraded", "up")]
