"""Seasonal anomaly rules (app/nms/anomaly.py) on real ClickHouse rollups (embedded), synthetic weeks."""
from datetime import datetime, timedelta, timezone

import pytest

from app.db.models import Switch, SwitchInterface, WirelessAp
from app.nms import anomaly as N
from app.wireless import client_analytics as A

NOW = datetime(2026, 11, 13, 11, 20, tzinfo=timezone.utc)          # last finished slot: 10:30–11:00 UTC
SLOT = N.last_slot(NOW)


@pytest.fixture
def wch(ch):
    for t in ("wireless_client_samples", "wireless_client_slots", "switch_if_hourly"):
        ch.command(f"TRUNCATE TABLE {t}")
    return ch


def _fill(ch, slot: datetime, counts: dict, wlc_id=1):
    """Rollup rows for one 30-minute slot: counts {(ssid, ap_id): clients} at each of its six 5-minute readings.
    Written straight into wireless_client_slots: the raw snapshots expire after 14 days, the rollup keeps 400."""
    if not counts:
        counts = {("OTHER", 99): 1}
    for (ssid, ap), c in counts.items():
        if c == 0:
            continue
        buckets = [int((slot + timedelta(minutes=5 * r)).timestamp()) for r in range(6)]
        macs = [f"m{ssid}{ap}{i}" for i in range(c)]
        ch.command("INSERT INTO wireless_client_slots (slot, wlc_id, ssid, ap_id, band, clients, conc, version) "
                   "SELECT toDateTime({s:UInt32}, 'UTC'), {w:UInt32}, {ss:String}, {ap:UInt32}, '5', uniqExactArrayState({m:Array(String)}), "
                   "sumMapState(arrayMap(x -> toDateTime(x, 'UTC'), {b:Array(UInt32)}), arrayMap(x -> toUInt64({n:UInt32}), {b:Array(UInt32)})), 1 "
                   "FROM system.one", {"s": int(slot.timestamp()), "w": wlc_id, "ss": ssid, "ap": ap, "m": macs, "b": buckets, "n": c})


def test_band_is_robust_to_one_outlier():
    med, low, high = N.band([30, 31, 29, 0], k=4, floor_abs=5)       # one holiday week at 0
    assert med == 29.5 and low < 10 < 29.5 < high


async def test_ssid_drop_is_detected_after_learning_but_not_a_normal_week(db, wch):
    for w in range(1, 5):
        _fill(wch, SLOT - timedelta(days=7 * w), {("CORP", 1): 30} if w != 3 else {("OTHER", 99): 1})   # week 3: a holiday, read but no CORP client
    _fill(wch, SLOT, {("CORP", 1): 5, ("GUEST", 1): 2})
    p = N.DEFAULT_RULES[0]["params"]
    (d,) = await N.rule_wireless_ssid_clients_anomaly(wch, NOW, p)
    assert d.evidence["ssid"] == "CORP" and d.evidence["observed"] == 5 and d.evidence["expected"] == 30 and d.evidence["weeks"] == 4
    assert d.group_key == "CORP:below"
    # same history, a normal week: nothing
    wch.command("TRUNCATE TABLE wireless_client_slots")
    for w in range(1, 5):
        _fill(wch, SLOT - timedelta(days=7 * w), {("CORP", 1): 30} if w != 3 else {("OTHER", 99): 1})
    _fill(wch, SLOT, {("CORP", 1): 28})
    assert await N.rule_wireless_ssid_clients_anomaly(wch, NOW, p) == []


async def test_learning_period_and_missing_readings(db, wch):
    for w in (1, 2):                                       # only two weeks of history: learning
        _fill(wch, SLOT - timedelta(days=7 * w), {("CORP", 1): 30})
    _fill(wch, SLOT, {("CORP", 1): 1})
    assert await N.rule_wireless_ssid_clients_anomaly(wch, NOW, N.DEFAULT_RULES[0]["params"]) == []
    # no reading at all in the current slot: a collection gap, not an outage
    assert await N.rule_wireless_ssid_clients_anomaly(wch, NOW + timedelta(hours=2), N.DEFAULT_RULES[0]["params"]) == []


async def test_quiet_ap_at_a_busy_time(db, wch):
    w = Switch(name="WLC", address="192.0.2.9", role="wlc", vendor="cisco", state="up", capabilities={}, group_state={}, health={}, thresholds={})
    db.add(w)
    await db.flush()
    a1 = WirelessAp(wlc_id=w.id, mac="00:aa:00:00:00:01", name="AP-1", site="HQ", state="up", present=True, counters={})
    a2 = WirelessAp(wlc_id=w.id, mac="00:aa:00:00:00:02", name="AP-2", site="HQ", state="up", present=True, counters={})
    db.add_all([a1, a2])
    await db.commit()
    for wk in range(1, 5):
        _fill(wch, SLOT - timedelta(days=7 * wk), {("CORP", a1.id): 8, ("CORP", a2.id): 6}, wlc_id=w.id)
    _fill(wch, SLOT, {("CORP", a2.id): 7}, wlc_id=w.id)        # AP-1 silent, the controller's table was read
    (d,) = await N.rule_wireless_ap_zero_clients(wch, NOW, N.DEFAULT_RULES[1]["params"])
    assert d.evidence["ap"] == "AP-1" and d.evidence["expected"] == 8
    a1.state = "down"                                          # a down AP is the AP-down rule's job, not this one
    await db.commit()
    assert await N.rule_wireless_ap_zero_clients(wch, NOW, N.DEFAULT_RULES[1]["params"]) == []


async def test_interface_utilisation_spike(db, wch):
    sw = Switch(name="ACC1", address="192.0.2.1", monitoring="active", state="up", capabilities={}, group_state={}, health={}, thresholds={})
    db.add(sw)
    await db.flush()
    db.add(SwitchInterface(switch_id=sw.id, ifindex=7, name="Gi1/0/7", present=True))
    await db.commit()
    hour = datetime.fromtimestamp(int(NOW.timestamp()) // 3600 * 3600 - 3600, tz=timezone.utc)
    cols = ["hour", "switch_id", "ifindex", "samples", "rated", "rx_util_max", "tx_util_max"]
    rows = [{"hour": hour - timedelta(days=7 * w), "switch_id": sw.id, "ifindex": 7, "samples": 12, "rated": 12, "rx_util_max": 20.0 + w,
             "tx_util_max": 5.0} for w in range(1, 5)]
    rows.append({"hour": hour, "switch_id": sw.id, "ifindex": 7, "samples": 12, "rated": 12, "rx_util_max": 92.0, "tx_util_max": 10.0})
    wch.insert("switch_if_hourly", rows, cols)
    (d,) = await N.rule_switch_if_util_anomaly(wch, NOW, N.DEFAULT_RULES[2]["params"])
    assert d.evidence["component"] == "Gi1/0/7" and d.evidence["observed"] == 92.0 and d.evidence["expected"] == 22.5


async def test_hourly_chart_carries_the_expected_band(db, wch):
    for w in range(1, 4):
        _fill(wch, SLOT - timedelta(days=7 * w), {("CORP", 1): 30})
    _fill(wch, SLOT, {("CORP", 1): 5})
    t0, t1, days, note = A.window(SLOT.date(), SLOT.date(), "UTC")
    sc = A.Scope(tz="UTC", t0=t0, t1=t1, wlc_ids=[1], days=days)
    h = await A.hourly(wch, sc, group="none", expected_weeks=4)
    (pt,) = h["series"][0]["points"]
    assert pt["avg_clients"] == 5 and pt["expected"] == 30 and pt["expected_low"] > 5
