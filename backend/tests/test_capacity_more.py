"""Capacity forecasts added for PoE budgets, AP client load and SSID load (nms/analytics.py capacity())."""
from datetime import datetime, timedelta, timezone

import pytest

from app.db.models import Switch, WirelessAp, WirelessWlan
from app.nms import analytics as A

from .test_anomaly import _fill


@pytest.fixture
def cch(ch):
    for t in ("wireless_client_slots", "switch_metrics_hourly"):
        ch.command(f"TRUNCATE TABLE {t}")
    return ch


async def test_poe_ap_and_ssid_load_forecasts(db, cch):
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    sw = Switch(name="ACC1", address="192.0.2.1", monitoring="active", state="up", capabilities={}, group_state={}, health={}, thresholds={})
    wlc = Switch(name="WLC", address="192.0.2.9", role="wlc", vendor="cisco", monitoring="active", state="up", capabilities={}, group_state={},
                 health={}, thresholds={"wireless": {"ap_clients_max": 40}})
    db.add_all([sw, wlc])
    await db.flush()
    ap = WirelessAp(wlc_id=wlc.id, mac="00:aa:00:00:00:01", name="AP-BUSY", site="HQ", state="up", present=True, counters={})
    quiet = WirelessAp(wlc_id=wlc.id, mac="00:aa:00:00:00:02", name="AP-QUIET", site="HQ", state="up", present=True, counters={})
    db.add_all([ap, quiet, WirelessWlan(wlc_id=wlc.id, wlan_id=1, ssid="CORP", max_clients=100, present=True)])
    await db.commit()
    rows = []
    for d in range(14):
        h = now - timedelta(days=13 - d)
        rows += [{"hour": h, "switch_id": sw.id, "metric": "switch_poe_budget_watts", "component": "unit 1", "samples": 1, "total": 370.0, "vmin": 370.0, "vmax": 370.0},
                 {"hour": h, "switch_id": sw.id, "metric": "switch_poe_power_watts", "component": "unit 1", "samples": 1, "total": 220.0 + 8 * d,
                  "vmin": 0.0, "vmax": 0.0}]
        slot = datetime.fromtimestamp(int(h.timestamp()) // 1800 * 1800, tz=timezone.utc)
        _fill(cch, slot, {("CORP", ap.id): 20 + d, ("CORP", quiet.id): 3}, wlc_id=wlc.id)
    cch.insert("switch_metrics_hourly", rows, ["hour", "switch_id", "metric", "component", "samples", "total", "vmin", "vmax"])
    res = await A.capacity(db, cch, days=30, threshold_if=80, threshold_dev=90)
    (poe,) = res["poe_forecast"]
    assert poe["component"] == "unit 1" and poe["slope_per_day"] == pytest.approx(100 * 8 / 370, abs=0.01) and 0 < poe["days_left"] < 30
    assert [x["ap"] for x in res["ap_load"]] == ["AP-BUSY"]                  # the quiet AP is far from its limit: not listed
    busy = res["ap_load"][0]
    assert busy["threshold"] == 40 and busy["current"] == 33 and busy["slope_per_day"] == pytest.approx(1.0) and 0 < busy["days_left"] < 10
    (ssid,) = res["ssid_load"]
    assert ssid["ssid"] == "CORP" and ssid["threshold"] == 100 and ssid["current"] == 36
    assert res["summary"]["poe_at_risk_30d"] == 1 and res["summary"]["aps_at_risk_30d"] == 1
