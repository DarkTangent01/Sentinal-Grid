"""Wireless RF & frequency monitoring: channel/frequency tables, RF collectors, normalisation (status / quality), events,
analytics (persistence, RF proximity, overlap), alert hysteresis, APIs and site filtering.

Fixtures are LABELLED synthetic MIB-shaped responses (tests/wireless_fixtures.py), not captured controller output."""
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.alerts.engine import ensure_default_rules, run_rules
from app.db.models import Alert, AlertRule, User, WirelessAp, WirelessEvent, WirelessRadio
from app.security import hash_password
from app.wireless import rf as RF
from app.wireless.rf_analytics import analyze

from .test_api import PW, api, login  # noqa: F401
from .test_iac import As
from .test_switches import _CH
from .test_wireless import T0, _groups, _poll, _seed
from .wireless_fixtures import AP1, AP2, c9800


# ------------------------------------------------------------------ frequency tables
def test_channel_to_frequency_per_band_and_special_cases():
    assert RF.channel_freq("2.4", 1) == 2412 and RF.channel_freq("2.4", 13) == 2472 and RF.channel_freq("2.4", 14) == 2484   # ch 14 special
    assert RF.channel_freq("5", 36) == 5180 and RF.channel_freq("5", 165) == 5825 and RF.channel_freq("5", 184) == 4920       # Japan 4.9 GHz
    assert RF.channel_freq("6", 1) == 5955 and RF.channel_freq("6", 2) == 5935 and RF.channel_freq("6", 233) == 7115
    assert RF.channel_freq("2.4", 36) is None and RF.channel_freq("5", 7) is None and RF.channel_freq("6", 3) is None            # invalid for band
    assert RF.channel_freq("5/6", 37) is None and RF.channel_freq("", 36) is None                                               # ambiguous band: unknown
    # bonded center frequencies come from the block, not the primary channel
    assert RF.center_freq("5", 36, 40) == 5190 and RF.center_freq("5", 40, 80) == 5210 and RF.center_freq("5", 64, 160) == 5250
    assert RF.center_freq("5", 149, 80) == 5775 and RF.center_freq("5", 165, 20) == 5825
    assert RF.center_freq("6", 5, 80) == 5985 and RF.center_freq("6", 37, 160) == 6185
    assert RF.center_freq("2.4", 6, 40) is None                                                                                 # bonding direction unknown
    assert RF.is_dfs("5", 52) and RF.is_dfs("5", 144) and not RF.is_dfs("5", 36) and RF.is_dfs("5", 48, 160) and not RF.is_dfs("2.4", 6)
    assert RF.is_dfs("5", 7) is None
    # overlap: 2.4 GHz 6 vs 8 partially overlaps, 1 vs 6 does not; same 80 MHz block fully overlaps
    assert RF.overlap_mhz(RF.span_mhz("2.4", 6, 20), RF.span_mhz("2.4", 8, 20)) > 0
    assert RF.overlap_mhz(RF.span_mhz("2.4", 1, 20), RF.span_mhz("2.4", 6, 20)) == 0
    assert RF.overlap_mhz(RF.span_mhz("5", 36, 80), RF.span_mhz("5", 44, 80)) == 80
    d = RF.describe("5", 100, 40)
    assert d == {"band": "5", "channel": 100, "width_mhz": 40, "channel_valid": True, "frequency_mhz": 5500, "center_channel": 102,
                 "center_frequency_mhz": 5510, "dfs": True}


# ------------------------------------------------------------------ collectors
async def test_rf_collectors_parse_meta_radar_and_neighbors():
    data, report, out = await _groups(c9800(1, rf=True, radar_heard=30), ("wireless_ap", "wireless_radio", "wireless_radio_rf", "wireless_radio_meta",
                                                                            "wireless_rf_neighbors"))
    assert all(r["ok"] for r in report.values()), report
    m = data["wireless_radio_meta"][f"{AP1}/1"]
    assert (m["channel_assignment"], m["power_assignment"], m["country"], m["environment"], m["regdomain_supported"]) == ("automatic", "automatic", "IN", "all", True)
    assert m["power_levels_mw"][3] == 50 and m["radio_mac"] == "00:11:22:33:44:a1" and m["recommended_channel"] == 36
    assert data["wireless_radios"][f"{AP1}/1"]["link_changes"] == 2
    assert data["wireless_radios"][f"{AP2}/0"]["radio_type"] == "3" and data["wireless_radios"][f"{AP2}/0"]["band"] == "2.4"   # XOR band column
    assert "interference_dbm" not in data["wireless_rf"][f"{AP2}/1"]                       # -128 dBm sentinel = not measured
    assert data["wireless_radar"][f"{AP1}/1"] == [{"channel": 52, "last_heard_s": 30}]
    nb = {n["mac"]: n for n in data["wireless_rf_neighbors"][f"{AP1}/1"]}
    assert nb[AP2] == {"mac": AP2, "slot": 1, "rssi_dbm": -60, "channel": 40, "width_mhz": 20}
    for k in ("wireless_radio_country", "wireless_radio_tx_power_dbm", "wireless_radio_neighbor_rssi_dbm", "wireless_radio_radar_detected"):
        assert out.results[k]["result"] == "ok", k


async def test_rf_tables_unsupported_are_missing_not_zero():
    data, report, out = await _groups(c9800(0), ("wireless_ap", "wireless_radio", "wireless_radio_meta", "wireless_rf_neighbors"))
    assert data["wireless_radio_meta"] == {} and data["wireless_rf_neighbors"] == {}
    for k in ("wireless_radio_country", "wireless_radio_tx_power_dbm", "wireless_radio_neighbor_rssi_dbm", "wireless_radio_link_changes"):
        assert out.results[k]["result"] == "missing", k
    assert data["wireless_radios"][f"{AP1}/1"]["link_changes"] is None


# ------------------------------------------------------------------ persistence, normalisation, events
async def test_poll_normalises_rf_telemetry_and_records_rf_events(db):
    wlc, cred = await _seed(db)
    ch = _CH()
    await _poll(db, ch, wlc, cred, c9800(0, rf=True, channel={(AP1, 1): 52}, util_over={(AP2, 1): 150}), 0)
    r = (await db.execute(select(WirelessRadio).join(WirelessAp, WirelessAp.id == WirelessRadio.ap_id).where(WirelessAp.mac == AP1, WirelessRadio.slot == 1))).scalars().one()
    assert (r.channel, r.frequency_mhz, r.center_frequency_mhz, r.dfs) == (52, 5260, 5290, True)
    assert (r.tx_power_level, r.tx_power_dbm, r.country, r.channel_assignment, r.radio_mac) == (3, 17.0, "IN", "automatic", "00:11:22:33:44:a1")
    rows = [x for x in ch.rows["rf_telemetry"] if x["radio_id"] == r.id]
    util = next(x for x in rows if x["metric"] == "channel_util_pct")
    assert util["value"] == 82.0 and util["status"] == "ok" and util["center_mhz"] == 5290 and util["vendor"] == "cisco" and util["site"] == "WH1"
    bad = next(x for x in ch.rows["rf_telemetry"] if x["metric"] == "channel_util_pct" and x["value"] is None)
    assert bad["status"] == "invalid"                                     # 150 % is implausible: recorded invalid, never clamped
    assert next(x for x in rows if x["metric"] == "retry_pct")["status"] == "missing"            # no previous counter sample yet
    assert next(x for x in rows if x["metric"] == "tx_power_dbm")["quality"] == "derived"
    # step 1: radar heard on channel 52 → DFS event; step 2: channel moves to 36 → change with DFS reason
    await _poll(db, ch, wlc, cred, c9800(1, rf=True, channel={(AP1, 1): 52}, radar_heard=30), 1)
    await _poll(db, ch, wlc, cred, c9800(2, rf=True, radar_heard=90), 2)
    evs = {e.kind: e for e in (await db.execute(select(WirelessEvent))).scalars()}
    assert evs["dfs_radar"].data["channel"] == 52 and evs["dfs_radar"].data["mhz"] == 5260
    cc = evs["channel_change"]
    assert (cc.data["old"], cc.data["new"], cc.data["old_mhz"], cc.data["new_mhz"]) == (52, 36, 5260, 5180)
    assert "radar" in cc.data["reason"] and cc.data["reason_confidence"] == "high"
    await db.refresh(r)
    assert r.neighbors[0]["ap_name"] == "WH1-AP-02" and r.neighbors[0]["rssi_dbm"] == -60


# ------------------------------------------------------------------ analytics
async def _two_polls(db, **kw):
    wlc, cred = await _seed(db)
    ch = _CH()
    for i in range(2):
        await _poll(db, ch, wlc, cred, c9800(i, **kw), i)
    return wlc


async def test_cochannel_needs_rf_proximity_overlap_and_impact(db):
    await _two_polls(db, rf=True, util_over={(AP1, 0): 75})
    f = await analyze(db, None, now=T0 + timedelta(minutes=2))
    co = [x for x in f["findings"] if x["rule"] == "cochannel_interference"]
    # AP1 5 GHz ch 36/80 and AP2 ch 40/80 share one 80 MHz block: co-channel although the channel numbers differ
    assert len(co) == 1 and co[0]["ap"] == "WH1-AP-01" and co[0]["slot"] == 1 and co[0]["confidence"] == "high"
    assert co[0]["neighbors"][0]["overlap_mhz"] == 80 and co[0]["frequency_mhz"] == 5180 and co[0]["center_frequency_mhz"] == 5210
    adj = [x for x in f["findings"] if x["rule"] == "adjacent_channel_interference"]
    assert len(adj) == 1 and adj[0]["slot"] == 0 and adj[0]["neighbors"][0]["channel"] == 8          # 6 vs 8 at -65 dBm
    assert not any(x["rule"] == "cochannel_interference" and x["slot"] == 0 for x in f["findings"])    # same-channel AP2 heard only at -82 dBm
    for x in f["findings"]:
        assert x["evidence"] and x["confidence"] in ("high", "medium", "low") and x["possible_causes"] and x["steps"]


async def test_same_channel_without_neighbor_data_is_not_interference(db):
    await _two_polls(db, channel={(AP2, 1): 36})                           # both on 36, no RRM neighbour table
    f = await analyze(db, None, now=T0 + timedelta(minutes=2))
    assert not any(x["rule"] in ("cochannel_interference", "adjacent_channel_interference") for x in f["findings"])
    assert f["coverage"]["radios_without_neighbor_data"] == 4
    hu = next(x for x in f["findings"] if x["rule"] == "high_channel_utilization")
    assert hu["confidence"] == "low" and "persistence not established" in hu["evidence"][1]   # no rf_telemetry history passed


async def test_persistence_and_history_from_rf_telemetry(db, ch):
    ch.command("TRUNCATE TABLE rf_telemetry")
    await _two_polls(db)
    r = (await db.execute(select(WirelessRadio).join(WirelessAp, WirelessAp.id == WirelessRadio.ap_id).where(WirelessAp.mac == AP1, WirelessRadio.slot == 1))).scalars().one()
    now = datetime.now(timezone.utc)
    rows = [{"ts": now - timedelta(minutes=m), "site": "WH1", "wlc_id": r.wlc_id, "ap_id": r.ap_id, "radio_id": r.id, "slot": 1, "vendor": "cisco",
             "band": "5", "channel": 36, "center_mhz": 5210, "width_mhz": 80, "metric": "channel_util_pct", "value": v, "unit": "%", "source": "t",
             "status": "ok", "quality": "measured"} for m, v in ((14, 85.0), (10, 88.0), (6, 90.0), (2, 86.0))]
    rows += [{**rows[0], "ts": now - timedelta(days=2), "value": 40.0}]
    rows += [{**rows[0], "ts": now - timedelta(minutes=1), "value": None, "status": "missing"}]           # gaps never count as 0
    ch.insert("rf_telemetry", rows, list(rows[0]))
    f = await analyze(db, ch, now=now)
    hu = next(x for x in f["findings"] if x["rule"] == "high_channel_utilization" and x["radio_id"] == r.id)
    assert hu["confidence"] == "high" and hu["persistence"]["bad"] == 4 and hu["persistence"]["samples"] == 4
    assert hu["history"]["avg_7d"] == 40.0 and hu["duration_s"] >= 14 * 60 - 5


# ------------------------------------------------------------------ alerts
async def test_utilization_alert_hysteresis_and_channel_change_rule(db, ch):
    ch.command("TRUNCATE TABLE wireless_metrics")
    wlc, cred = await _seed(db)
    fake = _CH()
    await _poll(db, fake, wlc, cred, c9800(0), 0)
    ap1 = (await db.execute(select(WirelessAp).where(WirelessAp.mac == AP1))).scalars().one()
    await ensure_default_rules(db)
    for r in (await db.execute(select(AlertRule))).scalars():
        r.enabled = r.key in ("wireless_channel_utilization", "wireless_channel_changes")
    await db.commit()

    def put(now, vals):
        rows = [{"ts": now - timedelta(minutes=12 - 3 * i), "wlc_id": wlc.id, "ap_id": ap1.id, "slot": 1, "wlan_id": 0, "band": "5",
                 "metric": "wireless_radio_channel_utilization_percent", "value": v, "source": "t"} for i, v in enumerate(vals)]
        ch.command("TRUNCATE TABLE wireless_metrics")
        ch.insert("wireless_metrics", rows, list(rows[0]))
    now = datetime.now(timezone.utc).replace(microsecond=0)
    put(now, [85, 86, 88, 90])
    await run_rules(ch, db, now=now, correlate=False)
    a = (await db.execute(select(Alert).where(Alert.rule_key == "wireless_channel_utilization"))).scalars().one()
    assert a.status == "new"
    put(now + timedelta(minutes=5), [76, 75, 74, 75])                       # below 80 but above the clear level 70: stays open
    await run_rules(ch, db, now=now + timedelta(minutes=5), correlate=False)
    await db.refresh(a)
    assert a.status == "new"
    put(now + timedelta(minutes=10), [66, 65, 64, 62])                      # below 70: recovers
    await run_rules(ch, db, now=now + timedelta(minutes=10), correlate=False)
    await db.refresh(a)
    assert a.status == "resolved"
    for i in range(4):
        db.add(WirelessEvent(wlc_id=wlc.id, ap_id=ap1.id, at=now - timedelta(hours=i), kind="channel_change", component="WH1-AP-01/1",
                             detail="x", data={"old": 36, "new": 40, "reason": "assigned by RRM / DCA"}))
    await db.commit()
    await run_rules(ch, db, now=now, correlate=False)
    cc = (await db.execute(select(Alert).where(Alert.rule_key == "wireless_channel_changes"))).scalars().one()
    assert "4 channel changes" in cc.explanation and "RRM" in cc.explanation


# ------------------------------------------------------------------ APIs
async def test_rf_api_views_rbac_and_site_filter(api, db, ch):  # noqa: F811
    ch.command("TRUNCATE TABLE rf_telemetry")
    wlc, cred = await _seed(db)
    for i in range(2):
        await _poll(db, ch, wlc, cred, c9800(i, rf=True, radar_heard=30), i)
    ap2 = (await db.execute(select(WirelessAp).where(WirelessAp.mac == AP2))).scalars().one()
    ap2.site = "FC2"
    db.add(User(username="gridonly", password_hash=hash_password(PW), role="analyst", products=["grid"]))
    await db.commit()
    an, grid = await As.login(api, "analyst1"), await As.login(api, "gridonly")
    assert (await grid.get("/api/wireless/rf/overview")).status_code == 403
    o = (await an.get("/api/wireless/rf/overview")).json()
    assert o["cards"]["monitored_aps"] == 2 and o["cards"]["radios"] == 4 and o["cards"]["operational_radios"] == 4
    assert o["cards"]["avg_channel_util_pct"] == round((36 + 82 + 37 + 20) / 4, 1) and o["cards"]["high_util_radios"] == 1
    d = (await an.get("/api/wireless/rf/distribution")).json()
    assert d["bands"] == ["2.4", "5"]                                       # no 6 GHz radios → no 6 GHz section
    assert {(c["band"], c["channel"], c["frequency_mhz"], c["radios"]) for c in d["channels"]} == {("2.4", 6, 2437, 2), ("5", 36, 5180, 1), ("5", 40, 5200, 1)}
    assert {(w["band"], w["width_mhz"], w["radios"]) for w in d["widths"]} == {("2.4", 20, 2), ("5", 80, 2)}
    site = (await an.get("/api/wireless/rf/radios", params={"site": "FC2"})).json()["items"]
    assert {x["ap"] for x in site} == {"WH1-AP-02"}                         # site filter excludes other sites' radios
    fx = (await an.get("/api/wireless/rf/findings", params={"site": "FC2"})).json()
    assert all(f["site"] == "FC2" for f in fx["findings"])
    h = (await an.get("/api/wireless/rf/heatmap", params={"range": "7d"})).json()          # fixture polls are timestamped at T0
    assert len(h["rows"]) == 4 and h["cells"] and all(c["value"] is None or 0 <= c["value"] <= 100 for c in h["cells"])
    rid = next(x["id"] for x in (await an.get("/api/wireless/rf/radios")).json()["items"] if x["ap"] == "WH1-AP-01" and x["slot"] == 1)
    det = (await an.get(f"/api/wireless/rf/radios/{rid}")).json()
    assert det["frequency"]["center_frequency_mhz"] == 5210 and det["radio"]["tx_power_dbm"] == 17.0 and det["neighbors"][0]["ap_name"] == "WH1-AP-02"
    assert det["radar"][0]["channel"] == 52 and det["thresholds"]["channel_util_pct"] == 80
    hist = (await an.get(f"/api/wireless/rf/radios/{rid}/history", params={"range": "7d"})).json()
    assert hist["series"]["channel_util_pct"][-1]["v"] == 82.0 and hist["series"]["retry_pct"]
    ev = (await an.get("/api/wireless/rf/events", params={"hours": 720})).json()
    assert "dfs_radar" in ev["kinds"]
    cap = (await an.get("/api/wireless/rf/capabilities")).json()
    assert cap["models"][0]["supported"]["tx_power_dbm"] and cap["controllers"][0]["metrics"]["wireless_radio_country"]["status"] == "ok"
    ref = {c["channel"]: c for c in (await an.get("/api/wireless/rf/channels", params={"band": "5", "width": 80})).json()["channels"]}
    assert ref[36]["center_frequency_mhz"] == 5210 and ref[32]["center_frequency_mhz"] is None and ref[100]["dfs"] is True
    assert (await an.get("/api/wireless/rf/radios/999999")).status_code == 404
    assert (await an.get("/api/wireless/rf/findings", params={"engine": "ai"})).status_code == 422
