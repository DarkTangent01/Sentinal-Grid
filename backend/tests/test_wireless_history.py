"""Wireless client history and daily / per-AP analytics (app/wireless/history.py, app/wireless/client_analytics.py).

Every scenario goes through the real persistence path (store.persist with a controller client table, as the poller
produces it), the real ClickHouse tables (embedded) and the real rollup, so the numbers checked are the ones the API
returns. Client tables here are synthetic, MIB-shaped rows (no captured controller data)."""
from datetime import date, datetime, timedelta, timezone
from datetime import time as dtime

import pytest
from sqlalchemy import select

from app.db.models import Switch, SwitchCredential, WirelessAp, WirelessClient, WirelessClientSession
from app.switches import poller as P
from app.wireless import client_analytics as A
from app.wireless import history as H
from app.wireless.store import persist

from .test_api import api  # noqa: F401  (fixture)

IST = "Asia/Kolkata"
def _recent_tuesday() -> date:
    """A Tuesday 4–13 days ago, so the fixtures stay inside the 14-day TTL of wireless_client_samples (a fixed date
    expired once it was two weeks old), preferring one whose Monday–Thursday lie in one month (week / month periods)."""
    import calendar
    today = datetime.now(timezone.utc).date()
    tues = [today - timedelta(days=k) for k in range(4, 14) if (today - timedelta(days=k)).weekday() == 1]
    good = [d for d in tues if d.day >= 2 and d.day + 2 <= calendar.monthrange(d.year, d.month)[1]]
    return (good or tues)[0]


DAY = _recent_tuesday()
T10 = datetime.combine(DAY, dtime(4, 30), tzinfo=timezone.utc)    # 10:00 IST
A1, A2, A3 = "00:aa:00:00:00:01", "00:aa:00:00:00:02", "00:bb:00:00:00:03"
C = [f"00:cc:00:00:00:0{i}" for i in range(10)]


@pytest.fixture
def wch(ch):
    for t in ("wireless_client_samples", "wireless_client_events", "wireless_client_slots"):
        ch.command(f"TRUNCATE TABLE {t}")
    return ch


async def _setup(db, n_wlc=1):
    cred = SwitchCredential(name="ro", version="v3", username="ro", auth_protocol="sha", priv_protocol="aes128",
                            secret_ciphertext=P.seal_secret({"auth_key": "a" * 12, "priv_key": "b" * 12}))
    db.add(cred)
    await db.flush()
    wlcs = []
    for i, site in enumerate(["WH1", "WH2"][:n_wlc]):
        w = Switch(name=f"WLC-{site}", address=f"192.0.2.{20 + i}", credential_id=cred.id, site=site, role="wlc", vendor="cisco",
                   capabilities={}, group_state={}, health={}, thresholds={})
        db.add(w)
        wlcs.append(w)
    await db.flush()
    for w, macs in zip(wlcs, [(A1, A2), (A3,)]):
        for n, m in enumerate(macs, start=1):
            db.add(WirelessAp(wlc_id=w.id, mac=m, name=f"{w.site}-AP-0{n}", site=w.site, state="up", present=True, counters={}))
    await db.commit()
    return wlcs


def _row(ap, ssid="CORP", band="5", up=None, vlan=40):
    return {"ap_mac": ap, "ssid": ssid, "band": band, "session_s": up, "vlan": vlan, "ip": "10.40.0.9", "sources": ["CISCO-LWAPP-DOT11-CLIENT-MIB"]}


async def _poll(db, ch, w, now, clients: dict, ok=True, truncated=False):
    data = {"wireless_clients": clients, "wireless_client_table_ok": ok, "wireless_client_truncated": truncated}
    await persist(db, ch, w, data, {"wireless_client"}, now, P.intervals_of(w), dict(w.health or {}))
    await db.commit()


async def _scope(db, ch, start=DAY, end=DAY, tz=IST, **kw):
    t0, t1, days, note = A.window(start, end, tz)
    ids = [w.id for w in (await db.execute(select(Switch))).scalars()]
    aps = {a.id: a for a in (await db.execute(select(WirelessAp))).scalars()}
    return A.Scope(tz=tz, t0=t0, t1=t1, wlc_ids=kw.pop("wlc_ids", ids), days=days, tz_note=note, **kw), aps


async def test_sessions_roams_reconnects_and_daily_counts(db, wch):
    """Scenarios 1–4, 6, 9, 10: several clients on one SSID, a client reconnecting, roaming, changing band, changing
    SSID, an AP broadcasting two SSIDs, a disconnect only seen as absence, and a duplicate poll."""
    (w,) = await _setup(db)
    m = lambda i: T10 + timedelta(minutes=5 * i)  # noqa: E731
    up = lambda i, since=0: (i - since) * 300 + 120  # noqa: E731   seconds associated at poll i (associated 2 min before poll `since`)
    # poll 0..2: C0 + C1 on CORP / AP1, C2 on GUEST / AP1 (AP1 broadcasts both), C3 on CORP / AP2
    for i in range(3):
        await _poll(db, wch, w, m(i), {C[0]: _row(A1, up=up(i)), C[1]: _row(A1, up=up(i)), C[2]: _row(A1, "GUEST", "2.4", up(i)),
                                     C[3]: _row(A2, up=up(i))})
    await _poll(db, wch, w, m(2), {C[0]: _row(A1, up=up(2)), C[1]: _row(A1, up=up(2)), C[2]: _row(A1, "GUEST", "2.4", up(2)),
                                   C[3]: _row(A2, up=up(2))})            # the same poll stored twice: nothing changes
    # poll 3: C0 roams to AP2 (association timer kept); C1 reconnected between polls (timer restarted, same AP);
    #         C2 moved to CORP (a new association); C3 changed band on its AP
    await _poll(db, wch, w, m(3), {C[0]: _row(A2, up=up(3)), C[1]: _row(A1, up=30), C[2]: _row(A1, "CORP", "5", 40),
                                   C[3]: _row(A2, band="2.4", up=up(3))})
    # poll 4: C1 gone (left; no disconnect event from the controller), the others stay
    await _poll(db, wch, w, m(4), {C[0]: _row(A2, up=up(4)), C[2]: _row(A1, "CORP", "5", 340), C[3]: _row(A2, band="2.4", up=up(4))})
    sess = (await db.execute(select(WirelessClientSession).order_by(WirelessClientSession.id))).scalars().all()
    by = {}
    for x in sess:
        by.setdefault(x.mac, []).append(x)
    assert len(by[C[0]]) == 1 and by[C[0]][0].roams == 1 and by[C[0]][0].start_source == "controller"      # roam ≠ new session
    assert by[C[0]][0].started_at.replace(tzinfo=timezone.utc) == m(0) - timedelta(seconds=120)          # controller's association time
    assert [x.end_reason for x in by[C[1]]] == ["reconnected", "not_listed"]                              # 2 sessions, both closed
    assert by[C[1]][1].ended_at.replace(tzinfo=timezone.utc) == m(3)                                       # last poll that listed it
    assert [x.end_reason for x in by[C[2]]] == ["ssid_change", ""] and by[C[2]][1].ssid == "CORP"
    assert len(by[C[3]]) == 1 and by[C[3]][0].band_changes == 1
    await H.aggregate(wch, now=m(5))
    sc, aps = await _scope(db, wch)
    daily = {r["ssid"]: r for r in (await A.daily_ssid(wch, sc))["items"]}
    assert daily["CORP"]["unique_clients"] == 4                  # C0, C1, C3 + C2 after its move: each MAC once
    assert daily["GUEST"]["unique_clients"] == 1
    assert daily["CORP"]["sessions"] == 5                        # C0, C1 ×2, C3, C2's CORP association
    assert daily["GUEST"]["sessions"] == 1
    assert daily["CORP"]["peak_clients"] == 4 and daily["GUEST"]["peak_clients"] == 1     # poll 3: C0, C1, C2, C3
    # concurrency per 5-minute bucket, averaged over the 5 buckets read: CORP 3,3,3,4,3 → 3.2 (the duplicate poll counts once)
    assert daily["CORP"]["avg_clients"] == 3.2 and daily["CORP"]["polled_buckets"] == 5
    ap = {(r["ap_name"], r["ssid"]): r for r in (await A.daily_ap(wch, sc, aps))["items"]}
    assert ap[("WH1-AP-01", "GUEST")]["unique_clients"] == 1 and ap[("WH1-AP-01", "CORP")]["unique_clients"] == 3
    assert ap[("WH1-AP-02", "CORP")]["unique_clients"] == 2      # C3 throughout, C0 after its roam
    assert ap[("WH1-AP-02", "CORP")]["sessions"] == 2            # C3's association + C0 roaming onto it
    rk = await A.rankings(wch, sc, aps)
    assert rk["aps"]["roams"][0]["roams"] == 1 and {r["ap_name"] for r in rk["aps"]["roams"]} == {"WH1-AP-01", "WH1-AP-02"}
    assert {r["ap_name"]: r["disconnects"] for r in rk["aps"]["disconnects"]}["WH1-AP-01"] == 3   # C1 twice, C2 (GUEST → CORP)
    ev = await A.client_events(wch, sc, C[0])
    assert [e["kind"] for e in ev] == ["roam", "connect"]
    dist = {r["ap_name"]: r for r in (await A.ap_distribution(wch, sc, aps))["items"]}
    assert dist["WH1-AP-02"]["clients_5"] == 2 and dist["WH1-AP-02"]["clients_24"] == 1 and dist["WH1-AP-02"]["unique_clients"] == 2


async def test_controller_restart_gaps_sites_timezone_and_expiry(db, wch):
    """Scenarios 5, 6, 7, 8: two controllers on two sites, a controller restart, a collection gap, an incomplete table
    and a client that is never seen again; day boundaries in the user's timezone."""
    w1, w2 = await _setup(db, 2)
    t = datetime.combine(DAY, dtime(18, 15), tzinfo=timezone.utc)  # 23:45 IST on DAY
    await _poll(db, wch, w1, t, {C[0]: _row(A1, up=600), C[1]: _row(A1, up=600)})
    await _poll(db, wch, w2, t, {C[5]: _row(A3, up=600)})
    # 23:50 IST: the controller restarted; every client associated again (timers restart, same AP)
    await _poll(db, wch, w1, t + timedelta(minutes=5), {C[0]: _row(A1, up=60), C[1]: _row(A1, up=60)})
    # 00:00–00:45 IST on the 11th: no polls (collection gap), then C0 only, and an incomplete table (nothing is closed)
    await _poll(db, wch, w1, t + timedelta(minutes=60), {C[0]: _row(A1, up=3300)})
    await _poll(db, wch, w1, t + timedelta(minutes=65), {}, ok=False)
    s1 = (await db.execute(select(WirelessClientSession).where(WirelessClientSession.mac == C[0]))).scalars().all()
    assert sorted(x.end_reason for x in s1) == ["", "reconnected"]          # restart → a new association, the old one closed
    c1 = (await db.execute(select(WirelessClientSession).where(WirelessClientSession.mac == C[1]))).scalars().all()
    assert sorted(x.end_reason for x in c1) == ["not_listed", "reconnected"]   # absent from the complete 00:45 table: closed
    c0 = (await db.execute(select(WirelessClientSession).where(WirelessClientSession.mac == C[0], WirelessClientSession.ended_at.is_(None))))
    assert c0.scalars().one() is not None          # the incomplete 00:50 table closes nothing
    await H.aggregate(wch, now=t + timedelta(minutes=70))
    sc10, aps = await _scope(db, wch)
    d10 = {r["ssid"]: r for r in (await A.daily_ssid(wch, sc10))["items"]}
    assert d10["CORP"]["unique_clients"] == 3 and d10["CORP"]["sessions"] >= 4          # restart adds sessions, never clients
    sc11, _ = await _scope(db, wch, DAY + timedelta(days=1), DAY + timedelta(days=1))
    d11 = {r["ssid"]: r for r in (await A.daily_ssid(wch, sc11))["items"]}
    assert d11["CORP"]["unique_clients"] == 1                                            # 00:45 IST on the 11th is the next day
    cov = await A.coverage(wch, sc11)
    assert cov == {(DAY + timedelta(days=1)).isoformat(): 1}                                                       # one 5-minute reading: a gap, not zeros
    assert d11["CORP"]["avg_clients"] == 1.0
    # in UTC the same readings are one day
    scu, _ = await _scope(db, wch, tz="UTC")
    assert {r["ssid"]: r["unique_clients"] for r in (await A.daily_ssid(wch, scu))["items"]}["CORP"] == 3
    # site filter: WH2 only
    wh2 = [i for i, a in aps.items() if a.site == "WH2"]
    sc2, _ = await _scope(db, wch, ap_ids=wh2)
    assert [(r["ssid"], r["unique_clients"]) for r in (await A.daily_ssid(wch, sc2))["items"]] == [("CORP", 1)]
    # a client never listed again by a complete table is closed after a day without being listed
    n = await H.expire(db, now=t + timedelta(days=2))
    await db.commit()
    assert n >= 2 and not (await db.execute(select(WirelessClientSession).where(WirelessClientSession.ended_at.is_(None)))).scalars().all()
    assert all(c.session_id is None for c in (await db.execute(select(WirelessClient))).scalars())


async def test_hourly_profile_and_rollup_is_idempotent(db, wch):
    (w,) = await _setup(db)
    for i in range(12):                       # 10:00–10:55 IST: 2 clients, a third from 10:30
        clients = {C[0]: _row(A1, up=600 + i * 300), C[1]: _row(A2, up=600 + i * 300)}
        if i >= 6:
            clients[C[2]] = _row(A2, "GUEST", up=60 + (i - 6) * 300)
        await _poll(db, wch, w, T10 + timedelta(minutes=5 * i), clients)
    await H.aggregate(wch, now=T10 + timedelta(minutes=60))
    await H.aggregate(wch, now=T10 + timedelta(minutes=60))       # rebuilding the same slots changes nothing
    sc, aps = await _scope(db, wch)
    h = await A.hourly(wch, sc, group="none")
    (pt,) = h["series"][0]["points"]
    assert (pt["unique_clients"], pt["peak_clients"], pt["min_clients"], pt["avg_clients"], pt["polled_buckets"]) == (3, 3, 2, 2.5, 12)
    assert h["peak_hour"] == 10 and h["profile"][0]["hour"] == 10                         # the hour in IST, not UTC (04)
    rk = await A.rankings(wch, sc, aps)
    top = rk["aps"]["peak_clients"][0]
    assert (top["ap_name"], top["peak_clients"], top["avg_clients"]) == ("WH1-AP-02", 2, 1.5)
    page = await A.daily_ap(wch, sc, aps, sort="unique_clients", order="desc", page=1, size=1)
    assert page["total"] == 3 and len(page["items"]) == 1


def test_window_respects_the_timezone_and_limits():
    t0, t1, days, note = A.window(DAY, DAY, IST)
    assert t0 == datetime.combine(DAY - timedelta(days=1), dtime(18, 30), tzinfo=timezone.utc) and t1 - t0 == timedelta(days=1) \
        and days == [DAY.isoformat()] and not note
    assert A.window(DAY, DAY, "Asia/Kathmandu")[3]                 # quarter-hour zone: rounding is stated
    with pytest.raises(ValueError):
        A.window(DAY, DAY - timedelta(days=1), "UTC")
    with pytest.raises(ValueError):
        A.check_tz("UTC'; DROP TABLE x")


async def test_analytics_api_filters_csv_history_and_access(api, db, wch):
    from app.db.models import User
    from app.security import hash_password
    from .test_api import PW
    from .test_iac import As
    w1, w2 = await _setup(db, 2)
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0) - timedelta(minutes=30)
    for i in range(3):
        await _poll(db, wch, w1, now + timedelta(minutes=5 * i), {C[0]: _row(A1, up=600 + 300 * i), C[1]: _row(A2, "GUEST", "2.4", 300 + 300 * i)})
        await _poll(db, wch, w2, now + timedelta(minutes=5 * i), {C[5]: _row(A3, up=900 + 300 * i)})
    await H.aggregate(wch, now=now + timedelta(minutes=15))
    db.add(User(username="gridonly", password_hash=hash_password(PW), role="analyst", products=["grid"]))
    await db.commit()
    N = await As.login(api, "analyst1")
    G = await As.login(api, "gridonly")
    assert (await G.get("/api/wireless/analytics/ssid/daily")).status_code == 403          # NMS product only
    f = (await N.get("/api/wireless/analytics/filters")).json()
    assert f["ssids"] == ["CORP", "GUEST"] and {c["name"] for c in f["controllers"]} == {"WLC-WH1", "WLC-WH2"} and f["sites"] == ["WH1", "WH2"]
    d = (await N.get("/api/wireless/analytics/ssid/daily")).json()
    assert {(r["ssid"], r["unique_clients"]) for r in d["items"]} == {("CORP", 2), ("GUEST", 1)} and d["timezone"] == "UTC"
    assert sum(d["coverage"].values()) == 3
    d = (await N.get("/api/wireless/analytics/ssid/daily", params={"site": "WH2"})).json()
    assert [(r["ssid"], r["unique_clients"]) for r in d["items"]] == [("CORP", 1)]
    d = (await N.get("/api/wireless/analytics/ssid/daily", params={"frequency_band": "2.4"})).json()
    assert [(r["ssid"], r["unique_clients"]) for r in d["items"]] == [("GUEST", 1)]
    d = (await N.get("/api/wireless/analytics/ap/daily", params={"ap_name": "WH1-AP-01", "sort": "unique_clients"})).json()
    assert [(r["ap_name"], r["ssid"], r["unique_clients"]) for r in d["items"]] == [("WH1-AP-01", "CORP", 1)]
    csv_ = await N.get("/api/wireless/analytics/ap/daily", params={"format": "csv"})
    assert csv_.headers["content-type"].startswith("text/csv") and csv_.text.splitlines()[0].startswith("day,ap_name,ap_mac,ssid")
    assert len(csv_.text.strip().splitlines()) == 4
    for path in ("hourly", "rankings", "ap/distribution", "roaming"):
        assert (await N.get(f"/api/wireless/analytics/{path}")).status_code == 200, path
    h = (await N.get(f"/api/wireless/analytics/clients/{C[0].upper()}/history")).json()
    assert h["total"] == 1 and h["sessions"][0]["open"] and h["sessions"][0]["start_source"] == "controller" and h["events"][0]["kind"] == "connect"
    assert (await N.get("/api/wireless/analytics/clients/not-a-mac/history")).status_code == 422
    assert (await N.get("/api/wireless/analytics/ssid/daily", params={"start_date": "2026-01-10", "end_date": "2026-01-01"})).status_code == 422
    assert (await N.get("/api/wireless/analytics/ssid/daily", params={"sort": "evil; DROP"})).status_code == 422


async def test_weekly_and_monthly_periods_count_each_client_once(db, wch):
    (w,) = await _setup(db)
    for d in range(3):                         # the same 2 clients on 3 consecutive days (Tue–Thu, one ISO week)
        t = T10 + timedelta(days=d)
        await _poll(db, wch, w, t, {C[0]: _row(A1, up=60), C[1]: _row(A1, up=60)})
        await _poll(db, wch, w, t + timedelta(hours=1), {})            # both leave: a new session each day
    await H.aggregate(wch, now=T10 + timedelta(days=3))
    sc, _ = await _scope(db, wch, DAY, DAY + timedelta(days=2))
    days = (await A.daily_ssid(wch, sc))["items"]
    assert sorted((r["day"], r["unique_clients"], r["sessions"]) for r in days) == [
        ((DAY + timedelta(days=i)).isoformat(), 2, 2) for i in range(3)]
    for period, start in (("week", (DAY - timedelta(days=1)).isoformat()), ("month", DAY.replace(day=1).isoformat())):
        (r,) = (await A.daily_ssid(wch, sc, period=period))["items"]
        assert (r["day"], r["unique_clients"], r["sessions"], r["peak_clients"]) == (start, 2, 6, 2)
        assert list((await A.coverage(wch, sc, period)).values()) == [3]


async def test_hourly_profile_is_the_total_not_a_mix_of_series(db, wch):
    (w,) = await _setup(db)
    for i in range(12):                       # CORP: 2 clients all hour; GUEST: 1 client in the first half only
        clients = {C[0]: _row(A1, up=600 + i * 300), C[1]: _row(A2, up=600 + i * 300)}
        if i < 6:
            clients[C[2]] = _row(A2, "GUEST", up=60 + i * 300)
        await _poll(db, wch, w, T10 + timedelta(minutes=5 * i), clients)
    await H.aggregate(wch, now=T10 + timedelta(minutes=60))
    sc, _ = await _scope(db, wch)
    h = await A.hourly(wch, sc, group="ssid")
    assert {s["key"]: s["points"][0]["min_clients"] for s in h["series"]} == {"CORP": 2, "GUEST": 0}
    (p,) = h["profile"]
    assert (p["min_clients"], p["peak_clients"], p["avg_clients"]) == (2, 3, 2.5)        # all clients together
