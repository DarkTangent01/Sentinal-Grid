"""APIs: Wireless Analysis (Sentinel NMS). Read-only monitoring of Cisco WLCs (docs/WIRELESS.md).

Controllers are monitored devices (`switches` rows with role "wlc"): onboarding, credentials, connectivity tests
(`POST /api/switches/test` with `wlc: true` runs the wireless capability scan) and polling settings use the existing
switch monitoring APIs. Nothing here changes a controller, AP, radio, WLAN or client. Client usernames are returned to
administrators only.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.ch import ClickHouse
from ..db.models import Switch, User, WirelessAp, WirelessClient, WirelessEvent, WirelessRadio, WirelessWlan
from ..db.pg import get_session
from ..switches.service import capability_view
from ..wireless import service as W
from ..wireless.oids import OBJ
from .deps import audit, ch_dep, current_user, require_admin

router = APIRouter(prefix="/api/wireless", tags=["wireless"])
RANGES = {"1h": 1, "6h": 6, "24h": 24, "7d": 168, "30d": 720}


def _now():
    return datetime.now(timezone.utc)


def _page(rows: list, page: int, size: int) -> dict:
    return {"items": rows[(page - 1) * size: page * size], "total": len(rows), "page": page, "size": size}


def _sort(rows: list[dict], key: str | None, desc: bool) -> list[dict]:
    if not key:
        return rows
    have = [r for r in rows if r.get(key) is not None]
    miss = [r for r in rows if r.get(key) is None]  # unknown values last, never ranked as 0
    have.sort(key=lambda r: r[key].lower() if isinstance(r[key], str) else r[key], reverse=desc)
    return have + miss


@router.get("/meta")
async def meta(user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    wlcs = await W.controllers(s)
    aps = (await s.execute(select(WirelessAp.site).distinct())).scalars().all()
    ssids = (await s.execute(select(WirelessWlan.ssid).where(WirelessWlan.present.is_(True)).distinct())).scalars().all()
    return {"controllers": [{"id": w.id, "name": w.name} for w in wlcs], "sites": sorted({x for x in aps if x} | {w.site for w in wlcs if w.site}),
            "ssids": sorted({x for x in ssids if x}), "bands": ["2.4", "5", "6", "5/6"], "is_admin": user.role == "admin",
            "scenarios": W.SCENARIOS, "thresholds": W.DEFAULTS, "score_weights": W.SCORE_WEIGHTS}


@router.get("/overview")
async def overview(wlc_id: list[int] = Query(default=[]), site: str | None = None, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    return await W.overview(s, wlc_ids=wlc_id or None, site=site)


@router.get("/controllers")
async def controllers(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    now = _now()
    return {"items": [W.wlc_out(w, now) for w in await W.controllers(s)]}


@router.get("/controllers/{wid}")
async def controller(wid: int, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    w = await s.get(Switch, wid)
    if not w or (w.role or "").lower() != "wlc":
        raise HTTPException(404, "controller not found")
    cap = capability_view(w)
    cap["metrics"] = [m for m in cap["metrics"] if m["group"].startswith("wireless_") or m["group"] in ("system", "cpu_memory", "interfaces")]
    cap["groups"] = [g for g in cap["groups"] if g["group"].startswith("wireless_") or g["group"] in ("system", "cpu_memory", "interfaces")]
    return {"controller": W.wlc_out(w, _now()), "capabilities": cap}


@router.get("/oids")
async def oids(_: User = Depends(current_user)):
    """The OID registry: every object the module may request, with its MIB, syntax, unit and metric."""
    return {"items": [{"object": n, **o} for n, o in OBJ.items()]}


# ------------------------------------------------------------------ APs
@router.get("/aps")
async def aps(wlc_id: list[int] = Query(default=[]), site: str | None = None, state: list[str] = Query(default=[]), q: str | None = Query(None, max_length=128),
              model: str | None = None, sort: str | None = Query(None, max_length=32), desc: bool = False, page: int = Query(1, ge=1),
              size: int = Query(100, ge=1, le=1000), _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    wlcs, ids, apmap, radios = await W.load(s, wlc_id or None, site)
    rows = []
    rad_by = {}
    for r in radios:
        rad_by.setdefault(r.ap_id, []).append(r)
    alerts = await _active_alert_counts(s, "ap_id")
    for a in apmap.values():
        if not a.present and a.state != "down":
            continue
        d = W.ap_out(a, wlcs.get(a.wlc_id))
        rs = rad_by.get(a.id, [])
        d.update(radios_up=sum(1 for r in rs if r.state == "up"), radios_total=len(rs), bands=sorted({r.band for r in rs if r.band}),
                 max_util=max((r.channel_util_pct for r in rs if r.channel_util_pct is not None), default=None), alerts=alerts.get(a.id, 0))
        rows.append(d)
    if state:
        rows = [r for r in rows if r["state"] in state]
    if model:
        rows = [r for r in rows if r["model"] == model]
    if q:
        ql = q.lower()
        rows = [r for r in rows if any(ql in str(r.get(k) or "").lower() for k in ("name", "mac", "ip", "model", "serial", "site", "location"))]
    order = {"down": 0, "degraded": 1, "unknown": 2, "maintenance": 3, "up": 4}
    rows = _sort(rows, sort, desc) if sort else sorted(rows, key=lambda r: (order.get(r["state"], 5), r["name"].lower()))
    states = {k: sum(1 for r in rows if r["state"] == k) for k in order}
    return {**_page(rows, page, size), "states": states, "models": sorted({r["model"] for r in rows if r["model"]})}


async def _active_alert_counts(s: AsyncSession, key: str) -> dict[int, int]:
    from ..db.models import Alert
    out: dict[int, int] = {}
    for a in (await s.execute(select(Alert).where(Alert.rule_key.like("wireless_%"), Alert.status.in_(["new", "investigating"])))).scalars():
        v = (a.evidence or {}).get(key)
        if isinstance(v, int):
            out[v] = out.get(v, 0) + 1
    return out


@router.get("/aps/{aid}")
async def ap_detail(aid: int, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    a = await s.get(WirelessAp, aid)
    if not a:
        raise HTTPException(404, "AP not found")
    wlc = await s.get(Switch, a.wlc_id)
    t = W.thresholds(wlc)
    radios = list((await s.execute(select(WirelessRadio).where(WirelessRadio.ap_id == aid).order_by(WirelessRadio.slot))).scalars())
    rmap = {r.slot: r for r in radios}
    clients = list((await s.execute(select(WirelessClient).where(WirelessClient.ap_id == aid, WirelessClient.present.is_(True)))).scalars())
    evs = list((await s.execute(select(WirelessEvent).where(WirelessEvent.ap_id == aid).order_by(WirelessEvent.at.desc()).limit(200))).scalars())
    from ..db.models import Alert
    alerts = [{"id": x.id, "name": x.name, "severity": x.severity, "last_seen": W._iso(x.last_seen)} for x in
              (await s.execute(select(Alert).where(Alert.rule_key.like("wireless_%"), Alert.status.in_(["new", "investigating"])))).scalars()
              if (x.evidence or {}).get("ap_id") == aid]
    return {"ap": W.ap_out(a, wlc), "controller": W.wlc_out(wlc, _now()) if wlc else None, "thresholds": t,
            "radios": [W.radio_out(r, a, t) for r in radios],
            "clients": [W.client_out(c, a, rmap.get(c.slot), t, user.role == "admin") for c in clients],
            "events": [W.event_out(e, {a.id: a}) for e in evs], "alerts": alerts, "switch_port": await W.switch_port(s, a)}


def _window(range_: str) -> tuple[datetime, datetime, int]:
    h = RANGES.get(range_, 24)
    t1 = _now()
    t0 = t1 - timedelta(hours=h)
    bucket = 60 if h <= 1 else 300 if h <= 6 else 900 if h <= 24 else 3600 if h <= 168 else 10800
    return t0, t1, bucket


async def _series(ch: ClickHouse, where: str, p: dict, t0, t1, bucket: int, by_slot=False) -> list[dict]:
    grp = "slot, " if by_slot else ""
    rows = await ch.aquery(f"SELECT toStartOfInterval(ts, INTERVAL {int(bucket)} SECOND) AS t, {grp}metric, avg(value) AS v FROM wireless_metrics "
                           f"WHERE {where} AND ts >= {{t0:DateTime64(3)}} AND ts < {{t1:DateTime64(3)}} GROUP BY t, {grp}metric ORDER BY t",
                           {**p, "t0": t0, "t1": t1})
    out: dict = {}
    for r in rows:
        k = (str(r["t"]), r.get("slot", -1))
        d = out.setdefault(k, {"t": W._iso(r["t"] if isinstance(r["t"], datetime) else datetime.fromisoformat(str(r["t"]))), "slot": r.get("slot")})
        v = r["v"]
        d[r["metric"]] = None if v != v else round(float(v), 2)
    return list(out.values())


@router.get("/aps/{aid}/history")
async def ap_history(aid: int, range: str = Query("24h", pattern=r"^(1h|6h|24h|7d|30d)$"), _: User = Depends(current_user),
                     s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    a = await s.get(WirelessAp, aid)
    if not a:
        raise HTTPException(404, "AP not found")
    t0, t1, b = _window(range)
    ap = await _series(ch, "wlc_id = {w:UInt32} AND ap_id = {a:UInt32} AND slot = -1", {"w": a.wlc_id, "a": aid}, t0, t1, b)
    radio = await _series(ch, "wlc_id = {w:UInt32} AND ap_id = {a:UInt32} AND slot >= 0", {"w": a.wlc_id, "a": aid}, t0, t1, b, by_slot=True)
    return {"bucket_seconds": b, "ap": ap, "radios": radio}


# ------------------------------------------------------------------ radios / RF
@router.get("/radios")
async def radios(wlc_id: list[int] = Query(default=[]), site: str | None = None, band: str | None = None, flag: str | None = None,
                 q: str | None = Query(None, max_length=128), sort: str | None = Query("rf_score", max_length=32), desc: bool = True,
                 page: int = Query(1, ge=1), size: int = Query(100, ge=1, le=1000), _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    wlcs, ids, apmap, rs = await W.load(s, wlc_id or None, site)
    rows = [W.radio_out(r, apmap.get(r.ap_id), W.thresholds(wlcs[r.wlc_id])) for r in rs if r.present]
    if band:
        rows = [r for r in rows if r["band"] == band]
    if flag:
        rows = [r for r in rows if flag in r["flags"]]
    if q:
        rows = [r for r in rows if q.lower() in (r["ap"] or "").lower()]
    return _page(_sort(rows, sort, desc), page, size)


@router.get("/rf")
async def rf(wlc_id: list[int] = Query(default=[]), site: str | None = None, band: str | None = None, range: str = Query("24h", pattern=r"^(1h|6h|24h|7d|30d)$"),
             _: User = Depends(current_user), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    """Channel distribution, utilisation heatmap (AP radio × time), RF health by band and site, congestion ranking and
    channel-change history."""
    wlcs, ids, apmap, rs = await W.load(s, wlc_id or None, site)
    rs = [r for r in rs if r.present and (not band or r.band == band)]
    chan = {}
    for r in rs:
        if r.channel is not None:
            k = (r.band or "?", r.channel)
            chan[k] = chan.get(k, 0) + 1
    t0, t1, b = _window(range)
    heat = []
    if ids:
        rows = await ch.aquery(f"SELECT ap_id, slot, toStartOfInterval(ts, INTERVAL {b} SECOND) AS t, avg(value) AS v FROM wireless_metrics "
                               "WHERE wlc_id IN {w:Array(UInt32)} AND metric = 'wireless_radio_channel_utilization_percent' "
                               "AND ts >= {t0:DateTime64(3)} AND ts < {t1:DateTime64(3)} GROUP BY ap_id, slot, t ORDER BY t",
                               {"w": ids, "t0": t0, "t1": t1})
        keep = {(r.ap_id, r.slot) for r in rs}
        for r in rows:
            if (int(r["ap_id"]), int(r["slot"])) in keep:
                heat.append({"ap_id": int(r["ap_id"]), "slot": int(r["slot"]), "t": W._iso(r["t"] if isinstance(r["t"], datetime) else datetime.fromisoformat(str(r["t"]))),
                             "util": round(float(r["v"]), 1)})
    by_site: dict[str, dict] = {}
    for r in rs:
        ap = apmap.get(r.ap_id)
        d = by_site.setdefault((ap.site if ap else "") or "(no site)", {"radios": 0, "problem": 0, "util": []})
        d["radios"] += 1
        sc = W.rf_problem_score(r, W.thresholds(wlcs[r.wlc_id]))
        d["problem"] += bool(sc and sc >= 1)
        if r.channel_util_pct is not None:
            d["util"].append(r.channel_util_pct)
    changes = list((await s.execute(select(WirelessEvent).where(WirelessEvent.kind == "channel_change", WirelessEvent.at >= t0,
                                                                WirelessEvent.wlc_id.in_(ids or [0])).order_by(WirelessEvent.at.desc()).limit(300))).scalars())
    ranked = sorted([W.radio_out(r, apmap.get(r.ap_id), W.thresholds(wlcs[r.wlc_id])) for r in rs], key=lambda x: -(x["rf_score"] or -1))
    return {"channels": [{"band": k[0], "channel": k[1], "radios": v} for k, v in sorted(chan.items(), key=lambda x: (x[0][0], x[0][1]))],
            "heatmap": heat, "bucket_seconds": b, "radios": ranked[:300],
            "aps": {r.ap_id: apmap[r.ap_id].name for r in rs if r.ap_id in apmap},
            "by_site": [{"site": k, "radios": v["radios"], "problem_radios": v["problem"],
                         "avg_util": round(sum(v["util"]) / len(v["util"]), 1) if v["util"] else None} for k, v in sorted(by_site.items())],
            "channel_changes": [W.event_out(e, apmap) for e in changes]}


@router.get("/radios/{rid}/history")
async def radio_history(rid: int, range: str = Query("24h", pattern=r"^(1h|6h|24h|7d|30d)$"), _: User = Depends(current_user),
                        s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    r = await s.get(WirelessRadio, rid)
    if not r:
        raise HTTPException(404, "radio not found")
    t0, t1, b = _window(range)
    return {"bucket_seconds": b, "points": await _series(ch, "wlc_id = {w:UInt32} AND ap_id = {a:UInt32} AND slot = {sl:Int16}",
                                                         {"w": r.wlc_id, "a": r.ap_id, "sl": r.slot}, t0, t1, b)}


# ------------------------------------------------------------------ clients
@router.get("/clients")
async def clients(wlc_id: list[int] = Query(default=[]), site: str | None = None, ssid: str | None = None, band: str | None = None, ap_id: int | None = None,
                  q: str | None = Query(None, max_length=128), problem: str | None = Query(None, pattern=r"^(poor_rssi|low_snr|low_rate|disconnects|roaming|poor_score)$"),
                  include_gone: bool = False, sort: str | None = Query(None, max_length=32), desc: bool = False, page: int = Query(1, ge=1),
                  size: int = Query(100, ge=1, le=1000), user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    wlcs, ids, apmap, rs = await W.load(s, wlc_id or None, site)
    qy = select(WirelessClient).where(WirelessClient.wlc_id.in_(ids or [0]))
    if not include_gone:
        qy = qy.where(WirelessClient.present.is_(True))
    for col, v in ((WirelessClient.ssid, ssid), (WirelessClient.band, band), (WirelessClient.ap_id, ap_id)):
        if v:
            qy = qy.where(col == v)
    if q:
        like = f"%{q.lower()}%"
        conds = [WirelessClient.mac.like(like), WirelessClient.ip.like(like)]
        if user.role == "admin":
            conds.append(func.lower(WirelessClient.username).like(like))
        qy = qy.where(or_(*conds))
    cl = list((await s.execute(qy.limit(50_000))).scalars())
    rmap = {(r.ap_id, r.slot): r for r in rs}
    rows = []
    for c in cl:
        if site and c.ap_id not in apmap:
            continue
        t = W.thresholds(wlcs[c.wlc_id])
        d = W.client_out(c, apmap.get(c.ap_id), rmap.get((c.ap_id, c.slot)), t, user.role == "admin")
        d["score"] = d["experience"]["score"]
        rows.append(d)
    if problem:
        t = W.DEFAULTS
        test = {"poor_rssi": lambda r: r["rssi_dbm"] is not None and r["rssi_dbm"] <= t["rssi_poor_dbm"],
                "low_snr": lambda r: r["snr_db"] is not None and r["snr_db"] <= t["snr_poor_db"],
                "low_rate": lambda r: r["tx_rate_mbps"] is not None and r["tx_rate_mbps"] <= t["rate_poor_mbps"],
                "disconnects": lambda r: (r["disconnects"] or 0) >= 3, "roaming": lambda r: (r["roams"] or 0) >= 10,
                "poor_score": lambda r: r["score"] is not None and r["score"] < 50}[problem]
        rows = [r for r in rows if test(r)]
    rows = _sort(rows, sort, desc) if sort else sorted(rows, key=lambda r: (r["score"] if r["score"] is not None else 101))
    measured = [r for r in rows if r["score"] is not None]
    return {**_page(rows, page, size), "summary": {"clients": len(rows), "scored": len(measured),
                                                    "avg_score": round(sum(r["score"] for r in measured) / len(measured), 1) if measured else None}}


@router.get("/clients/{mac}")
async def client(mac: str, range: str = Query("24h", pattern=r"^(1h|6h|24h|7d)$"), user: User = Depends(current_user),
                 s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    mac = mac.lower()
    c = (await s.execute(select(WirelessClient).where(WirelessClient.mac == mac).order_by(WirelessClient.last_seen.desc()))).scalars().first()
    if not c:
        raise HTTPException(404, "client not found")
    wlc = await s.get(Switch, c.wlc_id)
    ap = await s.get(WirelessAp, c.ap_id) if c.ap_id else None
    radio = (await s.execute(select(WirelessRadio).where(WirelessRadio.ap_id == c.ap_id, WirelessRadio.slot == c.slot))).scalars().first() if c.ap_id else None
    t0, t1, b = _window(range)
    samples = await ch.aquery(f"SELECT toStartOfInterval(ts, INTERVAL {b} SECOND) AS t, avg(rssi_dbm) AS o_rssi, avg(snr_db) AS o_snr, "
                              "avg(tx_rate_mbps) AS o_rate, any(ap_id) AS o_ap FROM wireless_client_samples WHERE wlc_id = {w:UInt32} AND mac = {m:String} "
                              "AND ts >= {t0:DateTime64(3)} GROUP BY t ORDER BY t", {"w": c.wlc_id, "m": mac, "t0": t0})
    pts = [{"t": W._iso(r["t"] if isinstance(r["t"], datetime) else datetime.fromisoformat(str(r["t"]))),
            **{k: (None if r["o_" + k] is None or r["o_" + k] != r["o_" + k] else round(float(r["o_" + k]), 1)) for k in ("rssi", "snr", "rate")},
            "ap_id": int(r["o_ap"])} for r in samples]
    aps = {a.id: a for a in (await s.execute(select(WirelessAp).where(WirelessAp.wlc_id == c.wlc_id))).scalars()}
    evs = list((await s.execute(select(WirelessEvent).where(WirelessEvent.client_mac == mac).order_by(WirelessEvent.at.desc()).limit(300))).scalars())
    return {"client": W.client_out(c, ap, radio, W.thresholds(wlc), user.role == "admin"), "controller": wlc.name if wlc else None,
            "radio": W.radio_out(radio, ap, W.thresholds(wlc)) if radio else None, "history": pts, "bucket_seconds": b,
            "events": [W.event_out(e, aps) for e in evs], "roaming": await W.roaming(s, wlc_ids=[c.wlc_id], hours=24, mac=mac)}


# ------------------------------------------------------------------ WLANs
@router.get("/wlans")
async def wlans(wlc_id: list[int] = Query(default=[]), range: str = Query("24h", pattern=r"^(1h|6h|24h|7d|30d)$"), _: User = Depends(current_user),
                s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    wlcs = {w.id: w for w in await W.controllers(s)}
    ids = [i for i in (wlc_id or list(wlcs)) if i in wlcs]
    ws = list((await s.execute(select(WirelessWlan).where(WirelessWlan.wlc_id.in_(ids or [0])).order_by(WirelessWlan.wlan_id))).scalars())
    cl = list((await s.execute(select(WirelessClient).where(WirelessClient.wlc_id.in_(ids or [0]), WirelessClient.present.is_(True)))).scalars())
    aps = {a.id: a.name for a in (await s.execute(select(WirelessAp).where(WirelessAp.wlc_id.in_(ids or [0])))).scalars()}
    rows = []
    for w in ws:
        mine = [c for c in cl if c.wlc_id == w.wlc_id and c.ssid == w.ssid]
        bands: dict[str, int] = {}
        for c in mine:
            bands[c.band or "unknown"] = bands.get(c.band or "unknown", 0) + 1
        top_aps: dict[str, int] = {}
        for c in mine:
            if c.ap_id in aps:
                top_aps[aps[c.ap_id]] = top_aps.get(aps[c.ap_id], 0) + 1
        rssi = [c.rssi_dbm for c in mine if c.rssi_dbm is not None]
        rows.append({"id": w.id, "wlc_id": w.wlc_id, "wlc": wlcs[w.wlc_id].name, "wlan_id": w.wlan_id, "profile": w.profile, "ssid": w.ssid,
                     "enabled": w.enabled, "security": w.security, "max_clients": w.max_clients, "clients": w.clients, "clients_seen": len(mine),
                     "aps": w.aps, "radios": w.radios, "present": w.present, "bands": bands, "top_aps": sorted(top_aps.items(), key=lambda x: -x[1])[:5],
                     "avg_rssi_dbm": round(sum(rssi) / len(rssi), 1) if rssi else None,
                     "rx_bytes": sum(c.rx_bytes or 0 for c in mine) if any(c.rx_bytes is not None for c in mine) else None,
                     "tx_bytes": sum(c.tx_bytes or 0 for c in mine) if any(c.tx_bytes is not None for c in mine) else None})
    t0, t1, b = _window(range)
    trend = await ch.aquery(f"SELECT toStartOfInterval(ts, INTERVAL {b} SECOND) AS t, wlan_id, avg(value) AS v FROM wireless_metrics "
                            "WHERE wlc_id IN {w:Array(UInt32)} AND metric = 'wireless_wlan_client_count' AND ts >= {t0:DateTime64(3)} GROUP BY t, wlan_id ORDER BY t",
                            {"w": ids or [0], "t0": t0}) if ids else []
    return {"items": rows, "bucket_seconds": b,
            "trend": [{"t": W._iso(r["t"] if isinstance(r["t"], datetime) else datetime.fromisoformat(str(r["t"]))), "wlan_id": int(r["wlan_id"]),
                       "clients": round(float(r["v"]), 1)} for r in trend],
            "note": "Traffic is the sum of the controller's per-client byte counters (Counter64) for current clients, not RF airtime or wired bandwidth."}


# ------------------------------------------------------------------ roaming, events, troubleshooting, health
@router.get("/roaming")
async def roaming(wlc_id: list[int] = Query(default=[]), hours: int = Query(24, ge=1, le=168), _: User = Depends(current_user),
                  s: AsyncSession = Depends(get_session)):
    return await W.roaming(s, wlc_ids=wlc_id or None, hours=hours)


@router.get("/events")
async def events(wlc_id: list[int] = Query(default=[]), kind: list[str] = Query(default=[]), ap_id: int | None = None, client_mac: str | None = None,
                 hours: int = Query(24, ge=1, le=720), page: int = Query(1, ge=1), size: int = Query(100, ge=1, le=500),
                 _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    q = select(WirelessEvent).where(WirelessEvent.at >= _now() - timedelta(hours=hours))
    if wlc_id:
        q = q.where(WirelessEvent.wlc_id.in_(wlc_id))
    if kind:
        q = q.where(WirelessEvent.kind.in_(kind))
    if ap_id:
        q = q.where(WirelessEvent.ap_id == ap_id)
    if client_mac:
        q = q.where(WirelessEvent.client_mac == client_mac.lower())
    total = (await s.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
    rows = list((await s.execute(q.order_by(WirelessEvent.at.desc()).offset((page - 1) * size).limit(size))).scalars())
    aps = {a.id: a for a in (await s.execute(select(WirelessAp).where(WirelessAp.id.in_({e.ap_id for e in rows if e.ap_id} or {0})))).scalars()}
    kinds = dict((await s.execute(select(WirelessEvent.kind, func.count()).where(WirelessEvent.at >= _now() - timedelta(hours=hours))
                                  .group_by(WirelessEvent.kind))).all())
    return {"items": [W.event_out(e, aps) for e in rows], "total": total, "page": page, "size": size, "kinds": kinds}


class TroubleshootIn(BaseModel):
    scenario: str = Field(pattern=r"^(poor_performance|ap_offline|client_cannot_connect|frequent_disconnects|high_load)$")
    ap_id: int | None = None
    mac: str | None = Field(None, pattern=r"^[0-9a-fA-F:.-]{12,17}$")
    ssid: str | None = Field(None, max_length=64)


@router.post("/troubleshoot")
async def troubleshoot(body: TroubleshootIn, request: Request, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    """Read-only analysis (POST only because it takes a structured body; nothing on any device changes)."""
    try:
        mac = body.mac.lower().replace("-", ":") if body.mac else None
        r = await W.troubleshoot(s, body.scenario, ap_id=body.ap_id, mac=mac, ssid=body.ssid)
    except ValueError as e:
        raise HTTPException(422, str(e))
    await audit(s, request, user.username, "wireless_troubleshoot", body.scenario, {"ap_id": body.ap_id, "ssid": body.ssid})
    return r


@router.get("/health")
async def health(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    now = _now()
    out = []
    for w in await W.controllers(s):
        cap = capability_view(w, now)
        out.append({"controller": W.wlc_out(w, now), "metrics": [m for m in cap["metrics"] if m["group"].startswith("wireless_")],
                    "groups": [g for g in cap["groups"] if g["group"].startswith("wireless_")]})
    return {"items": out}


class ThresholdsIn(BaseModel):
    thresholds: dict = Field(default_factory=dict)


@router.put("/controllers/{wid}/thresholds")
async def set_thresholds(wid: int, body: ThresholdsIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    """Per-controller (≈ per-site) overrides of the wireless thresholds; channel utilisation per band."""
    w = await s.get(Switch, wid)
    if not w or (w.role or "").lower() != "wlc":
        raise HTTPException(404, "controller not found")
    clean = {}
    for k, v in body.thresholds.items():
        if k == "channel_util_pct" and isinstance(v, dict):
            clean[k] = {str(b): float(x) for b, x in v.items() if str(b) in ("2.4", "5", "6", "5/6", "") and 1 <= float(x) <= 100}
        elif k in W.DEFAULTS and k != "channel_util_pct" and isinstance(v, (int, float)):
            clean[k] = float(v)
        else:
            raise HTTPException(422, f"unknown or invalid threshold: {k}")
    w.thresholds = {**(w.thresholds or {}), "wireless": clean}
    await s.commit()
    await audit(s, request, user.username, "wireless_thresholds", w.name, clean)
    return {"ok": True, "thresholds": W.thresholds(w)}
