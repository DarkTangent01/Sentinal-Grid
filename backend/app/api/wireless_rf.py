"""APIs: Wireless → RF & Frequency Monitoring (Sentinel NMS). Read-only; docs/WIRELESS.md (RF section).

Everything here is built from controller telemetry already collected by the switch poller (wireless_radio,
wireless_radio_rf, wireless_radio_meta, wireless_rf_neighbors groups) and the rf_telemetry history. A value the controller
did not report is returned as null with its collection status; it is never shown as zero. Nothing here changes a channel,
transmit power, RF profile or any controller setting.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.ch import ClickHouse
from ..db.models import Alert, Switch, User, WirelessAp, WirelessClient, WirelessEvent, WirelessRadio
from ..db.pg import get_session
from ..wireless import rf as RF
from ..wireless import service as W
from ..wireless.rf_analytics import RCA_PROVIDERS, RULES, analyze
from ..wireless.oids import OBJ
from .deps import ch_dep, current_user

router = APIRouter(prefix="/api/wireless/rf", tags=["wireless-rf"])
RANGES = {"1h": (1, 60), "6h": (6, 300), "24h": (24, 900), "7d": (168, 3600), "30d": (720, 14400)}
RF_EVENT_KINDS = ("channel_change", "dfs_radar", "radio_up", "radio_down", "radio_disabled", "tx_power_change", "radio_link_change")
RF_ALERT_RULES = ("wireless_channel_utilization", "wireless_interference", "wireless_noise_high", "wireless_retry_high", "wireless_low_snr",
                  "wireless_radio_down", "wireless_channel_changes")
RF_METRICS = ("channel_util_pct", "tx_util_pct", "rx_util_pct", "noise_dbm", "interference_pct", "interference_dbm", "clients", "retry_pct",
              "tx_power_level", "tx_power_dbm", "poor_snr_clients", "channel", "radio_up", "link_changes")


def _now():
    return datetime.now(timezone.utc)


async def _scope(s: AsyncSession, wlc_id: list[int], site: str | None, ap_id: int | None = None, radio_id: int | None = None,
                 band: str | None = None):
    wlcs, ids, apmap, rs = await W.load(s, wlc_id or None, site)
    rs = [r for r in rs if r.present and (not band or r.band == band) and (not ap_id or r.ap_id == ap_id) and (not radio_id or r.id == radio_id)]
    return wlcs, ids, apmap, rs


@router.get("/overview")
async def overview(wlc_id: list[int] = Query(default=[]), site: str | None = Query(None, max_length=128), band: str | None = Query(None, max_length=8),
                   _: User = Depends(current_user), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    wlcs, ids, apmap, rs = await _scope(s, wlc_id, site, band=band)
    measured = [r.channel_util_pct for r in rs if r.channel_util_pct is not None]
    high = [r for r in rs if r.channel_util_pct is not None and r.channel_util_pct >= W.util_limit(W.thresholds(wlcs[r.wlc_id]), r.band)]
    fnd = await analyze(s, ch, site=site, wlc_ids=wlc_id or None, band=band)
    poor = {f["radio_id"] for f in fnd["findings"] if f["rule"] != "uneven_client_distribution"}
    by_band: dict[str, dict] = {}
    for r in rs:
        d = by_band.setdefault(r.band or "?", {"radios": 0, "up": 0, "util": []})
        d["radios"] += 1
        d["up"] += r.state == "up"
        if r.channel_util_pct is not None:
            d["util"].append(r.channel_util_pct)
    return {"cards": {"monitored_aps": len({r.ap_id for r in rs}), "radios": len(rs), "operational_radios": sum(1 for r in rs if r.state == "up"),
                      "offline_radios": sum(1 for r in rs if r.state == "down"), "disabled_radios": sum(1 for r in rs if r.state == "disabled"),
                      "unknown_radios": sum(1 for r in rs if r.state == "unknown"),
                      "avg_channel_util_pct": round(sum(measured) / len(measured), 1) if measured else None, "util_measured_radios": len(measured),
                      "high_util_radios": len(high), "poor_rf_radios": len(poor), "dfs_radios": sum(1 for r in rs if r.dfs)},
            "by_band": [{"band": k, "radios": v["radios"], "up": v["up"], "avg_util": round(sum(v["util"]) / len(v["util"]), 1) if v["util"] else None}
                        for k, v in sorted(by_band.items())],
            "findings": fnd["counts"], "coverage": fnd["coverage"],
            "collection": {"util": len(measured), "noise": sum(1 for r in rs if r.noise_dbm is not None),
                           "neighbors": sum(1 for r in rs if r.neighbors), "tx_power_dbm": sum(1 for r in rs if r.tx_power_dbm is not None),
                           "country": sum(1 for r in rs if r.country)}}


@router.get("/distribution")
async def distribution(wlc_id: list[int] = Query(default=[]), site: str | None = Query(None, max_length=128), _: User = Depends(current_user),
                       s: AsyncSession = Depends(get_session)):
    """AP radios per channel (with frequency), channel widths, and frequency use per site. 6 GHz appears only when radios on 6 GHz exist."""
    wlcs, ids, apmap, rs = await _scope(s, wlc_id, site)
    chans: dict[tuple, dict] = {}
    widths: dict[tuple, int] = {}
    sites: dict[tuple, int] = {}
    unknown = 0
    for r in rs:
        if r.channel is None or r.band not in ("2.4", "5", "6"):
            unknown += 1
            continue
        k = (r.band, r.channel)
        d = chans.setdefault(k, {"band": r.band, "channel": r.channel, "frequency_mhz": RF.channel_freq(r.band, r.channel),
                                 "dfs": RF.is_dfs(r.band, r.channel), "radios": 0, "clients": 0, "util": []})
        d["radios"] += 1
        d["clients"] += r.clients or 0
        if r.channel_util_pct is not None:
            d["util"].append(r.channel_util_pct)
        widths[(r.band, r.channel_width_mhz)] = widths.get((r.band, r.channel_width_mhz), 0) + 1
        a = apmap.get(r.ap_id)
        sk = ((a.site if a else "") or "(no site)", r.band, r.channel)
        sites[sk] = sites.get(sk, 0) + 1
    bands = sorted({b for b, _ in chans}, key=lambda b: float(b))
    return {"bands": bands, "channels": [{**{k: v for k, v in d.items() if k != "util"}, "avg_util": round(sum(d["util"]) / len(d["util"]), 1) if d["util"] else None}
                                         for _, d in sorted(chans.items(), key=lambda x: (float(x[0][0]), x[0][1]))],
            "widths": [{"band": b, "width_mhz": w, "radios": n} for (b, w), n in sorted(widths.items(), key=lambda x: (float(x[0][0]), x[0][1] or 0))],
            "by_site": [{"site": st, "band": b, "channel": c, "frequency_mhz": RF.channel_freq(b, c), "radios": n}
                        for (st, b, c), n in sorted(sites.items(), key=lambda x: (x[0][0], float(x[0][1]), x[0][2]))],
            "radios_without_channel": unknown,
            "reference": {b: [{"channel": c, "frequency_mhz": RF.channel_freq(b, c), "dfs": RF.is_dfs(b, c)} for c in (RF.CH_24 if b == "2.4" else RF.CH_5 if b == "5" else RF.CH_6)]
                          for b in bands}}


@router.get("/heatmap")
async def heatmap(wlc_id: list[int] = Query(default=[]), site: str | None = Query(None, max_length=128), ap_id: int | None = None, radio_id: int | None = None,
                  band: str | None = Query(None, max_length=8), metric: str = Query("channel_util_pct", pattern=r"^(channel_util_pct|noise_dbm|interference_pct|retry_pct|clients)$"),
                  range: str = Query("24h", pattern=r"^(1h|6h|24h|7d|30d)$"), _: User = Depends(current_user), s: AsyncSession = Depends(get_session),
                  ch: ClickHouse = Depends(ch_dep)):
    """AP radio × time from rf_telemetry. Buckets without an ok sample are null (shown as 'no data', never 0)."""
    wlcs, ids, apmap, rs = await _scope(s, wlc_id, site, ap_id, radio_id, band)
    hours, b = RANGES[range]
    t1 = _now()
    t0 = t1 - timedelta(hours=hours)
    cells = []
    if rs:
        rows = await ch.aquery(f"SELECT radio_id, toStartOfInterval(ts, INTERVAL {b} SECOND) AS t, avgIf(value, status = 'ok') AS v, countIf(status = 'ok') AS n "
                               "FROM rf_telemetry WHERE metric = {m:String} AND radio_id IN {r:Array(UInt32)} AND ts >= {t0:DateTime64(3)} "
                               "GROUP BY radio_id, t ORDER BY t", {"m": metric, "r": [r.id for r in rs], "t0": t0})
        for x in rows:
            t = x["t"] if isinstance(x["t"], datetime) else datetime.fromisoformat(str(x["t"]))
            cells.append({"radio_id": int(x["radio_id"]), "t": W._iso(t), "value": round(float(x["v"]), 1) if int(x["n"]) else None})
    t = None
    if rs:
        t = W.thresholds(next(iter(wlcs.values())))
    return {"metric": metric, "bucket_seconds": b, "from": t0.isoformat(), "to": t1.isoformat(), "cells": cells,
            "rows": [{"radio_id": r.id, "ap_id": r.ap_id, "ap": apmap[r.ap_id].name if r.ap_id in apmap else "", "slot": r.slot, "band": r.band,
                      "channel": r.channel, "site": apmap[r.ap_id].site if r.ap_id in apmap else "",
                      "threshold": W.util_limit(W.thresholds(wlcs[r.wlc_id]), r.band) if metric == "channel_util_pct" else None}
                     for r in sorted(rs, key=lambda r: ((apmap[r.ap_id].name if r.ap_id in apmap else ""), r.slot))][:500],
            "thresholds": {"noise_dbm": t["noise_dbm"], "interference_pct": t["interference_pct"], "retry_pct": t["retry_pct"]} if t else None}


@router.get("/radios")
async def radios(wlc_id: list[int] = Query(default=[]), site: str | None = Query(None, max_length=128), ap_id: int | None = None,
                 band: str | None = Query(None, max_length=8), q: str | None = Query(None, max_length=64), _: User = Depends(current_user),
                 s: AsyncSession = Depends(get_session)):
    wlcs, ids, apmap, rs = await _scope(s, wlc_id, site, ap_id, band=band)
    out = [W.radio_out(r, apmap.get(r.ap_id), W.thresholds(wlcs[r.wlc_id])) for r in rs]
    if q:
        ql = q.lower()
        out = [x for x in out if ql in (x["ap"] or "").lower() or ql == str(x["channel"])]
    return {"items": sorted(out, key=lambda x: ((x["ap"] or ""), x["slot"]))}


@router.get("/radios/{rid}")
async def radio(rid: int, _: User = Depends(current_user), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    r = await s.get(WirelessRadio, rid)
    if r is None:
        raise HTTPException(404, "radio not found")
    a = await s.get(WirelessAp, r.ap_id)
    w = await s.get(Switch, r.wlc_id)
    t = W.thresholds(w)
    siblings = (await s.execute(select(WirelessRadio).where(WirelessRadio.ap_id == r.ap_id, WirelessRadio.present.is_(True)).order_by(WirelessRadio.slot))).scalars().all()
    cl = (await s.execute(select(WirelessClient).where(WirelessClient.ap_id == r.ap_id, WirelessClient.slot == r.slot, WirelessClient.present.is_(True)))).scalars().all()
    snr = [c.snr_db for c in cl if c.snr_db is not None]
    rssi = [c.rssi_dbm for c in cl if c.rssi_dbm is not None]
    status = {}
    try:
        rows = await ch.aquery("SELECT metric, argMax(status, ts) AS o_st, max(ts) AS o_t FROM rf_telemetry WHERE radio_id = {r:UInt32} "
                               "AND ts >= {t0:DateTime64(3)} GROUP BY metric", {"r": rid, "t0": _now() - timedelta(hours=6)})
        status = {x["metric"]: {"status": x["o_st"], "at": W._iso(x["o_t"] if isinstance(x["o_t"], datetime) else datetime.fromisoformat(str(x["o_t"])))} for x in rows}
    except Exception:
        status = {}
    evs = (await s.execute(select(WirelessEvent).where(WirelessEvent.ap_id == r.ap_id, WirelessEvent.kind.in_(RF_EVENT_KINDS),
                                                       WirelessEvent.component == f"{a.name if a else ''}/{r.slot}").order_by(WirelessEvent.at.desc()).limit(50))).scalars().all()
    fnd = await analyze(s, ch, ap_id=r.ap_id)
    return {"radio": W.radio_out(r, a, t), "ap": W.ap_out(a, w) if a else None, "controller": {"id": w.id, "name": w.name, "firmware": w.firmware, "model": w.model} if w else None,
            "frequency": RF.describe(r.band, r.channel, r.channel_width_mhz), "power_levels_mw": r.power_levels or {},
            "siblings": [W.radio_out(x, a, t) for x in siblings],
            "clients": {"count": len(cl), "snr_measured": len(snr), "avg_snr_db": round(sum(snr) / len(snr), 1) if snr else None,
                        "avg_rssi_dbm": round(sum(rssi) / len(rssi), 1) if rssi else None, "poor_snr": sum(1 for x in snr if x <= t["snr_poor_db"])},
            "neighbors": r.neighbors or [], "radar": r.radar or [], "metric_status": status,
            "events": [W.event_out(e, {a.id: a} if a else {}) for e in evs], "findings": [f for f in fnd["findings"] if f["radio_id"] == rid],
            "thresholds": {"channel_util_pct": W.util_limit(t, r.band), "noise_dbm": t["noise_dbm"], "interference_pct": t["interference_pct"],
                           "retry_pct": t["retry_pct"], "snr_poor_db": t["snr_poor_db"]}}


@router.get("/radios/{rid}/history")
async def radio_history(rid: int, range: str = Query("24h", pattern=r"^(1h|6h|24h|7d|30d)$"), metric: list[str] = Query(default=[]),
                        _: User = Depends(current_user), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    r = await s.get(WirelessRadio, rid)
    if r is None:
        raise HTTPException(404, "radio not found")
    ms = [m for m in metric if m in RF_METRICS] or ["channel_util_pct", "tx_util_pct", "rx_util_pct", "noise_dbm", "interference_pct", "clients", "retry_pct"]
    hours, b = RANGES[range]
    rows = await ch.aquery(f"SELECT metric, toStartOfInterval(ts, INTERVAL {b} SECOND) AS t, avgIf(value, status = 'ok') AS v, countIf(status = 'ok') AS n, "
                           "count() AS total, anyLast(channel) AS o_ch FROM rf_telemetry WHERE radio_id = {r:UInt32} AND metric IN {m:Array(String)} "
                           "AND ts >= {t0:DateTime64(3)} GROUP BY metric, t ORDER BY t", {"r": rid, "m": ms, "t0": _now() - timedelta(hours=hours)})
    series: dict[str, list] = {m: [] for m in ms}
    for x in rows:
        t = x["t"] if isinstance(x["t"], datetime) else datetime.fromisoformat(str(x["t"]))
        series[x["metric"]].append({"t": W._iso(t), "v": round(float(x["v"]), 2) if int(x["n"]) else None, "samples": int(x["n"]), "polls": int(x["total"]),
                                    "channel": x["o_ch"]})
    return {"radio_id": rid, "bucket_seconds": b, "series": series}


@router.get("/events")
async def events(wlc_id: list[int] = Query(default=[]), site: str | None = Query(None, max_length=128), ap_id: int | None = None,
                 kind: list[str] = Query(default=[]), hours: int = Query(24, ge=1, le=720), include_alerts: bool = True,
                 _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    """Channel changes (with inferred reason and confidence), DFS radar, radio up/down, power changes, radio link changes, and
    RF alerts (high utilisation, noise, interference, retries, SNR) from the alert engine."""
    wlcs, ids, apmap, rs = await _scope(s, wlc_id, site, ap_id)
    kinds = [k for k in kind if k in RF_EVENT_KINDS] or list(RF_EVENT_KINDS)
    since = _now() - timedelta(hours=hours)
    q = select(WirelessEvent).where(WirelessEvent.at >= since, WirelessEvent.kind.in_(kinds), WirelessEvent.wlc_id.in_(ids or [0]))
    if ap_id or site:
        q = q.where(WirelessEvent.ap_id.in_({r.ap_id for r in rs} or {0}))
    out = [{**W.event_out(e, apmap), "source": "telemetry"} for e in (await s.execute(q.order_by(WirelessEvent.at.desc()).limit(1000))).scalars()]
    if include_alerts and (not kind or "alert" in kind):
        aps_in = {r.ap_id for r in rs}
        for al in (await s.execute(select(Alert).where(Alert.rule_key.in_(RF_ALERT_RULES), Alert.last_seen >= since).order_by(Alert.last_seen.desc()).limit(500))).scalars():
            if (al.evidence or {}).get("ap_id") not in aps_in:
                continue
            out.append({"id": f"alert-{al.id}", "at": W._iso(al.first_seen), "kind": al.rule_key, "severity": al.severity, "detail": al.explanation,
                        "status": al.status, "ap_id": (al.evidence or {}).get("ap_id"), "ap": apmap[(al.evidence or {})["ap_id"]].name if (al.evidence or {}).get("ap_id") in apmap else "",
                        "source": "alert", "alert_id": al.id, "last_seen": W._iso(al.last_seen)})
    out.sort(key=lambda e: e.get("at") or "", reverse=True)
    return {"items": out[:1500], "kinds": {k: sum(1 for e in out if e["kind"] == k) for k in {e["kind"] for e in out}}}


@router.get("/findings")
async def findings(wlc_id: list[int] = Query(default=[]), site: str | None = Query(None, max_length=128), ap_id: int | None = None,
                   band: str | None = Query(None, max_length=8), rule: list[str] = Query(default=[]), engine: str = Query("rules", pattern=r"^rules$"),
                   _: User = Depends(current_user), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    """Explainable RF findings (rule-based). `engine` is the root-cause provider; only "rules" is implemented."""
    r = await analyze(s, ch, site=site, wlc_ids=wlc_id or None, ap_id=ap_id, band=band, engine=engine)
    if rule:
        r["findings"] = [f for f in r["findings"] if f["rule"] in rule]
    r["rules"] = list(RULES)
    r["engines"] = list(RCA_PROVIDERS)
    return r


@router.get("/capabilities")
async def capabilities(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    """What each controller (software) and AP model actually reports, from collected data: a metric counts as supported for a
    model only when at least one of its radios returned it."""
    wlcs = {w.id: w for w in (await s.execute(select(Switch).where(func.lower(Switch.role) == "wlc"))).scalars()}
    rs = list((await s.execute(select(WirelessRadio).where(WirelessRadio.present.is_(True)))).scalars())
    aps = {a.id: a for a in (await s.execute(select(WirelessAp))).scalars()}
    fields = {"channel_util_pct": "channel_util_pct", "noise_dbm": "noise_dbm", "interference_pct": "interference_pct", "retry_pct": "retry_pct",
              "tx_power_dbm": "tx_power_dbm", "channel_width_mhz": "channel_width_mhz", "country": "country", "radio_mac": "radio_mac",
              "neighbors": "neighbors", "radar": "radar", "link_changes": "link_changes", "recommended_channel": "recommended_channel"}
    models: dict[tuple, dict] = {}
    for r in rs:
        a = aps.get(r.ap_id)
        k = (r.wlc_id, (a.model if a else "") or "unknown")
        d = models.setdefault(k, {"radios": 0, **{f: 0 for f in fields}})
        d["radios"] += 1
        for f, attr in fields.items():
            v = getattr(r, attr)
            if f in ("neighbors", "radar"):
                d[f] += r.neighbors_collected_at is not None if f == "neighbors" else (r.rf_collected_at is not None)
            elif v not in (None, "", [], {}):
                d[f] += 1
    ctrl = []
    rf_keys = sorted({o["metric"] for o in OBJ.values() if o["group"] in ("wireless_radio", "wireless_radio_rf", "wireless_radio_meta", "wireless_rf_neighbors") and o["metric"]})
    for w in wlcs.values():
        caps = w.capabilities or {}
        ctrl.append({"id": w.id, "name": w.name, "model": w.model, "firmware": w.firmware,
                     "metrics": {k: {"status": (caps.get(k) or {}).get("last_result") or "not collected yet", "ever_ok": (caps.get(k) or {}).get("ever_ok", False),
                                     "source": (caps.get(k) or {}).get("source", "")} for k in rf_keys}})
    return {"controllers": ctrl, "models": [{"wlc_id": k[0], "wlc": wlcs[k[0]].name if k[0] in wlcs else "", "model": k[1], **v,
                                             "supported": {f: v[f] > 0 for f in fields}} for k, v in sorted(models.items(), key=lambda x: (x[0][0], x[0][1]))]}


@router.get("/channels")
async def channels(band: str = Query("5", pattern=r"^(2\.4|5|6)$"), width: int = Query(20, ge=20, le=160), _: User = Depends(current_user)):
    """Reference: channel → frequency / center frequency / DFS for a band and width (app/wireless/rf.py)."""
    chs = RF.CH_24 if band == "2.4" else RF.CH_5 if band == "5" else RF.CH_6
    return {"band": band, "width_mhz": width, "channels": [RF.describe(band, c, width) for c in chs]}
