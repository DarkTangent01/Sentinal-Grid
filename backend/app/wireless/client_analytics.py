"""Historical wireless client analytics (Wireless → WLAN / SSID → daily client analysis, per-AP client analytics).

Every number is computed in ClickHouse from what the controllers reported (app/wireless/history.py):
  * unique clients   = distinct client MACs listed by the controller in the period (wireless_client_slots.clients);
  * peak / average / minimum concurrent clients = clients listed per 5-minute bucket (wireless_client_slots.conc),
    averaged over the buckets in which the controller's client table was actually read; a bucket with no reading is a
    gap, never a zero;
  * sessions        = associations (wireless_client_events kind 'connect'); per AP, associations that began on the AP
    plus roams onto it ("AP sessions");
  * disconnects / roams = detected changes between two client polls (wireless_client_events).

Days are calendar days in the caller's timezone (the user's display timezone). The rollup grain is 30 minutes, so day
boundaries are exact in whole- and half-hour timezones; a quarter-hour timezone (e.g. Asia/Kathmandu) is rounded to the
nearest half hour, and the response says so.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo

SORTS_SSID = {"date": "day", "ssid": "ssid", "unique_clients": "unique_clients", "sessions": "sessions", "peak_clients": "peak_clients",
              "avg_clients": "avg_clients"}
SORTS_AP = {**SORTS_SSID, "ap_name": "ap_name"}
MAX_DAYS = 400
BANDS = ("2.4", "5", "6")


@dataclass
class Scope:
    tz: str
    t0: datetime
    t1: datetime
    wlc_ids: list[int]
    ssids: list[str] = field(default_factory=list)
    ap_ids: list[int] | None = None          # None = all APs; [] = a filter that matched no AP
    bands: list[str] = field(default_factory=list)
    days: list[str] = field(default_factory=list)
    tz_note: str = ""


def check_tz(tz: str | None) -> str:
    tz = tz or "UTC"
    if not re.fullmatch(r"[A-Za-z0-9_+\-/]{1,64}", tz):
        raise ValueError("invalid timezone")
    ZoneInfo(tz)            # raises for an unknown zone
    return tz


def window(start: date, end: date, tz: str) -> tuple[datetime, datetime, list[str], str]:
    if end < start:
        raise ValueError("end_date is before start_date")
    if (end - start).days + 1 > MAX_DAYS:
        raise ValueError(f"at most {MAX_DAYS} days")
    z = ZoneInfo(tz)
    t0 = datetime.combine(start, time(0), tzinfo=z).astimezone(timezone.utc)
    t1 = datetime.combine(end + timedelta(days=1), time(0), tzinfo=z).astimezone(timezone.utc)
    off = int(datetime.combine(start, time(0), tzinfo=z).utcoffset().total_seconds())
    note = "" if off % 1800 == 0 else f"{tz} is not a whole or half hour from UTC: day boundaries are rounded to the nearest 30 minutes."
    days = [(start + timedelta(days=i)).isoformat() for i in range((end - start).days + 1)]
    return t0, t1, days, note


PERIODS = ("day", "week", "month")


def _period(col: str, tz: str, period: str) -> str:
    """Calendar period start in the timezone: day, ISO week (Monday) or month."""
    d = f"toDate({col}, {_lit(tz)})"
    return {"week": f"toMonday({d})", "month": f"toStartOfMonth({d})"}.get(period, d)


def _lit(tz: str) -> str:
    return "'" + tz + "'"          # check_tz() allows only [A-Za-z0-9_+-/]


def _where(sc: Scope, *, ts: str = "slot", filters: bool = True, events: bool = False, ap_cols: tuple[str, ...] = ("ap_id",)) -> tuple[str, dict]:
    parts = [f"{ts} >= {{t0:DateTime64(3)}}", f"{ts} < {{t1:DateTime64(3)}}", "wlc_id IN {w:Array(UInt32)}"]
    p: dict = {"t0": sc.t0, "t1": sc.t1, "w": sc.wlc_ids or [0]}
    if filters:
        if sc.ssids:
            parts.append("ssid IN {ss:Array(String)}")
            p["ss"] = sc.ssids
        if sc.ap_ids is not None:
            parts.append("(" + " OR ".join(f"{c} IN {{aps:Array(UInt32)}}" for c in ap_cols) + ")")
            p["aps"] = sc.ap_ids or [0]
        if sc.bands:
            parts.append("band IN {bs:Array(String)}")
            p["bs"] = sc.bands
    return " AND ".join(parts), p


def _names(aps: dict) -> dict:
    ids = sorted(aps)
    return {"ap_ids_all": ids or [0], "ap_names_all": [aps[i].name or aps[i].mac for i in ids] or [""],
            "ap_macs_all": [aps[i].mac for i in ids] or [""]}


def _page(rows: list[dict]) -> int:
    return int(rows[0]["_total"]) if rows else 0


async def coverage(ch, sc: Scope, period: str = "day") -> dict:
    """Per period: 5-minute buckets in which a client table was read (288 a day at the default 300-s interval)."""
    w, p = _where(sc, filters=False)
    rows = await ch.aquery(f"SELECT toString({_period('slot', sc.tz, period)}) AS day, length((sumMapMerge(conc)).1) AS polled "
                           f"FROM wireless_client_slots FINAL WHERE {w} GROUP BY day ORDER BY day", p)
    return {r["day"]: int(r["polled"]) for r in rows}


async def daily_ssid(ch, sc: Scope, sort: str = "date", order: str = "desc", page: int = 1, size: int = 50, period: str = "day") -> dict:
    w, p = _where(sc)
    wp, _ = _where(sc, filters=False)
    we, pe = _where(sc, ts="ts")
    ps, pt = _period("slot", sc.tz, period), _period("ts", sc.tz, period)
    col = SORTS_SSID.get(sort, "day")
    sql = f"""
    SELECT toString(d.day) AS day, d.ssid AS ssid, d.uniq AS unique_clients, e.sessions AS sessions,
           arrayMax(tupleElement(d.m, 2)) AS peak_clients,
           round(arraySum(tupleElement(d.m, 2)) / greatest(pl.polled, 1), 2) AS avg_clients, pl.polled AS polled_buckets,
           count() OVER () AS _total
    FROM (SELECT {ps} AS day, ssid, uniqExactMerge(clients) AS uniq, sumMapMerge(conc) AS m
          FROM wireless_client_slots FINAL WHERE {w} GROUP BY day, ssid) AS d
    LEFT JOIN (SELECT {ps} AS day, length((sumMapMerge(conc)).1) AS polled
               FROM wireless_client_slots FINAL WHERE {wp} GROUP BY day) AS pl ON pl.day = d.day
    LEFT JOIN (SELECT {pt} AS day, ssid, count() AS sessions
               FROM wireless_client_events FINAL WHERE kind = 'connect' AND {we} GROUP BY day, ssid) AS e ON e.day = d.day AND e.ssid = d.ssid
    ORDER BY {col} {'ASC' if order == 'asc' else 'DESC'}, day DESC, ssid
    LIMIT {int(size)} OFFSET {int((max(1, page) - 1) * size)}
    """
    rows = await ch.aquery(sql, {**p, **pe})
    return {"items": [_clean(r) for r in rows], "total": _page(rows), "page": page, "page_size": size}


async def daily_ap(ch, sc: Scope, aps: dict, by_ssid: bool = True, sort: str = "date", order: str = "desc", page: int = 1, size: int = 50,
                   period: str = "day") -> dict:
    """Per day and AP (and SSID when by_ssid). AP sessions = associations that began on the AP + roams onto it."""
    w, p = _where(sc)
    wp, _ = _where(sc, filters=False)
    we, pe = _where(sc, ts="ts")
    ps, pt = _period("slot", sc.tz, period), _period("ts", sc.tz, period)
    g = "ap_id, ssid" if by_ssid else "ap_id"
    on_ssid = " AND e.ssid = d.ssid" if by_ssid else ""
    col = SORTS_AP.get(sort, "day")
    sql = f"""
    SELECT toString(d.day) AS day, d.ap_id AS ap_id, transform(d.ap_id, {{ap_ids_all:Array(UInt32)}}, {{ap_names_all:Array(String)}}, '') AS ap_name,
           transform(d.ap_id, {{ap_ids_all:Array(UInt32)}}, {{ap_macs_all:Array(String)}}, '') AS ap_mac,
           {'d.ssid' if by_ssid else "''"} AS ssid, d.uniq AS unique_clients, e.sessions AS sessions,
           arrayMax(tupleElement(d.m, 2)) AS peak_clients,
           round(arraySum(tupleElement(d.m, 2)) / greatest(pl.polled, 1), 2) AS avg_clients, count() OVER () AS _total
    FROM (SELECT {ps} AS day, {g}, uniqExactMerge(clients) AS uniq, sumMapMerge(conc) AS m
          FROM wireless_client_slots FINAL WHERE {w} AND ap_id != 0 GROUP BY day, {g}) AS d
    LEFT JOIN (SELECT {ps} AS day, length((sumMapMerge(conc)).1) AS polled
               FROM wireless_client_slots FINAL WHERE {wp} GROUP BY day) AS pl ON pl.day = d.day
    LEFT JOIN (SELECT {pt} AS day, {g}, count() AS sessions
               FROM wireless_client_events FINAL WHERE kind IN ('connect', 'roam') AND {we} GROUP BY day, {g}) AS e
           ON e.day = d.day AND e.ap_id = d.ap_id{on_ssid}
    ORDER BY {col} {'ASC' if order == 'asc' else 'DESC'}, day DESC, ap_name, ssid
    LIMIT {int(size)} OFFSET {int((max(1, page) - 1) * size)}
    """
    rows = await ch.aquery(sql, {**p, **pe, **_names(aps)})
    return {"items": [_clean(r) for r in rows], "total": _page(rows), "page": page, "page_size": size}


async def hourly(ch, sc: Scope, group: str = "ssid", limit: int = 8, expected_weeks: int = 0) -> dict:
    """Clients per hour (in the caller's timezone): unique, average / peak / minimum concurrent, for the top `limit`
    SSIDs or APs (group) or all together (group 'none'); plus the 24-hour profile of all selected clients together.

    An hour in which the client table was read but a series had no client is 0 for that series; an hour with no
    reading at all is left out (a gap). expected_weeks > 0 adds to each point the usual average for that hour of the week
    (median of the same hour in up to that many previous weeks, with a robust band; nms/anomaly.band)."""
    from dataclasses import replace
    from ..nms.anomaly import band
    t_show = sc.t0
    if expected_weeks:
        sc = replace(sc, t0=sc.t0 - timedelta(days=7 * expected_weeks))
    w, p = _where(sc)
    wp, _ = _where(sc, filters=False)
    tz = _lit(sc.tz)
    dim = {"ssid": "ssid", "ap": "ap_id"}.get(group, "")
    apf = " AND ap_id != 0" if dim == "ap_id" else ""
    q = ("SELECT toUnixTimestamp(toStartOfHour(slot, {tz})) AS h, {sel}, uniqExactMerge(clients) AS u, sumMapMerge(conc) AS m "
         "FROM wireless_client_slots FINAL WHERE {w}{apf} GROUP BY h, k")
    rows = await ch.aquery(q.format(tz=tz, sel=f"{dim} AS k" if dim else "'all' AS k", w=w, apf=apf), p)
    totals = rows if not dim else await ch.aquery(q.format(tz=tz, sel="'all' AS k", w=w, apf=apf), p)
    polled = {_ts(r["h"]): list(r["b"]) for r in await ch.aquery(
        f"SELECT toUnixTimestamp(toStartOfHour(slot, {tz})) AS h, (sumMapMerge(conc)).1 AS b FROM wireless_client_slots FINAL WHERE {wp} GROUP BY h", p)}
    all_hours = sorted(polled)
    hours = [h for h in all_hours if h >= t_show]

    def point(h: datetime, r: dict | None) -> dict:
        buckets = polled[h]
        vals = dict(zip(r["m"][0], r["m"][1])) if r else {}
        counts = [int(vals.get(b, 0)) for b in buckets] or [0]
        return {"t": h.isoformat(), "unique_clients": int(r["u"]) if r else 0, "avg_clients": round(sum(counts) / max(1, len(buckets)), 2),
                "peak_clients": max(counts), "min_clients": min(counts), "polled_buckets": len(buckets)}

    tot: dict = {}
    by: dict = {}
    for r in rows:
        tot[r["k"]] = tot.get(r["k"], 0) + int(r["u"])
        by[(r["k"], _ts(r["h"]))] = r
    keys = [k for k, _ in sorted(tot.items(), key=lambda x: -x[1])[:limit]]
    series = [{"key": str(k), "points": [point(h, by.get((k, h))) for h in hours]} for k in keys]
    if expected_weeks:
        for sr, k in zip(series, keys):
            for pt, h in zip(sr["points"], hours):
                hist = [point(x, by.get((k, x)))["avg_clients"] for x in (h - timedelta(days=7 * n) for n in range(1, expected_weeks + 1)) if x in polled]
                if len(hist) >= 2:
                    med, low, high = band(hist, 3.0, 1.0, 0.1)
                    pt.update(expected=round(med, 2), expected_low=round(max(0.0, low), 2), expected_high=round(high, 2))
    z = ZoneInfo(sc.tz)
    all_by = {_ts(r["h"]): r for r in totals}
    profile: dict[int, dict] = {}
    for h in hours:
        pt = point(h, all_by.get(h))
        hod = h.astimezone(z).hour
        pr = profile.setdefault(hod, {"avg_sum": 0.0, "n": 0, "peak_clients": 0, "min_clients": None, "unique_sum": 0})
        pr["avg_sum"] += pt["avg_clients"]
        pr["n"] += 1
        pr["unique_sum"] += pt["unique_clients"]
        pr["peak_clients"] = max(pr["peak_clients"], pt["peak_clients"])
        pr["min_clients"] = pt["min_clients"] if pr["min_clients"] is None else min(pr["min_clients"], pt["min_clients"])
    prof = [{"hour": h, "avg_clients": round(v["avg_sum"] / v["n"], 2), "peak_clients": v["peak_clients"], "min_clients": v["min_clients"],
             "avg_unique_clients": round(v["unique_sum"] / v["n"], 1), "hours_observed": v["n"]} for h, v in sorted(profile.items())]
    peak = max(prof, key=lambda x: x["avg_clients"]) if prof else None
    return {"group": group, "series": series, "profile": prof, "peak_hour": peak["hour"] if peak else None}


async def rankings(ch, sc: Scope, aps: dict, top: int = 10) -> dict:
    """Over the whole range, per AP: unique clients, peak / average concurrent, disconnects, roams (in + out), AP
    sessions; per SSID: unique, peak, average, sessions. Top `top` for each metric."""
    w, p = _where(sc)
    wp, _ = _where(sc, filters=False)
    we, pe = _where(sc, ts="ts", ap_cols=("ap_id", "from_ap_id"))
    polled = (await ch.aquery(f"SELECT length((sumMapMerge(conc)).1) AS n FROM wireless_client_slots FINAL WHERE {wp}", p))[0]["n"] or 0
    ap_rows = await ch.aquery(f"SELECT ap_id, uniqExactMerge(clients) AS u, sumMapMerge(conc) AS m FROM wireless_client_slots FINAL "
                              f"WHERE {w} AND ap_id != 0 GROUP BY ap_id", p)
    ev = await ch.aquery(f"SELECT kind, ap_id, from_ap_id, count() AS n FROM wireless_client_events FINAL WHERE {we} "
                         "AND kind IN ('disconnect', 'roam', 'connect') GROUP BY kind, ap_id, from_ap_id", pe)
    disc: dict = {}
    roams: dict = {}
    sess: dict = {}
    for r in ev:
        n = int(r["n"])
        if r["kind"] == "disconnect":
            disc[r["ap_id"]] = disc.get(r["ap_id"], 0) + n
        elif r["kind"] == "roam":
            roams[r["ap_id"]] = roams.get(r["ap_id"], 0) + n
            if r["from_ap_id"]:
                roams[r["from_ap_id"]] = roams.get(r["from_ap_id"], 0) + n
            sess[r["ap_id"]] = sess.get(r["ap_id"], 0) + n
        else:
            sess[r["ap_id"]] = sess.get(r["ap_id"], 0) + n
    out = []
    for r in ap_rows:
        a = aps.get(int(r["ap_id"]))
        vals = r["m"][1]
        out.append({"ap_id": int(r["ap_id"]), "ap_name": a.name if a else f"AP {r['ap_id']}", "ap_mac": a.mac if a else "",
                    "unique_clients": int(r["u"]), "peak_clients": int(max(vals)) if vals else 0,
                    "avg_clients": round(sum(vals) / max(1, polled), 2), "disconnects": disc.get(r["ap_id"], 0),
                    "roams": roams.get(r["ap_id"], 0), "sessions": sess.get(r["ap_id"], 0)})
    ss = await ch.aquery(f"SELECT ssid, uniqExactMerge(clients) AS u, sumMapMerge(conc) AS m FROM wireless_client_slots FINAL WHERE {w} GROUP BY ssid", p)
    ssess = {r["ssid"]: int(r["n"]) for r in await ch.aquery(
        f"SELECT ssid, count() AS n FROM wireless_client_events FINAL WHERE kind = 'connect' AND {we} GROUP BY ssid", pe)}
    ssids = [{"ssid": r["ssid"], "unique_clients": int(r["u"]), "peak_clients": int(max(r["m"][1])) if r["m"][1] else 0,
              "avg_clients": round(sum(r["m"][1]) / max(1, polled), 2), "sessions": ssess.get(r["ssid"], 0)} for r in ss]
    rank = lambda rows, k: sorted(rows, key=lambda x: (-x[k], str(x.get("ap_name") or x.get("ssid"))))[:top]  # noqa: E731
    return {"aps": {k: rank(out, k) for k in ("unique_clients", "peak_clients", "avg_clients", "disconnects", "roams")},
            "ssids": {k: rank(ssids, k) for k in ("unique_clients", "peak_clients", "avg_clients", "sessions")},
            "polled_buckets": int(polled)}


async def ap_distribution(ch, sc: Scope, aps: dict, limit: int = 30) -> dict:
    """Unique clients per AP and band over the range. The AP total counts a client once even if it used two bands."""
    w, p = _where(sc)
    by_band = await ch.aquery(f"SELECT ap_id, band, uniqExactMerge(clients) AS u FROM wireless_client_slots FINAL WHERE {w} AND ap_id != 0 "
                              "GROUP BY ap_id, band", p)
    totals = await ch.aquery(f"SELECT ap_id, uniqExactMerge(clients) AS u FROM wireless_client_slots FINAL WHERE {w} AND ap_id != 0 "
                             "GROUP BY ap_id", p)
    per: dict = {int(r["ap_id"]): {"2.4": 0, "5": 0, "6": 0, "other": 0, "total": int(r["u"])} for r in totals}
    for r in by_band:
        d = per.setdefault(int(r["ap_id"]), {"2.4": 0, "5": 0, "6": 0, "other": 0, "total": 0})
        d[r["band"] if r["band"] in BANDS else "other"] += int(r["u"])
    items = []
    for ap_id, d in per.items():
        a = aps.get(ap_id)
        items.append({"ap_id": ap_id, "ap_name": a.name if a else f"AP {ap_id}", "connected_now": a.clients if a else None,
                      "clients_24": d["2.4"], "clients_5": d["5"], "clients_6": d["6"], "clients_other": d["other"], "unique_clients": d["total"]})
    items.sort(key=lambda x: (-x["unique_clients"], x["ap_name"]))
    return {"items": items[:limit], "total": len(items)}


async def roaming(ch, sc: Scope, aps: dict, top: int = 15) -> dict:
    we, pe = _where(sc, ts="ts", ap_cols=("ap_id", "from_ap_id"))
    tz = _lit(sc.tz)
    daily = await ch.aquery(f"SELECT toString(toDate(ts, {tz})) AS day, count() AS roams, uniqExact(mac) AS clients FROM wireless_client_events FINAL "
                            f"WHERE kind = 'roam' AND {we} GROUP BY day ORDER BY day", pe)
    pairs = await ch.aquery(f"SELECT from_ap_id, ap_id, count() AS n FROM wireless_client_events FINAL WHERE kind = 'roam' AND {we} "
                            f"GROUP BY from_ap_id, ap_id ORDER BY n DESC LIMIT {int(top)}", pe)
    hod = await ch.aquery(f"SELECT toHour(ts, {tz}) AS hour, count() AS n FROM wireless_client_events FINAL WHERE kind = 'roam' AND {we} "
                          "GROUP BY hour ORDER BY hour", pe)
    movers = await ch.aquery(f"SELECT mac, count() AS n, uniqExact(ap_id) AS aps FROM wireless_client_events FINAL WHERE kind = 'roam' AND {we} "
                             f"GROUP BY mac ORDER BY n DESC LIMIT {int(top)}", pe)
    name = lambda i: (aps[i].name if i in aps else f"AP {i}") if i else "unknown"  # noqa: E731
    return {"daily": [{"day": r["day"], "roams": int(r["roams"]), "clients": int(r["clients"])} for r in daily],
            "pairs": [{"from_ap_id": int(r["from_ap_id"]), "from_ap": name(int(r["from_ap_id"])), "to_ap_id": int(r["ap_id"]),
                       "to_ap": name(int(r["ap_id"])), "roams": int(r["n"])} for r in pairs],
            "by_hour": [{"hour": int(r["hour"]), "roams": int(r["n"])} for r in hod],
            "top_clients": [{"mac": r["mac"], "roams": int(r["n"]), "aps": int(r["aps"])} for r in movers],
            "note": "Roams are detected between two client polls: the time is the poll that first showed the new AP."}


async def client_events(ch, sc: Scope, mac: str, limit: int = 500) -> list[dict]:
    we, pe = _where(sc, ts="ts", filters=False)
    rows = await ch.aquery(f"SELECT ts, wlc_id, kind, session_id, ssid, ap_id, from_ap_id, band, from_band, from_ssid, vlan, reason, precision "
                           f"FROM wireless_client_events FINAL WHERE mac = {{mac:String}} AND {we} ORDER BY ts DESC LIMIT {int(limit)}",
                           {**pe, "mac": mac})
    return [_clean(r) for r in rows]


def _ts(v) -> datetime:
    if isinstance(v, (int, float)) or (isinstance(v, str) and v.isdigit()):
        return datetime.fromtimestamp(int(v), tz=timezone.utc)
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(str(v)).replace(tzinfo=timezone.utc)


def _clean(r: dict) -> dict:
    out = {}
    for k, v in r.items():
        if k == "_total":
            continue
        if isinstance(v, datetime):
            v = _ts(v).isoformat()
        elif isinstance(v, float) and v != v:
            v = None
        out[k] = v
    return out
