"""Firewall health from FortiGate event logs: resource use, reboots, FortiAnalyzer connectivity and log-feed gaps.

Sources:
    0100040704  System performance statistics (every few minutes): cpu, mem, totalsession, setuprate, bandwidth,
                sysuptime, waninfo. A drop in sysuptime between two samples is a reboot.
    0100022901 / 0100022902  FortiAnalyzer connection up / down
    events_minute rollup     per-minute event counts per firewall and category (log-feed gaps)
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .db.models import Firewall

PERF = "0100040704"
FAZ_UP, FAZ_DOWN = "0100022901", "0100022902"
CATEGORIES = ("traffic", "dns", "web", "security", "system")


def _num(name: str) -> str:
    return f"toFloat64OrNull(extract(raw, '[ ]{name}=([0-9.]+)'))"


# HA members log under one registered firewall; key-value logs carry devname, RFC 5424 logs carry it as the hostname
MEMBER = ("if(extract(raw, 'devname=\"([^\"]+)\"') != '', extract(raw, 'devname=\"([^\"]+)\"'), "
          "extract(raw, '^<[0-9]+>1 [^ ]+ ([^ ]+)'))")


def _aware(v) -> datetime:
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(str(v).replace("Z", "")).replace(tzinfo=timezone.utc)


def _clean(v):
    return None if isinstance(v, float) and v != v else v


async def perf_samples(ch, t0: datetime, t1: datetime, fw_ids: list[int] | None = None) -> list[dict]:
    p = {"t0": t0, "t1": t1}
    fw = ""
    if fw_ids:
        p["fws"] = [int(x) for x in fw_ids]
        fw = " AND firewall_id IN {fws:Array(UInt32)}"
    rows = await ch.aquery(
        f"SELECT firewall_id, firewall_name, {MEMBER} AS member, event_time AS t, {_num('cpu')} AS cpu, {_num('mem')} AS mem, "
        f"{_num('totalsession')} AS sessions, {_num('setuprate')} AS setuprate, {_num('sysuptime')} AS uptime, "
        f"toFloat64OrNull(extract(raw, 'bandwidth=\"([0-9]+)/')) AS bw_in, toFloat64OrNull(extract(raw, 'bandwidth=\"[0-9]+/([0-9]+)')) AS bw_out "
        f"FROM events WHERE category = 'system' AND log_id = '{PERF}' AND event_time >= {{t0:DateTime64(3)}} "
        f"AND event_time < {{t1:DateTime64(3)}}{fw} ORDER BY firewall_id, member, t", p)
    for r in rows:
        r["t"] = _aware(r["t"])
        for k in ("cpu", "mem", "sessions", "setuprate", "uptime", "bw_in", "bw_out"):
            r[k] = _clean(r[k])
    return rows


def reboots(samples: list[dict]) -> list[dict]:
    """sysuptime going backwards = the member restarted; boot time ≈ sample time − new uptime."""
    out, prev = [], {}
    for r in samples:
        k = (r["firewall_id"], r["member"])
        last = prev.get(k)
        if last and r["uptime"] is not None and last["uptime"] is not None and r["uptime"] + 60 < last["uptime"]:
            boot = r["t"] - timedelta(seconds=r["uptime"])
            out.append({"firewall_id": r["firewall_id"], "firewall_name": r["firewall_name"], "member": r["member"],
                        "boot_time": boot.isoformat(), "detected_at": r["t"].isoformat(), "previous_uptime_s": int(last["uptime"])})
        prev[k] = r
    return out


async def faz_status(ch, t0: datetime, t1: datetime) -> dict[int, dict]:
    rows = await ch.aquery(
        f"SELECT firewall_id, countIf(log_id = '{FAZ_DOWN}') AS disconnects, argMax(log_id, event_time) AS last_id, "
        f"max(event_time) AS last_at, anyIf(extract(raw, 'reason=\"([^\"]+)\"'), log_id = '{FAZ_DOWN}') AS reason, "
        f"anyIf(extract(msg, '([0-9.]+)$'), log_id IN ('{FAZ_UP}', '{FAZ_DOWN}')) AS server "
        f"FROM events WHERE category = 'system' AND log_id IN ('{FAZ_UP}', '{FAZ_DOWN}') AND event_time >= {{t0:DateTime64(3)}} "
        f"AND event_time < {{t1:DateTime64(3)}} GROUP BY firewall_id", {"t0": t0, "t1": t1})
    return {int(r["firewall_id"]): {"disconnects": int(r["disconnects"]), "connected": r["last_id"] == FAZ_UP,
                                    "last_change": _aware(r["last_at"]).isoformat(), "reason": r["reason"], "server": r["server"]} for r in rows}


async def feed_status(ch, now: datetime, silent_minutes: int = 15) -> list[dict]:
    """Per firewall and log category: is the feed alive? A category that normally logs (≥ 1 event / 10 min over the
    last day) but has been silent for `silent_minutes` is a gap — e.g. traffic logging switched off on a policy."""
    rows = await ch.aquery(
        "SELECT firewall_id, category, sum(events) AS n24, max(minute) AS last, "
        "sumIf(events, minute >= now() - INTERVAL 1 HOUR) AS n1h FROM events_minute "
        "WHERE minute >= now() - INTERVAL 1 DAY GROUP BY firewall_id, category")
    out = []
    for r in rows:
        last = _aware(r["last"])
        n24 = int(r["n24"])
        silent = (now - last).total_seconds() / 60
        regular = n24 >= 144
        out.append({"firewall_id": int(r["firewall_id"]), "category": r["category"], "events_24h": n24, "events_1h": int(r["n1h"]),
                    "last_event": last.isoformat(), "silent_minutes": round(silent, 1),
                    "gap": regular and silent >= silent_minutes})
    return out


async def notable(ch, t0: datetime, t1: datetime) -> list[dict]:
    """Operationally interesting system events: HA, conserve mode, link/interface, config, update failures."""
    return await ch.aquery(
        "SELECT firewall_id, log_id, any(extract(raw, 'logdesc=\"([^\"]+)\"')) AS logdesc, any(msg) AS sample, count() AS n, "
        "max(event_time) AS last FROM events WHERE category = 'system' AND event_subtype IN ('system', 'ha') "
        f"AND log_id NOT IN ('{PERF}', '{FAZ_UP}', '{FAZ_DOWN}') AND severity IN ('critical', 'error', 'warning', 'alert', 'emergency') "
        "AND event_time >= {t0:DateTime64(3)} AND event_time < {t1:DateTime64(3)} GROUP BY firewall_id, log_id ORDER BY n DESC LIMIT 200",
        {"t0": t0, "t1": t1})


def _stats(vals: list[float]) -> dict:
    v = sorted(x for x in vals if x is not None)
    if not v:
        return {"avg": None, "max": None, "p95": None}
    return {"avg": round(sum(v) / len(v), 2), "max": v[-1], "p95": v[min(len(v) - 1, int(len(v) * 0.95))]}


async def overview(ch, s: AsyncSession, t0: datetime, t1: datetime, fw_ids: list[int] | None = None) -> dict:
    fws = {f.id: f for f in (await s.execute(select(Firewall))).scalars()}
    samples = await perf_samples(ch, t0, t1, fw_ids)
    boots = reboots(samples)
    faz = await faz_status(ch, t0, t1)
    feeds = await feed_status(ch, datetime.now(timezone.utc))
    notes = await notable(ch, t0, t1)
    members: dict[tuple[int, str], list[dict]] = {}
    for r in samples:
        members.setdefault((r["firewall_id"], r["member"]), []).append(r)
    out = []
    ids = sorted({k[0] for k in members} | {f["firewall_id"] for f in feeds} | set(faz))
    for fid in ids:
        if fw_ids and fid not in fw_ids:
            continue
        f = fws.get(fid)
        mem_rows = []
        for (mfid, member), rs in members.items():
            if mfid != fid:
                continue
            last = rs[-1]
            mem_rows.append({"member": member, "last_sample": last["t"].isoformat(), "cpu": last["cpu"], "mem": last["mem"],
                             "sessions": last["sessions"], "setuprate": last["setuprate"], "uptime_s": last["uptime"],
                             "bw_in_kbps": last["bw_in"], "bw_out_kbps": last["bw_out"],
                             "cpu_stats": _stats([x["cpu"] for x in rs]), "mem_stats": _stats([x["mem"] for x in rs]),
                             "sessions_stats": _stats([x["sessions"] for x in rs]), "samples": len(rs)})
        fd = [x for x in feeds if x["firewall_id"] == fid]
        out.append({"firewall_id": fid, "firewall_name": f.name if f else str(fid), "site": f.site if f else "",
                    "members": sorted(mem_rows, key=lambda m: m["member"]),
                    "reboots": [b for b in boots if b["firewall_id"] == fid], "faz": faz.get(fid),
                    "feeds": sorted(fd, key=lambda x: CATEGORIES.index(x["category"]) if x["category"] in CATEGORIES else 9),
                    "feed_gaps": [x["category"] for x in fd if x["gap"]],
                    "notable": [{"log_id": n["log_id"], "logdesc": n["logdesc"], "sample": n["sample"], "count": int(n["n"]),
                                 "last": _aware(n["last"]).isoformat()} for n in notes if int(n["firewall_id"]) == fid][:15],
                    "api_status": f.api_status if f else None, "is_demo": bool(f and f.is_demo)})
    return {"window": {"start": t0.isoformat(), "end": t1.isoformat()}, "firewalls": out,
            "totals": {"firewalls": len(out), "reboots": len(boots), "feed_gaps": sum(len(x["feed_gaps"]) for x in out),
                       "faz_disconnects": sum((x["faz"] or {}).get("disconnects", 0) for x in out),
                       "high_cpu": sum(1 for x in out for m in x["members"] if (m["cpu"] or 0) >= 80),
                       "high_mem": sum(1 for x in out for m in x["members"] if (m["mem"] or 0) >= 80)}}


async def timeseries(ch, fw_id: int, t0: datetime, t1: datetime, bucket: int) -> list[dict]:
    rows = await ch.aquery(
        f"SELECT toStartOfInterval(event_time, INTERVAL {int(bucket)} SECOND) AS t, {MEMBER} AS member, avg({_num('cpu')}) AS cpu, "
        f"max({_num('cpu')}) AS cpu_max, avg({_num('mem')}) AS mem, max({_num('totalsession')}) AS sessions, avg({_num('setuprate')}) AS setuprate "
        f"FROM events WHERE category = 'system' AND log_id = '{PERF}' AND firewall_id = {{fw:UInt32}} AND event_time >= {{t0:DateTime64(3)}} "
        f"AND event_time < {{t1:DateTime64(3)}} GROUP BY t, member ORDER BY t", {"fw": fw_id, "t0": t0, "t1": t1})
    for r in rows:
        r["t"] = _aware(r["t"]).isoformat()
        for k in ("cpu", "cpu_max", "mem", "sessions", "setuprate"):
            r[k] = _clean(r[k])
    return rows
