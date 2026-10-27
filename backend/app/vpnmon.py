"""Site-to-site IPsec tunnel monitoring from FortiGate VPN event logs.

    0101037138  IPsec connection status change: action tunnel-up / tunnel-down
    0101037141  IPsec tunnel statistics (every `nextstat` seconds, usually 600): duration, sentbyte, rcvdbyte
    0101037124  IPsec phase 1 error: remip, reason (failing / unknown peers)

Dial-up (remote-access) tunnels carry an xauth user and FortiOS appends _<n> to the instance name; they are counted
separately and not treated as site-to-site links.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

UP_DOWN, STATS, P1_ERR = "0101037138", "0101037141", "0101037124"
BASE = "category = 'system' AND event_subtype = 'vpn'"
STALE = timedelta(minutes=25)  # > 2 missed statistics intervals


def _kv(name: str) -> str:
    return f"extract(raw, '{name}=\"?([^\" ]*)')"


def _aware(v) -> datetime:
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(str(v).replace("Z", "")).replace(tzinfo=timezone.utc)


DIALUP = f"({_kv('xauthuser')} NOT IN ('', 'N/A') OR match(extract(raw, 'vpntunnel=\"([^\"]*)\"'), '_[0-9]+$'))"
TUNNEL = "extract(raw, 'vpntunnel=\"([^\"]*)\"')"


def _stale_after(times: list[datetime]) -> timedelta:
    """Statistics normally arrive every nextstat (600 s), but some firewalls batch them; allow 3× the observed median
    interval (never less than STALE) before calling a silent tunnel stale."""
    gaps = sorted((b - a).total_seconds() for a, b in zip(times, times[1:]) if (b - a).total_seconds() > 30)
    if not gaps:
        return STALE
    return max(STALE, timedelta(seconds=3 * gaps[len(gaps) // 2]))


def _fw(fw_ids, p) -> str:
    if not fw_ids:
        return ""
    p["fws"] = [int(x) for x in fw_ids]
    return " AND firewall_id IN {fws:Array(UInt32)}"


async def tunnels(ch, t0: datetime, t1: datetime, fw_ids: list[int] | None = None) -> dict:
    p = {"t0": t0, "t1": t1, "lb": t0 - timedelta(days=2)}
    fw = _fw(fw_ids, p)
    tw = "event_time >= {t0:DateTime64(3)} AND event_time < {t1:DateTime64(3)}"
    stats = await ch.aquery(
        f"SELECT firewall_id, any(firewall_name) AS fname, {TUNNEL} AS tunnel, argMax({_kv('remip')}, event_time) AS remip, "
        f"argMax({_kv('locip')}, event_time) AS locip, argMax(extract(raw, 'outintf=\"([^\"]*)\"'), event_time) AS outintf, "
        f"min(event_time) AS first, max(event_time) AS last, count() AS n, "
        f"groupArray((event_time, toUInt64OrZero({_kv('sentbyte')}), toUInt64OrZero({_kv('rcvdbyte')}), toUInt64OrZero({_kv('duration')}))) AS pts "
        f"FROM events WHERE {BASE} AND log_id = '{STATS}' AND {tw}{fw} AND NOT {DIALUP} AND tunnel NOT IN ('', 'N/A') "
        f"GROUP BY firewall_id, tunnel", p)
    changes = await ch.aquery(
        f"SELECT firewall_id, any(firewall_name) AS fname, {TUNNEL} AS tunnel, event_time AS t, extract(raw, 'action=\"([^\"]*)\"') AS act, "
        f"any({_kv('remip')}) AS remip FROM events WHERE {BASE} AND log_id = '{UP_DOWN}' AND event_time >= {{lb:DateTime64(3)}} "
        f"AND event_time < {{t1:DateTime64(3)}}{fw} AND NOT {DIALUP} AND tunnel NOT IN ('', 'N/A') "
        f"GROUP BY firewall_id, tunnel, t, act ORDER BY t", p)
    keys: dict[tuple[int, str], dict] = {}

    def tk(fid, name, fname):
        k = (int(fid), name)
        if k not in keys:
            keys[k] = {"firewall_id": int(fid), "firewall_name": fname, "tunnel": name, "remote_ip": "", "local_ip": "", "interface": "",
                       "events": [], "stats": None}
        return keys[k]
    for r in stats:
        t = tk(r["firewall_id"], r["tunnel"], r["fname"])
        t.update({"remote_ip": r["remip"], "local_ip": r["locip"], "interface": r["outintf"], "stats": r})
    for r in changes:
        t = tk(r["firewall_id"], r["tunnel"], r["fname"])
        t["events"].append((_aware(r["t"]), r["act"]))
        t["remote_ip"] = t["remote_ip"] or r["remip"]
    now = min(t1, datetime.now(timezone.utc))
    span = (t1 - t0).total_seconds()
    out = []
    for t in keys.values():
        st = t.pop("stats")
        evs = t.pop("events")
        last_stat = _aware(st["last"]) if st else None
        # down intervals: tunnel-down → next tunnel-up or next statistics sample
        downs, start = [], None
        before = [a for ts, a in evs if ts < t0]
        if before and before[-1] == "tunnel-down":
            start = t0
        stat_times = sorted(_aware(x[0]) for x in st["pts"]) if st else []
        for ts, act in [e for e in evs if e[0] >= t0]:
            if act == "tunnel-down" and start is None:
                start = ts
            elif act == "tunnel-up" and start is not None:
                downs.append((start, ts))
                start = None
        if start is not None:
            nxt = next((x for x in stat_times if x > start), None)
            downs.append((start, nxt or t1))
        downtime = sum((b - a).total_seconds() for a, b in downs)
        last_change = evs[-1] if evs else None
        if last_change and last_change[1] == "tunnel-down" and (not last_stat or last_stat < last_change[0]):
            status = "down"
        elif last_stat and now - last_stat <= _stale_after(stat_times):
            status = "up"
        elif last_change and last_change[1] == "tunnel-up" and now - last_change[0] <= STALE:
            status = "up"
        else:
            status = "stale"
        # throughput from consecutive cumulative counters (reset when the SA is renegotiated)
        rates, series = [], []
        if st:
            pts = sorted((_aware(a), b, c, d) for a, b, c, d in st["pts"])
            for (ta, sa, ra, _), (tb, sb, rb, _) in zip(pts, pts[1:]):
                dt = (tb - ta).total_seconds()
                if dt <= 0 or sb < sa or rb < ra:
                    continue
                rates.append(((sb - sa) * 8 / dt, (rb - ra) * 8 / dt))
                series.append({"t": tb.isoformat(), "out_bps": round((sb - sa) * 8 / dt), "in_bps": round((rb - ra) * 8 / dt)})
            t["uptime_s"] = int(pts[-1][3]) if pts else None
        t.update({"status": status, "last_stats": last_stat.isoformat() if last_stat else None,
                  "downs": len(downs), "flaps": sum(1 for _, a in evs if a == "tunnel-down" and _ >= t0),
                  "downtime_s": round(downtime), "availability": round(100 * (span - downtime) / span, 4) if span and (st or evs) else None,
                  "last_down": downs[-1][0].isoformat() if downs else None,
                  "avg_in_bps": round(sum(r[1] for r in rates) / len(rates)) if rates else None,
                  "avg_out_bps": round(sum(r[0] for r in rates) / len(rates)) if rates else None,
                  "peak_in_bps": round(max(r[1] for r in rates)) if rates else None,
                  "peak_out_bps": round(max(r[0] for r in rates)) if rates else None,
                  "down_periods": [{"start": a.isoformat(), "end": b.isoformat(), "duration_s": round((b - a).total_seconds())} for a, b in downs][-50:],
                  "series": series[-500:]})
        out.append(t)
    out.sort(key=lambda x: ({"down": 0, "stale": 1, "up": 2}[x["status"]], x["firewall_name"], x["tunnel"]))
    return {"tunnels": out}


async def phase1_failures(ch, t0: datetime, t1: datetime, fw_ids: list[int] | None = None) -> list[dict]:
    """Peers that keep failing IKE phase 1 — misconfigured partners, expired PSKs/certs, or unsolicited scanners."""
    p = {"t0": t0, "t1": t1}
    fw = _fw(fw_ids, p)
    rows = await ch.aquery(
        f"SELECT firewall_id, any(firewall_name) AS fname, {_kv('remip')} AS remip, extract(raw, 'reason=\"([^\"]*)\"') AS reason, "
        f"any(extract(raw, 'outintf=\"([^\"]*)\"')) AS outintf, any({_kv('locip')}) AS locip, count() AS n, min(event_time) AS first, "
        f"max(event_time) AS last, any(src_country) AS country FROM events WHERE {BASE} AND log_id = '{P1_ERR}' "
        f"AND event_time >= {{t0:DateTime64(3)}} AND event_time < {{t1:DateTime64(3)}}{fw} "
        f"GROUP BY firewall_id, remip, reason ORDER BY n DESC LIMIT 100", p)
    return [{"firewall_id": int(r["firewall_id"]), "firewall_name": r["fname"], "remote_ip": r["remip"], "reason": r["reason"],
             "interface": r["outintf"], "local_ip": r["locip"], "count": int(r["n"]), "first": _aware(r["first"]).isoformat(),
             "last": _aware(r["last"]).isoformat(), "country": r["country"]} for r in rows]


async def dialup(ch, t0: datetime, t1: datetime, fw_ids: list[int] | None = None) -> dict:
    p = {"t0": t0, "t1": t1}
    fw = _fw(fw_ids, p)
    rows = await ch.aquery(
        f"SELECT {_kv('xauthuser')} AS u, count() AS sessions, max(event_time) AS last, any({_kv('remip')}) AS remip, any(firewall_name) AS fname "
        f"FROM events WHERE {BASE} AND log_id = '{UP_DOWN}' AND extract(raw, 'action=\"([^\"]*)\"') = 'tunnel-up' AND {DIALUP} "
        f"AND event_time >= {{t0:DateTime64(3)}} AND event_time < {{t1:DateTime64(3)}}{fw} GROUP BY u ORDER BY sessions DESC LIMIT 50", p)
    return {"users": [{"user": r["u"], "sessions": int(r["sessions"]), "last": _aware(r["last"]).isoformat(), "remote_ip": r["remip"],
                       "firewall_name": r["fname"]} for r in rows]}


async def overview(ch, t0: datetime, t1: datetime, fw_ids: list[int] | None = None) -> dict:
    tun = (await tunnels(ch, t0, t1, fw_ids))["tunnels"]
    fails = await phase1_failures(ch, t0, t1, fw_ids)
    dial = await dialup(ch, t0, t1, fw_ids)
    by_reason: dict[str, int] = defaultdict(int)
    for f in fails:
        by_reason[f["reason"] or "unknown"] += f["count"]
    lite = [{k: v for k, v in t.items() if k != "series"} for t in tun]
    return {"window": {"start": t0.isoformat(), "end": t1.isoformat()}, "tunnels": lite, "phase1_failures": fails,
            "failure_reasons": sorted(({"reason": k, "count": v} for k, v in by_reason.items()), key=lambda x: -x["count"]),
            "dialup": dial["users"],
            "totals": {"tunnels": len(tun), "down": sum(1 for t in tun if t["status"] == "down"), "stale": sum(1 for t in tun if t["status"] == "stale"),
                       "flaps": sum(t["flaps"] for t in tun), "phase1_errors": sum(f["count"] for f in fails),
                       "failing_peers": len({f["remote_ip"] for f in fails}), "dialup_users": len(dial["users"])}}
