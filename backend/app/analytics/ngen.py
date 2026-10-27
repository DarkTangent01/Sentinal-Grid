"""Aggregations for threat intel, geography/ASN and VPN analytics."""
from __future__ import annotations

import asyncio
import ipaddress

from ..alerts.engine import VPN_FAIL, VPN_UP
from ..alerts.travel import find_impossible_travel
from ..db.ch import ClickHouse
from .filters import EventFilter, build_where, table
from .queries import _clean, category_timeseries, bucket_seconds, FILL


async def ti_summary(ch: ClickHouse, f: EventFilter) -> dict:
    where, p = build_where(f, extra=["ti_match != ''"])
    qs = {
        "totals": f"SELECT count() AS events, uniqExact(ti_match) AS indicators, uniqExact(src_ip) AS hosts FROM {table()} WHERE {where}",
        "indicators": f"""SELECT ti_match AS indicator, any(ti_source) AS feed, any(ti_category) AS category, count() AS events,
                          uniqExact(src_ip) AS hosts, groupUniqArray(5)(src_ip) AS sample_hosts, max(event_time) AS last_seen,
                          countIf(action IN ('deny','block')) AS blocked
                          FROM {table()} WHERE {where} GROUP BY indicator ORDER BY events DESC LIMIT 100""",
        "hosts": f"""SELECT src_ip, count() AS events, uniqExact(ti_match) AS indicators, max(event_time) AS last_seen
                     FROM {table()} WHERE {where} AND src_ip != '' GROUP BY src_ip ORDER BY events DESC LIMIT 50""",
        "categories": f"SELECT ti_category AS key, count() AS events FROM {table()} WHERE {where} GROUP BY key ORDER BY events DESC",
    }
    keys = list(qs)
    res = await asyncio.gather(*(ch.aquery(qs[k], p) for k in keys))
    out = {k: _clean(v) for k, v in zip(keys, res)}
    out["totals"] = out["totals"][0] if out["totals"] else {}
    start, end = f.window()
    b = bucket_seconds(start, end)
    p2 = {**p, "b": b}
    out["timeseries"] = {"bucket_seconds": b, "points": _clean(await ch.aquery(
        f"""SELECT toStartOfInterval(event_time, toIntervalSecond({{b:UInt32}})) AS t, count() AS events,
            countIf(action IN ('deny','block')) AS blocked FROM {table()} WHERE {where} GROUP BY t {FILL}""", p2))}
    return out


def parse_indicators(text: str) -> tuple[list[str], list[str], list[str]]:
    ips, nets, doms = [], [], []
    for raw in text.replace(",", "\n").split():
        v = raw.strip().lower()
        if not v:
            continue
        try:
            if "/" in v:
                nets.append(str(ipaddress.ip_network(v, strict=False)))
            else:
                ips.append(str(ipaddress.ip_address(v)))
            continue
        except ValueError:
            pass
        if "." in v and len(v) <= 253:
            doms.append(v.rstrip("."))
    return ips[:5000], nets[:500], doms[:5000]


async def hunt(ch: ClickHouse, f: EventFilter, text: str) -> dict:
    """Retroactive IOC search over stored events (indicators not yet in a feed)."""
    ips, nets, doms = parse_indicators(text)
    if not (ips or nets or doms):
        raise ValueError("no valid IPs, CIDRs or domains")
    conds, p = [], {}
    if ips:
        p["h_ips"] = ips
        conds.append("(src_ip IN {h_ips:Array(String)} OR dst_ip IN {h_ips:Array(String)})")
    if nets:
        p["h_nets"] = nets
        conds.append("(arrayExists(c -> isIPAddressInRange(if(isIPv4String(dst_ip) OR isIPv6String(dst_ip), dst_ip, '::'), c), {h_nets:Array(String)}) "
                     "OR arrayExists(c -> isIPAddressInRange(if(isIPv4String(src_ip) OR isIPv6String(src_ip), src_ip, '::'), c), {h_nets:Array(String)}))")
    if doms:
        p["h_doms"] = doms
        conds.append("(arrayExists(d -> lower(hostname) = d OR endsWith(lower(hostname), concat('.', d)) OR dns_qname = d "
                     "OR endsWith(dns_qname, concat('.', d)), {h_doms:Array(String)}))")
    where, wp = build_where(f, extra=["(" + " OR ".join(conds) + ")"])
    p.update(wp)
    rows = await ch.aquery(f"""SELECT category, src_ip, dst_ip, dst_port, hostname, dns_qname, action, count() AS events,
        min(event_time) AS first_seen, max(event_time) AS last_seen FROM {table()} WHERE {where}
        GROUP BY category, src_ip, dst_ip, dst_port, hostname, dns_qname, action ORDER BY events DESC LIMIT 500""", p)
    return {"indicators": {"ips": len(ips), "cidrs": len(nets), "domains": len(doms)}, "matches": _clean(rows),
            "total_events": sum(int(r["events"]) for r in rows)}


async def geo_summary(ch: ClickHouse, f: EventFilter) -> dict:
    where, p = build_where(f, categories=("traffic",))
    qs = {
        "dst": f"""SELECT dst_country AS country, count() AS events, sum(sent_bytes + rcvd_bytes) AS bytes,
                   countIf(action IN ('deny','block')) AS denied, uniqExact(src_ip) AS hosts
                   FROM {table()} WHERE {where} AND dst_country != '' GROUP BY country ORDER BY events DESC LIMIT 250""",
        "src": f"""SELECT src_country AS country, count() AS events, countIf(action IN ('deny','block')) AS denied,
                   uniqExact(src_ip) AS sources FROM {table()} WHERE {where} AND src_country != '' GROUP BY country ORDER BY events DESC LIMIT 250""",
        "asn": f"""SELECT dst_asn AS asn, any(dst_as_org) AS org, count() AS events, sum(sent_bytes + rcvd_bytes) AS bytes,
                   uniqExact(src_ip) AS hosts FROM {table()} WHERE {where} AND dst_asn > 0 GROUP BY asn ORDER BY bytes DESC LIMIT 50""",
        "coverage": f"""SELECT count() AS events, countIf(dst_country != '') AS with_country, countIf(dst_asn > 0) AS with_asn
                        FROM {table()} WHERE {where}""",
    }
    keys = list(qs)
    res = await asyncio.gather(*(ch.aquery(qs[k], p) for k in keys))
    out = {k: _clean(v) for k, v in zip(keys, res)}
    out["coverage"] = out["coverage"][0] if out["coverage"] else {}
    return out


async def vpn_summary(ch: ClickHouse, f: EventFilter, travel_kmh: float = 900, travel_min_km: float = 500) -> dict:
    where, p = build_where(f, categories=("system",), extra=["event_subtype = 'vpn'"])
    qs = {
        "totals": f"""SELECT countIf({VPN_UP}) AS logins, countIf({VPN_FAIL}) AS failures, uniqExactIf(user, user != '') AS users,
                      uniqExactIf(src_ip, src_ip != '') AS sources, countIf(orig_action = 'tunnel-down') AS logouts FROM {table()} WHERE {where}""",
        "users": f"""SELECT user, countIf({VPN_UP}) AS logins, countIf({VPN_FAIL}) AS failures, uniqExact(src_ip) AS sources,
                     groupUniqArrayIf(5)(src_country, src_country != '') AS countries, max(event_time) AS last_seen,
                     argMax(orig_action, event_time) AS last_action, any(vpn_tunnel) AS tunnel
                     FROM {table()} WHERE {where} AND user != '' GROUP BY user ORDER BY logins + failures DESC LIMIT 200""",
        "failures": f"""SELECT src_ip, any(src_country) AS country, count() AS failures, uniqExact(user) AS users,
                        groupUniqArray(5)(user) AS user_list, max(event_time) AS last_seen
                        FROM {table()} WHERE {where} AND {VPN_FAIL} GROUP BY src_ip ORDER BY failures DESC LIMIT 50""",
        "countries": f"""SELECT src_country AS key, countIf({VPN_UP}) AS logins, countIf({VPN_FAIL}) AS failures
                         FROM {table()} WHERE {where} AND src_country != '' GROUP BY key ORDER BY logins + failures DESC LIMIT 50""",
    }
    keys = list(qs)
    res = await asyncio.gather(*(ch.aquery(qs[k], p) for k in keys))
    out = {k: _clean(v) for k, v in zip(keys, res)}
    out["totals"] = out["totals"][0] if out["totals"] else {}
    out["active"] = [u for u in out["users"] if u.get("last_action") in ("tunnel-up", "ssl-login", "login")]
    out["timeseries"] = await category_timeseries(ch, f, "system")
    start, end = f.window()
    logins = await ch.aquery(f"""SELECT user, event_time, src_ip, src_country, src_lat, src_lon, firewall_id FROM {table()}
        WHERE {where} AND {VPN_UP} AND user != '' ORDER BY user, event_time LIMIT 200000""", p)
    out["impossible_travel"] = find_impossible_travel(logins, max_kmh=travel_kmh, min_km=travel_min_km)
    return out
