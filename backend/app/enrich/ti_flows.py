"""Sentinel Grid detection: threat-intelligence indicators matched against flow telemetry (NetFlow / IPFIX / sFlow).

Firewall logs are matched at ingest (rule ti_match); this rule covers what never reaches a firewall log — east-west and
switched traffic, sampled traffic on switches — by matching the flow records' external endpoints against the same
indicator set (enabled feeds, not expired, not marked false positive; IPs and CIDRs).

Data coupling, not code coupling: the rule reads the ClickHouse `flows` table by name (shared event store until the
product databases are separated, docs/architecture/MIGRATION_PLAN.md phase 6). No Sentinel NMS module is imported.
"""
from __future__ import annotations

import ipaddress
from datetime import timedelta

DEFAULT_RULE = {
    "key": "ti_flow_match", "name": "Flow traffic to or from a threat-intel indicator", "severity": "high",
    "mitre": {"tactic": "TA0011", "tactic_name": "Command and Control", "techniques": ["T1071"]},
    "description": "A flow record (NetFlow / IPFIX / sFlow from switches and routers) shows an internal host exchanging traffic with an "
                   "address listed by an enabled threat-intelligence feed. Covers traffic that never passes a logging firewall. "
                   "Sampled telemetry: volumes are estimates, and short contacts can be missed.",
    "params": {"window_minutes": 15, "interval_minutes": 5, "min_bytes": 0, "low_categories": ["hijacked_netblock"], "max_per_run": 50},
}
_ENRICHER = None


def _internal(ip: str, nets: list) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a.version == n.version and a in n for n in nets)


async def rule_ti_flow_match(ch, now, p):
    global _ENRICHER
    from ..alerts.engine import Detection, _dt
    from .enricher import Enricher
    from ..assets import internal_cidrs
    if _ENRICHER is None:
        _ENRICHER = Enricher()
    await _ENRICHER.refresh_ti()
    ti = _ENRICHER.ti
    if not len(ti):
        return []
    nets = [ipaddress.ip_network(c, strict=False) for c in internal_cidrs()]
    t0 = now - timedelta(minutes=int(p.get("window_minutes", 15)))
    rows = await ch.aquery(
        "SELECT src_ip, dst_ip, any(src_port) AS sp, any(dst_port) AS dp, any(proto) AS proto, sum(bytes) AS b, sum(packets) AS pk, count() AS n, "
        "min(ts) AS first, max(ts) AS last, max(sampling) AS smp, groupUniqArray(3)(exporter) AS exs FROM flows "
        "WHERE ts >= {t0:DateTime64(3)} AND ts < {t1:DateTime64(3)} GROUP BY src_ip, dst_ip HAVING b >= {mb:UInt64} LIMIT 300000",
        {"t0": t0, "t1": now, "mb": int(p.get("min_bytes", 0))})
    low = set(p.get("low_categories") or [])
    hits: dict[tuple, dict] = {}
    cache: dict[str, object] = {}
    for r in rows:
        for ext, host, outbound in ((r["dst_ip"], r["src_ip"], True), (r["src_ip"], r["dst_ip"], False)):
            if _internal(ext, nets) or not _internal(host, nets):
                continue
            if ext not in cache:
                cache[ext] = ti.match_ip(ext)
            h = cache[ext]
            if not h:
                continue
            k = (host, h.indicator)
            d = hits.setdefault(k, {"host": host, "ext": ext, "hit": h, "b": 0, "pk": 0, "n": 0, "first": r["first"], "last": r["last"], "smp": 0,
                                    "out": 0, "in": 0, "ports": set(), "exs": set()})
            d["b"] += int(r["b"]); d["pk"] += int(r["pk"]); d["n"] += int(r["n"])  # noqa: E702
            d["first"], d["last"] = min(d["first"], r["first"]), max(d["last"], r["last"])
            d["smp"] = max(d["smp"], int(r["smp"]))
            d["out" if outbound else "in"] += int(r["b"])
            d["ports"].add(int(r["dp"] if outbound else r["sp"]))
            d["exs"].update(r["exs"])
    out = []
    for (host, ind), d in sorted(hits.items(), key=lambda x: -x[1]["b"])[: int(p.get("max_per_run", 50))]:
        h = d["hit"]
        direction = "outbound" if d["out"] >= d["in"] else "inbound"
        out.append(Detection(
            group_key=f"{host}|{ind}"[:255], count=d["n"], first_seen=_dt(d["first"]), last_seen=_dt(d["last"]), src_ip=host, dst_ip=d["ext"],
            severity="medium" if h.category in low else None,
            explanation=(f"{host} exchanged {d['b'] / 1e6:.2f} MB ({direction}) with {d['ext']}, listed as {h.indicator} by '{h.source}' "
                         f"({h.category}); seen in flow telemetry{' (sampled: estimate)' if d['smp'] > 1 else ''}."),
            evidence={"indicator": h.indicator, "feed": h.source, "category": h.category, "external": d["ext"], "bytes": d["b"], "packets": d["pk"],
                      "bytes_out": d["out"], "bytes_in": d["in"], "ports": sorted(d["ports"])[:10], "sampling": d["smp"],
                      "exporters": sorted(d["exs"]), "telemetry": "flows"},
            event_filter={"q": d["ext"], "src_ip": host}))
    return out
