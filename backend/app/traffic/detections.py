"""Traffic security detections (NMS alert rules, registered through alerts/nms.py).

The alert framework provides deduplication (one open alert per group key, updated while the condition continues),
suppression, acknowledgement (status), assignment, notes, notification and maintenance windows. Each rule here
aggregates flows over its window into a few detections — never one per flow — and caps how many it returns.

Sampling: sFlow (and sampled NetFlow / IPFIX) shows a fraction of the packets. Counts of distinct ports / hosts are
therefore lower bounds; byte and packet figures are estimates. Evidence states the sampling rate seen.

Authorised services come from settings (traffic_settings): SNMP managers, DNS resolvers, MQTT brokers / clients and
global exclusions. Rules that depend on such a list stay silent until it is configured, rather than flagging the
monitoring system itself.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta

from sqlalchemy import select

from ..db.models import TrafficRule, TrafficVlanPolicy
from ..db.pg import session_factory
from . import networks as N
from . import registry as R
from .query import Ctx, Filters, Sql
from .settings import load_settings

INSECURE_DEFAULT = ["Telnet", "FTP", "FTP Data", "TFTP", "POP3", "IMAP", "MQTT", "Redis", "CoAP"]
MAX_PER_RUN = 25
# a TCP SYN without ACK is a connection attempt (a probe), not a service in use: scans are the scan rule's business
PROBE = "NOT (proto = 6 AND bitAnd(tcp_flags, 18) = 2)"
TROUBLE = {
    "traffic_unexpected_mqtt": ["Identify the device (MAC, switch port) and whether it should talk MQTT at all",
                                "Add an approved broker / client network under Traffic settings, or block the broker at the firewall"],
    "traffic_unauthorized_snmp": ["Confirm whether the source is a monitoring system; if so add it to the authorised SNMP managers",
                                  "Otherwise restrict SNMP on the devices with an ACL and rotate the community / SNMPv3 credentials"],
    "traffic_excessive_dns": ["Check the client for malware or a misconfigured application (DNS logs: queried names)",
                              "Point clients at the approved resolvers and block outbound DNS at the firewall"],
    "traffic_new_external_destination": ["Review the destination (ASN, country, reverse DNS) and the device that reached it",
                                         "Look at the conversation's ports and volume over time"],
    "traffic_port_scan": ["Find the source device (switch port, wireless client) and the process doing the scan",
                          "If it is an approved scanner, add its address to the rule's allowed sources"],
    "traffic_vlan_policy": ["Check whether the communication is required; if so, add an allow policy for the VLAN pair",
                            "Otherwise fix the inter-VLAN ACL / firewall policy on the gateway"],
    "traffic_insecure_protocol": ["Move the service to its encrypted variant (SSH, SFTP / FTPS, IMAPS, MQTT over TLS)",
                                  "Flow telemetry does not see payloads: confirm on the server before acting"],
    "traffic_custom": ["Review the matching conversations in Application & Protocol Intelligence → Conversations"],
}
DEFAULT_RULES = [
    {"key": "traffic_unexpected_mqtt", "name": "Unexpected MQTT traffic", "severity": "medium", "mitre": {},
     "description": "MQTT (TCP/1883, TCP/8883) to a broker that is not approved, or from a network not allowed to use MQTT "
                    "(Traffic settings → authorised services). Without approved brokers every MQTT conversation is reported.",
     "params": {"window_minutes": 15, "interval_minutes": 5, "min_bytes": 0, "alert_cross_vlan": False, "allow_sources": [], "allow_destinations": []}},
    {"key": "traffic_unauthorized_snmp", "name": "SNMP from an unauthorised manager", "severity": "high", "mitre": {},
     "description": "SNMP requests (UDP/161) from, or traps (UDP/162) to, an address that is not an authorised SNMP manager. "
                    "Silent until the authorised managers are configured, so the monitoring system is never flagged.",
     "params": {"window_minutes": 15, "interval_minutes": 5, "min_targets": 1, "allow_sources": []}},
    {"key": "traffic_excessive_dns", "name": "Excessive or unauthorised DNS", "severity": "medium", "mitre": {},
     "description": "A source sending far more DNS than usual, DNS to a resolver outside the approved list (when configured), or "
                    "unusually large DNS payloads (a tunnelling indicator). Query names and NXDOMAIN rates come from DNS logs (SIEM rules).",
     "params": {"window_minutes": 15, "interval_minutes": 5, "min_packets": 20000, "tunnel_min_bytes": 5_000_000, "tunnel_avg_packet": 400,
                "allow_sources": []}},
    {"key": "traffic_new_external_destination", "name": "High-volume traffic to a new external destination", "severity": "low", "mitre": {},
     "description": "An external address not seen in the baseline period received at least the configured volume, especially when "
                    "a single internal device talks to it. Learning period: no detections until the baseline has enough history.",
     "params": {"window_minutes": 60, "interval_minutes": 30, "baseline_days": 7, "learning_days": 3, "min_bytes": 50_000_000,
                "allow_destinations": []}},
    {"key": "traffic_port_scan", "name": "Possible port or host scan", "severity": "high", "mitre": {},
     "description": "One source reaching many destination ports on one host, or one port on many hosts, with little data per flow. "
                    "Sampled telemetry undercounts distinct ports: thresholds are on what was observed.",
     "params": {"window_minutes": 10, "interval_minutes": 5, "min_ports": 100, "min_hosts": 50, "max_avg_bytes": 2000, "allow_sources": []}},
    {"key": "traffic_vlan_policy", "name": "Inter-VLAN / zone policy violation", "severity": "high", "mitre": {},
     "description": "Traffic between zones or VLANs that a VLAN policy denies (Traffic settings → VLAN policies). Inter-VLAN traffic "
                    "as such is never reported; new VLAN pairs only when enabled in the settings (informational).",
     "params": {"window_minutes": 15, "interval_minutes": 5, "min_bytes": 0, "baseline_days": 7}},
    {"key": "traffic_insecure_protocol", "name": "Unencrypted protocol in use", "severity": "low", "mitre": {},
     "description": "Services of the listed unencrypted protocols (Telnet, FTP, POP3, IMAP, MQTT …), from the port signature, or "
                    "proven by a sampled HTTP request line. The payload is not inspected: encryption is not verified.",
     "params": {"window_minutes": 60, "interval_minutes": 30, "protocols": INSECURE_DEFAULT, "include_http": False, "min_bytes": 0,
                "allow_destinations": []}},
    {"key": "traffic_behaviour_anomaly", "name": "Host or VLAN traffic far outside its normal pattern", "severity": "medium", "mitre": {},
     "description": "The last full hour's upload, download or number of peers of an internal host (or a VLAN) is far above the same hour on "
                    "the previous 14 days (median + k × MAD, silent days counted as zero). No fixed thresholds: each host is compared with "
                    "itself. Learning period: 5 days of history.",
     "params": {"interval_minutes": 30, "k": 6, "factor": 5, "min_upload_bytes": 200_000_000, "min_download_bytes": 1_000_000_000,
                "min_peers": 100, "scopes": ["host", "vlan"], "allow_sources": []}},
    {"key": "traffic_custom", "name": "Custom traffic rule matched", "severity": "medium", "mitre": {},
     "description": "A custom traffic watch rule (Traffic → Rules) matched: protocol / ports / networks / direction above a volume.",
     "params": {"interval_minutes": 5}},
]
AUTO_RESOLVE: set[str] = set()


def _det(key: str, rule: str, explanation: str, first: datetime, last: datetime, *, src: str | None = None, dst: str | None = None,
         count: int = 1, severity: str | None = None, evidence: dict | None = None, flt: dict | None = None, sites: list | None = None):
    from ..alerts.engine import Detection
    ev = {"rule": rule, "troubleshooting": TROUBLE.get(rule, []), **(evidence or {})}
    return Detection(group_key=key[:255], count=max(1, int(count)), first_seen=first, last_seen=last, explanation=explanation,
                     src_ip=src, dst_ip=dst, sites=sites or [], evidence=ev, severity=severity,
                     event_filter={"traffic": {k: v for k, v in (flt or {}).items() if v not in (None, "")}})


def _nets(values) -> list:
    out = []
    for v in values or []:
        try:
            out.append(ipaddress.ip_network(str(v), strict=False))
        except ValueError:
            continue
    return out


def _in(ip: str, nets: list) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a.version == n.version and a in n for n in nets)


async def _ctx() -> tuple[Ctx, dict, list]:
    async with session_factory()() as s:
        st = await load_settings(s)
        reg = await R.load(s)
        nets = await N.load(s)
        pols = (await s.execute(select(TrafficVlanPolicy).where(TrafficVlanPolicy.enabled.is_(True)))).scalars().all()
        rules = (await s.execute(select(TrafficRule).where(TrafficRule.enabled.is_(True)))).scalars().all()
        from .enrich import ip_apps
        ia = await ip_apps(s)
    return Ctx(reg=reg, nets=nets, ip_apps=ia, dedup=st.get("dedup") != "none"), st, [pols, rules]


def _t(v) -> datetime:
    from ..alerts.engine import _dt
    return _dt(v)


def _window(now: datetime, p: dict) -> tuple[datetime, datetime]:
    return now - timedelta(minutes=int(p.get("window_minutes", 15))), now


async def _rows(ch, sql: str, params: dict) -> list[dict]:
    return await ch.aquery(sql, params)


def _where_window() -> str:
    return "ts >= {t0:DateTime64(3)} AND ts < {t1:DateTime64(3)}"


# ------------------------------------------------------------------ 1 MQTT
async def rule_traffic_unexpected_mqtt(ch, now, p):
    ctx, st, _ = await _ctx()
    t0, t1 = _window(now, p)
    q = Sql(ctx, "raw")
    sv, dv = q.src_vlan(), q.dst_vlan()
    rows = await _rows(ch, (
        "SELECT if(dst_port IN (1883, 8883), src_ip, dst_ip) AS client, if(dst_port IN (1883, 8883), dst_ip, src_ip) AS broker, "
        "if(dst_port IN (1883, 8883), dst_port, src_port) AS port, sum(bytes) AS b, sum(packets) AS pk, count() AS n, min(ts) AS first, max(ts) AS last, "
        f"max(sampling) AS smp, any({sv}) AS cv, any({dv}) AS bv, groupUniqArray(3)(exporter) AS exs FROM flows WHERE {_where_window()} AND proto = 6 "
        "AND (dst_port IN (1883, 8883) OR src_port IN (1883, 8883)) GROUP BY client, broker, port HAVING b >= {mb:UInt64} ORDER BY b DESC LIMIT 500"),
        {**q.p, "t0": t0, "t1": t1, "mb": int(p.get("min_bytes", 0))})
    brokers, clients = _nets(st["mqtt_brokers"]), _nets(st["mqtt_clients"])
    excl = _nets(st["detection_exclusions"]) + _nets(p.get("allow_sources")) + _nets(p.get("allow_destinations"))
    out = []
    for r in rows:
        c, b = r["client"], r["broker"]
        if _in(c, excl) or _in(b, excl):
            continue
        reasons = []
        if not _in(b, brokers):
            reasons.append("broker not approved")
        if clients and not _in(c, clients):
            reasons.append("client network not allowed to use MQTT")
        cross = int(r["cv"] or 0) != int(r["bv"] or 0) and int(r["cv"] or 0) and int(r["bv"] or 0)
        if cross and p.get("alert_cross_vlan"):
            reasons.append(f"crosses VLAN {r['cv']} → {r['bv']}")
        if not reasons:
            continue
        ext = not ctx.nets.is_internal(b)
        sev = "high" if ext and int(r["port"]) == 1883 else None
        out.append(_det(f"{c}|{b}|{r['port']}", "traffic_unexpected_mqtt",
                        f"{c} spoke MQTT{' (unencrypted, TCP/1883)' if int(r['port']) == 1883 else ' over TLS (TCP/8883)'} with "
                        f"{'external ' if ext else ''}broker {b}: {', '.join(reasons)}.", _t(r["first"]), _t(r["last"]), src=c, dst=b,
                        count=int(r["n"]), severity=sev,
                        evidence={"bytes": int(r["b"]), "packets": int(r["pk"]), "port": int(r["port"]), "reasons": reasons,
                                  "client_vlan": int(r["cv"] or 0) or None, "broker_vlan": int(r["bv"] or 0) or None, "sampling": int(r["smp"]),
                                  "exporters": r["exs"], "confidence": "port-based", "threshold": {"min_bytes": int(p.get("min_bytes", 0))}},
                        flt={"src": c, "dst": b, "port": int(r["port"])}))
        if len(out) >= MAX_PER_RUN:
            break
    return out


# ------------------------------------------------------------------ 2 SNMP
async def rule_traffic_unauthorized_snmp(ch, now, p):
    ctx, st, _ = await _ctx()
    managers = _nets(st["snmp_managers"]) + _nets(p.get("allow_sources"))
    if not _nets(st["snmp_managers"]):
        return []          # not configured: never flag the monitoring system itself
    t0, t1 = _window(now, p)
    rows = await _rows(ch, (
        "SELECT multiIf(dst_port = 161, src_ip, src_port = 161, dst_ip, dst_ip) AS mgr, toUInt8(dst_port = 162 OR src_port = 162) AS trap, "
        "uniqExact(multiIf(dst_port = 161, dst_ip, src_port = 161, src_ip, src_ip)) AS targets, groupUniqArray(10)(multiIf(dst_port = 161, dst_ip, "
        "src_port = 161, src_ip, src_ip)) AS sample, sum(bytes) AS b, sum(packets) AS pk, count() AS n, min(ts) AS first, max(ts) AS last, "
        f"max(sampling) AS smp FROM flows WHERE {_where_window()} AND proto = 17 AND (dst_port IN (161, 162) OR src_port IN (161, 162)) "
        "GROUP BY mgr, trap ORDER BY targets DESC LIMIT 500"), {"t0": t0, "t1": t1})
    excl = _nets(st["detection_exclusions"])
    out = []
    for r in rows:
        m = r["mgr"]
        if _in(m, managers) or _in(m, excl) or int(r["targets"]) < int(p.get("min_targets", 1)):
            continue
        trap = bool(r["trap"])
        what = f"received SNMP traps from {r['targets']} device(s)" if trap else f"sent SNMP requests to {r['targets']} device(s)"
        out.append(_det(f"{m}|{'trap' if trap else 'poll'}", "traffic_unauthorized_snmp", f"{m} is not an authorised SNMP manager but {what}.",
                        _t(r["first"]), _t(r["last"]), src=None if trap else m, dst=m if trap else None, count=int(r["n"]),
                        evidence={"manager": m, "kind": "trap receiver" if trap else "poller", "targets": int(r["targets"]),
                                  "sample_targets": r["sample"], "bytes": int(r["b"]), "packets": int(r["pk"]), "sampling": int(r["smp"]),
                                  "confidence": "port-based", "threshold": {"min_targets": int(p.get("min_targets", 1))}},
                        flt={"ip": m, "proto": 17, "port": 162 if trap else 161}))
        if len(out) >= MAX_PER_RUN:
            break
    return out


# ------------------------------------------------------------------ 3 DNS
async def rule_traffic_excessive_dns(ch, now, p):
    ctx, st, _ = await _ctx()
    t0, t1 = _window(now, p)
    rows = await _rows(ch, (
        "SELECT src_ip AS client, dst_ip AS resolver, proto, sum(bytes) AS b, sum(packets) AS pk, count() AS n, min(ts) AS first, max(ts) AS last, "
        f"max(sampling) AS smp FROM flows WHERE {_where_window()} AND dst_port = 53 AND proto IN (6, 17) AND {PROBE} GROUP BY client, resolver, proto "
        "ORDER BY pk DESC LIMIT 5000"), {"t0": t0, "t1": t1})
    resolvers = _nets(st["dns_resolvers"])
    excl = _nets(st["detection_exclusions"]) + _nets(p.get("allow_sources"))
    per: dict[str, dict] = {}
    for r in rows:
        c = r["client"]
        if _in(c, excl) or _in(c, resolvers):     # resolvers forwarding upstream are not clients
            continue
        d = per.setdefault(c, {"pk": 0, "b": 0, "n": 0, "first": r["first"], "last": r["last"], "smp": 0, "unauth": {}, "tunnel": []})
        d["pk"] += int(r["pk"])
        d["b"] += int(r["b"])
        d["n"] += int(r["n"])
        d["first"], d["last"] = min(d["first"], r["first"]), max(d["last"], r["last"])
        d["smp"] = max(d["smp"], int(r["smp"]))
        if resolvers and not _in(r["resolver"], resolvers):
            d["unauth"][r["resolver"]] = d["unauth"].get(r["resolver"], 0) + int(r["pk"])
        if int(r["proto"]) == 17 and int(r["b"]) >= int(p.get("tunnel_min_bytes", 5_000_000)) and \
                int(r["b"]) / max(1, int(r["pk"])) >= int(p.get("tunnel_avg_packet", 400)):
            d["tunnel"].append(r["resolver"])
    out = []
    for c, d in sorted(per.items(), key=lambda x: -x[1]["pk"]):
        reasons = []
        if d["pk"] >= int(p.get("min_packets", 20000)):
            reasons.append(f"{d['pk']:,} DNS packets in {p.get('window_minutes', 15)} min")
        if d["unauth"]:
            reasons.append("queries to resolvers outside the approved list: " + ", ".join(sorted(d["unauth"])[:5]))
        if d["tunnel"]:
            reasons.append(f"large DNS payloads ({d['b'] // max(1, d['pk'])} bytes per packet on average) to {', '.join(d['tunnel'][:3])}")
        if not reasons:
            continue
        out.append(_det(f"{c}|dns", "traffic_excessive_dns", f"{c}: " + "; ".join(reasons) + ".", _t(d["first"]), _t(d["last"]), src=c,
                        count=d["n"], severity="high" if d["tunnel"] else None,
                        evidence={"packets": d["pk"], "bytes": d["b"], "flows": d["n"], "unauthorised_resolvers": sorted(d["unauth"])[:10],
                                  "tunnel_indicator": bool(d["tunnel"]), "sampling": d["smp"], "confidence": "port-based",
                                  "threshold": {k: p.get(k) for k in ("min_packets", "tunnel_min_bytes", "tunnel_avg_packet")}},
                        flt={"src": c, "port": 53}))
        if len(out) >= MAX_PER_RUN:
            break
    return out


# ------------------------------------------------------------------ 4 new external destinations
async def rule_traffic_new_external_destination(ch, now, p):
    ctx, st, _ = await _ctx()
    t0, t1 = _window(now, p)
    days, learn = int(p.get("baseline_days", 7)), int(p.get("learning_days", 3))
    oldest = await _rows(ch, "SELECT min(hour) AS h, count() AS n FROM flows_conv_hourly", {})
    if not oldest or not int(oldest[0]["n"]) or _t(oldest[0]["h"]) > now - timedelta(days=learn):
        return []                                    # learning period
    ie, ip_ = ctx.nets.sql_internal("if(server_is_dst = 1, dst_ip, src_ip)", "ext")
    rows = await _rows(ch, (
        "SELECT if(server_is_dst = 1, dst_ip, src_ip) AS dst, sum(bytes) AS b, sum(flows) AS n, uniqExact(if(server_is_dst = 1, src_ip, dst_ip)) AS srcs, "
        "groupUniqArray(5)(if(server_is_dst = 1, src_ip, dst_ip)) AS sample, groupUniqArray(5)(port) AS ports, min(first) AS first, max(last) AS last, "
        f"max(sampling) AS smp FROM flows_conv_hourly WHERE hour >= toStartOfHour({{t0:DateTime64(3)}}) AND hour < {{t1:DateTime64(3)}} AND NOT ({ie}) "
        "GROUP BY dst HAVING b >= {mb:UInt64} ORDER BY b DESC LIMIT 200"),
        {**ip_, "t0": t0, "t1": t1, "mb": int(p.get("min_bytes", 50_000_000))})
    if not rows:
        return []
    cands = [r["dst"] for r in rows]
    seen = {r["dst"] for r in await _rows(ch, (
        "SELECT DISTINCT if(server_is_dst = 1, dst_ip, src_ip) AS dst FROM flows_conv_hourly WHERE hour >= toStartOfHour({b0:DateTime64(3)}) "
        "AND hour < toStartOfHour({t0:DateTime64(3)}) AND if(server_is_dst = 1, dst_ip, src_ip) IN {c:Array(String)}"),
        {"b0": t0 - timedelta(days=days), "t0": t0, "c": cands})}
    excl = _nets(st["detection_exclusions"]) + _nets(p.get("allow_destinations"))
    out = []
    for r in rows:
        d = r["dst"]
        if d in seen or _in(d, excl):
            continue
        b = int(r["b"])
        single = int(r["srcs"]) == 1
        app = ctx.ip_apps.get(d, ("", "", ""))[0]
        out.append(_det(f"{d}|new", "traffic_new_external_destination",
                        f"New external destination {d}{f' ({app})' if app else ''}: {b / 1e6:.1f} MB in {p.get('window_minutes', 60)} min from "
                        f"{r['srcs']} internal device(s){' — only one device talks to it' if single else ''}; not seen in the previous {days} days.",
                        _t(r["first"]), _t(r["last"]), src=r["sample"][0] if single and r["sample"] else None, dst=d, count=int(r["n"]),
                        severity="medium" if b >= 10 * int(p.get("min_bytes", 50_000_000)) or single else None,
                        evidence={"bytes": b, "flows": int(r["n"]), "sources": int(r["srcs"]), "sample_sources": r["sample"], "ports": r["ports"],
                                  "provider": app, "baseline_days": days, "sampling": int(r["smp"]), "confidence": "observed",
                                  "threshold": {"min_bytes": int(p.get("min_bytes", 50_000_000))}},
                        flt={"dst": d}))
        if len(out) >= MAX_PER_RUN:
            break
    return out


# ------------------------------------------------------------------ 5 scans
async def rule_traffic_port_scan(ch, now, p):
    ctx, st, _ = await _ctx()
    t0, t1 = _window(now, p)
    excl = _nets(st["detection_exclusions"]) + _nets(p.get("allow_sources"))
    maxavg = int(p.get("max_avg_bytes", 2000))
    vertical = await _rows(ch, (
        "SELECT src_ip, dst_ip, uniqExact(dst_port) AS ports, min(dst_port) AS lo, max(dst_port) AS hi, count() AS n, sum(bytes) AS b, "
        "countIf(proto = 6 AND bitAnd(tcp_flags, 18) = 2) AS syn, countIf(tcp_flags != 0) AS flagged, min(ts) AS first, max(ts) AS last, "
        f"max(sampling) AS smp FROM flows WHERE {_where_window()} AND proto IN (6, 17) GROUP BY src_ip, dst_ip "
        "HAVING ports >= {mp:UInt32} AND b / n <= {ma:UInt32} ORDER BY ports DESC LIMIT 100"),
        {"t0": t0, "t1": t1, "mp": int(p.get("min_ports", 100)), "ma": maxavg})
    horizontal = await _rows(ch, (
        "SELECT src_ip, dst_port, uniqExact(dst_ip) AS hosts, groupUniqArray(5)(dst_ip) AS sample, count() AS n, sum(bytes) AS b, "
        "countIf(proto = 6 AND bitAnd(tcp_flags, 18) = 2) AS syn, countIf(tcp_flags != 0) AS flagged, min(ts) AS first, max(ts) AS last, "
        f"max(sampling) AS smp FROM flows WHERE {_where_window()} AND proto IN (6, 17) GROUP BY src_ip, dst_port "
        "HAVING hosts >= {mh:UInt32} AND b / n <= {ma:UInt32} ORDER BY hosts DESC LIMIT 100"),
        {"t0": t0, "t1": t1, "mh": int(p.get("min_hosts", 50)), "ma": maxavg})
    out = []
    for r in vertical:
        if _in(r["src_ip"], excl):
            continue
        span = int(r["hi"]) - int(r["lo"]) + 1
        seq = int(r["ports"]) / max(1, span) >= 0.8
        syn = int(r["flagged"]) and int(r["syn"]) / max(1, int(r["flagged"])) >= 0.8
        out.append(_det(f"{r['src_ip']}|v|{r['dst_ip']}", "traffic_port_scan",
                        f"{r['src_ip']} reached {r['ports']} ports on {r['dst_ip']} (ports {r['lo']}–{r['hi']}{', sequential' if seq else ''})"
                        f"{' with SYN-only probes' if syn else ''}.", _t(r["first"]), _t(r["last"]), src=r["src_ip"], dst=r["dst_ip"],
                        count=int(r["n"]), severity="high" if syn or seq else "medium",
                        evidence={"kind": "vertical (ports on one host)", "ports": int(r["ports"]), "port_range": [int(r["lo"]), int(r["hi"])],
                                  "sequential": seq, "syn_only": bool(syn), "avg_bytes": int(r["b"]) // max(1, int(r["n"])), "sampling": int(r["smp"]),
                                  "confidence": "observed", "threshold": {"min_ports": int(p.get("min_ports", 100)), "max_avg_bytes": maxavg}},
                        flt={"src": r["src_ip"], "dst": r["dst_ip"]}))
    for r in horizontal:
        if _in(r["src_ip"], excl):
            continue
        syn = int(r["flagged"]) and int(r["syn"]) / max(1, int(r["flagged"])) >= 0.8
        out.append(_det(f"{r['src_ip']}|h|{r['dst_port']}", "traffic_port_scan",
                        f"{r['src_ip']} reached port {r['dst_port']} on {r['hosts']} hosts{' with SYN-only probes' if syn else ''}.",
                        _t(r["first"]), _t(r["last"]), src=r["src_ip"], count=int(r["n"]), severity="high" if syn else "medium",
                        evidence={"kind": "horizontal (one port on many hosts)", "hosts": int(r["hosts"]), "port": int(r["dst_port"]),
                                  "sample_hosts": r["sample"], "syn_only": bool(syn), "sampling": int(r["smp"]), "confidence": "observed",
                                  "threshold": {"min_hosts": int(p.get("min_hosts", 50)), "max_avg_bytes": maxavg}},
                        flt={"src": r["src_ip"], "port": int(r["dst_port"])}))
    return out[:MAX_PER_RUN]


# ------------------------------------------------------------------ 6 VLAN / zone policies
async def rule_traffic_vlan_policy(ch, now, p):
    ctx, st, (pols, _) = await _ctx()
    if not pols and not st.get("alert_new_vlan_pairs"):
        return []
    t0, t1 = _window(now, p)
    q = Sql(ctx, "raw")
    sv, dv = q.src_vlan(), q.dst_vlan()
    sz, dz = q.net_attr("src_ip", "zone", "sz"), q.net_attr("dst_ip", "zone", "dz")
    si, di = q.internal("src_ip", "s"), q.internal("dst_ip", "d")
    rows = await _rows(ch, (
        f"SELECT {sv} AS svl, {dv} AS dvl, {sz} AS szn, {dz} AS dzn, toUInt8({si}) AS sint, toUInt8({di}) AS dint, sum(bytes) AS b, count() AS n, "
        "uniqExact(src_ip) AS srcs, uniqExact(dst_ip) AS dsts, groupUniqArray(5)(concat(src_ip, ' → ', dst_ip, ':', toString(dst_port))) AS sample, "
        f"min(ts) AS first, max(ts) AS last, max(sampling) AS smp FROM flows WHERE {_where_window()} GROUP BY svl, dvl, szn, dzn, sint, dint "
        "HAVING b >= {mb:UInt64} ORDER BY b DESC LIMIT 1000"), {**q.p, "t0": t0, "t1": t1, "mb": int(p.get("min_bytes", 0))})
    from .analytics import policy_verdict
    out = []
    for r in rows:
        svl, dvl, szn, dzn = int(r["svl"]), int(r["dvl"]), r["szn"], r["dzn"]
        if svl == dvl and szn == dzn and bool(r["sint"]) == bool(r["dint"]):
            continue                                   # same segment: not inter-VLAN
        v = policy_verdict(pols, svl, szn, bool(r["sint"]), dvl, dzn, bool(r["dint"]))
        if not v or v["action"] != "deny":
            continue
        a = f"VLAN {svl}" if svl else (f"zone {szn}" if szn else "unknown segment")
        b = "external" if not r["dint"] else (f"VLAN {dvl}" if dvl else (f"zone {dzn}" if dzn else "unknown segment"))
        out.append(_det(f"pol{v['id']}|{svl}|{szn}|{dvl}|{dzn}|{int(r['dint'])}", "traffic_vlan_policy",
                        f"{a}{f' ({szn})' if szn and svl else ''} → {b}{f' ({dzn})' if dzn and dvl else ''}: denied by policy '{v['name']}' — "
                        f"{r['srcs']} source(s), {r['dsts']} destination(s), {int(r['b']) / 1e6:.2f} MB.", _t(r["first"]), _t(r["last"]),
                        count=int(r["n"]), severity=v["severity"],
                        evidence={"policy": v, "src_vlan": svl or None, "dst_vlan": dvl or None, "src_zone": szn, "dst_zone": dzn,
                                  "sample": r["sample"], "bytes": int(r["b"]), "sampling": int(r["smp"]), "confidence": "observed"},
                        flt={"vlan": svl or None}))
        if len(out) >= MAX_PER_RUN:
            break
    if st.get("alert_new_vlan_pairs") and len(out) < MAX_PER_RUN:
        pairs = {(int(r["svl"]), int(r["dvl"])) for r in rows if int(r["svl"]) and int(r["dvl"]) and int(r["svl"]) != int(r["dvl"])}
        if pairs:
            qb = Sql(ctx, "conv")
            known = {(int(x["a"]), int(x["b"])) for x in await _rows(ch, (
                f"SELECT DISTINCT {qb.src_vlan()} AS a, {qb.dst_vlan()} AS b FROM flows_conv_hourly WHERE hour >= toStartOfHour({{b0:DateTime64(3)}}) "
                "AND hour < toStartOfHour({t0:DateTime64(3)})"), {**qb.p, "b0": t0 - timedelta(days=int(p.get("baseline_days", 7))), "t0": t0})}
            oldest = await _rows(ch, "SELECT min(hour) AS h, count() AS n FROM flows_conv_hourly", {})
            if oldest and int(oldest[0]["n"]) and _t(oldest[0]["h"]) <= now - timedelta(days=int(p.get("baseline_days", 7))):
                for a, b in sorted(pairs - known)[: MAX_PER_RUN - len(out)]:
                    out.append(_det(f"new|{a}|{b}", "traffic_vlan_policy", f"New VLAN pair: VLAN {a} → VLAN {b} was not seen in the baseline.",
                                    t0, t1, severity="informational", evidence={"src_vlan": a, "dst_vlan": b, "kind": "new pair"}, flt={"vlan": a}))
    return out


# ------------------------------------------------------------------ 7 insecure protocols
async def rule_traffic_insecure_protocol(ch, now, p):
    ctx, st, _ = await _ctx()
    t0, t1 = _window(now, p)
    want = set(p.get("protocols") or INSECURE_DEFAULT)
    if p.get("include_http"):
        want.add("HTTP")
    q = Sql(ctx, "raw")
    label, enc = q.port_label(), q.port_enc()
    rows = await _rows(ch, (
        f"SELECT ({label}) AS app, ({enc}) AS enc, {q.t['server']} AS server, any({q.t['port']}) AS port, uniqExact({q.t['client']}) AS clients, "
        f"groupUniqArray(5)({q.t['client']}) AS sample, sum(bytes) AS b, count() AS n, countIf(l7 = 'http') AS http_seen, min(ts) AS first, max(ts) AS last, "
        f"max(sampling) AS smp FROM flows WHERE {_where_window()} AND {PROBE} GROUP BY app, enc, server HAVING app IN {{want:Array(String)}} AND b >= {{mb:UInt64}} "
        "ORDER BY b DESC LIMIT 200"), {**q.p, "t0": t0, "t1": t1, "want": sorted(want), "mb": int(p.get("min_bytes", 0))})
    excl = _nets(st["detection_exclusions"]) + _nets(p.get("allow_destinations"))
    out = []
    for r in rows:
        if int(r["enc"]) == 1 or _in(r["server"], excl):
            continue
        proven = int(r["http_seen"]) > 0
        out.append(_det(f"{r['app']}|{r['server']}", "traffic_insecure_protocol",
                        f"{r['app']} service on {r['server']} (port {r['port']}) used by {r['clients']} client(s)"
                        f"{' — plain-text HTTP request lines seen in samples' if proven else ' (port signature; payload not inspected)'}.",
                        _t(r["first"]), _t(r["last"]), dst=r["server"], count=int(r["n"]),
                        severity="medium" if r["app"] in ("Telnet", "FTP") else None,
                        evidence={"app": r["app"], "port": int(r["port"]), "clients": int(r["clients"]), "sample_clients": r["sample"],
                                  "bytes": int(r["b"]), "sampling": int(r["smp"]), "confidence": "confirmed" if proven else "port-based",
                                  "note": "Flow telemetry does not see payloads; encryption is not verified."},
                        flt={"dst": r["server"], "port": int(r["port"])}))
        if len(out) >= MAX_PER_RUN:
            break
    return out


# ------------------------------------------------------------------ behaviour baselines
async def rule_traffic_behaviour_anomaly(ch, now, p):
    from . import baselines as B
    ctx, st, _ = await _ctx()
    start = await B.history_start(ch)
    if start is None or now - start < timedelta(days=B.LEARNING_DAYS):
        return []                                        # learning period
    hour = B._hour(now) - timedelta(hours=1)             # the last complete hour
    excl = _nets(st["detection_exclusions"]) + _nets(p.get("allow_sources"))
    minimum = {"bytes_out": int(p.get("min_upload_bytes", 2e8)), "bytes_in": int(p.get("min_download_bytes", 1e9)), "peers": int(p.get("min_peers", 100))}
    floor = {"bytes_out": 10_000_000, "bytes_in": 50_000_000, "peers": 10}
    out = []
    for scope in p.get("scopes") or ["host", "vlan"]:
        cur = await B.hourly(ch, scope, None, hour, hour + timedelta(hours=1))
        cands = [k for k, v in cur.items() if any(v[hour][m] >= minimum[m] for m in minimum if hour in v)]
        if scope == "host":
            cands = [k for k in cands if ctx.nets.is_internal(k) and not _in(k, excl)]
        if not cands:
            continue
        hist = await B.hourly(ch, scope, cands[:500], hour - timedelta(days=B.BASELINE_DAYS), hour)
        for key in cands[:500]:
            now_v = cur[key][hour]
            for metric, label in B.METRICS.items():
                base = B.same_hour_history(hist.get(key, {}), hour, metric, B.BASELINE_DAYS, start)
                if len(base) < B.LEARNING_DAYS:
                    continue
                bad, st_ = B.departs(float(now_v[metric]), base, k=float(p.get("k", 6)), factor=float(p.get("factor", 5)), floor=floor[metric],
                                     minimum=minimum[metric])
                if not bad:
                    continue
                unit = (lambda v: f"{v / 1e6:,.0f} MB") if metric != "peers" else (lambda v: f"{v:,.0f}")
                who = key if scope == "host" else f"VLAN {key}"
                out.append(_det(f"{scope}|{key}|{metric}|{hour:%Y%m%d%H}", "traffic_behaviour_anomaly",
                                f"{who}: {label} {unit(now_v[metric])} in the hour from {hour:%H:00} UTC, normally about {unit(st_['median'])} "
                                f"at this hour ({st_['factor']}× usual; expected at most {unit(st_['expected_max'])}).",
                                hour, hour + timedelta(hours=1), src=key if scope == "host" else None, count=1,
                                severity="high" if metric == "bytes_out" and st_["factor"] >= 20 else None,
                                evidence={"scope": scope, "metric": metric, "value": now_v[metric], "baseline_median": st_["median"],
                                          "baseline_mad": st_["mad"], "expected_max": st_["expected_max"], "factor": st_["factor"],
                                          "baseline_days": len(base), "hour": hour.isoformat(), "confidence": "observed",
                                          "threshold": {"k": p.get("k", 6), "factor": p.get("factor", 5), "minimum": minimum[metric]}},
                                flt={"src": key} if scope == "host" else {"vlan": int(key)}))
                if len(out) >= MAX_PER_RUN:
                    return out
    return out


# ------------------------------------------------------------------ custom rules
async def rule_traffic_custom(ch, now, p):
    ctx, st, (_, rules) = await _ctx()
    out = []
    for rule in rules:
        f = Filters(start=now - timedelta(minutes=max(1, min(1440, rule.window_minutes))), end=now,
                    proto=rule.proto, direction=None if rule.direction == "any" else rule.direction)
        q = Sql(ctx, "raw")
        t0, t1 = f.window(now)
        where = q.where(f, t0, t1)
        extra = []
        if rule.ports:
            q.p["cports"] = [int(x) for x in rule.ports][:100]
            extra.append(f"({q.t['port']}) IN {{cports:Array(UInt16)}}")
        for name, col, nets in (("cs", "src_ip", rule.src_cidrs), ("cd", "dst_ip", rule.dst_cidrs)):
            if nets:
                q.p[name] = list(nets)[:100]
                extra.append(f"arrayExists(c -> isIPAddressInRange({col}, c), {{{name}:Array(String)}})")
        if rule.exclude_cidrs:
            q.p["cx"] = list(rule.exclude_cidrs)[:100]
            extra.append("NOT arrayExists(c -> isIPAddressInRange(src_ip, c) OR isIPAddressInRange(dst_ip, c), {cx:Array(String)})")
        cond = " AND ".join([where] + extra)
        rows = await _rows(ch, (f"SELECT src_ip, dst_ip, ({q.t['port']}) AS port, sum(bytes) AS b, count() AS n, min(ts) AS first, max(ts) AS last, "
                                f"max(sampling) AS smp FROM flows WHERE {cond} GROUP BY src_ip, dst_ip, port HAVING b >= {{mb:UInt64}} "
                                "ORDER BY b DESC LIMIT 10"), {**q.p, "mb": int(rule.min_bytes or 0)})
        for r in rows:
            out.append(_det(f"rule{rule.id}|{r['src_ip']}|{r['dst_ip']}|{r['port']}", "traffic_custom",
                            f"Rule '{rule.name}': {r['src_ip']} → {r['dst_ip']} port {r['port']}, {int(r['b']) / 1e6:.2f} MB in {rule.window_minutes} min.",
                            _t(r["first"]), _t(r["last"]), src=r["src_ip"], dst=r["dst_ip"], count=int(r["n"]), severity=rule.severity,
                            evidence={"rule_id": rule.id, "rule": rule.name, "bytes": int(r["b"]), "port": int(r["port"]), "sampling": int(r["smp"]),
                                      "threshold": {"min_bytes": int(rule.min_bytes or 0), "window_minutes": rule.window_minutes}},
                            flt={"src": r["src_ip"], "dst": r["dst_ip"], "port": int(r["port"])}))
            if len(out) >= MAX_PER_RUN:
                return out
    return out


RULES = {d["key"]: globals()[f"rule_{d['key']}"] for d in DEFAULT_RULES}
