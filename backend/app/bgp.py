"""BGP monitoring: neighbor health, flaps, NOTIFICATIONs and route announcements / withdrawals.

Two sources, merged per (firewall, peer):

* Firewall logs (history, no API needed). FortiGate router event logs, e.g.
      0103020300  BGP neighbor status changed  "BGP: %BGP-5-ADJCHANGE: VRF 0 neighbor 169.254.1.1 Down Hold Timer Expired"
      0103020304  Routing log warning          "BGP: %BGP-3-NOTIFICATION: sending to 169.254.1.1 4/0 (Hold Timer Expired/...)"
                                               "BGP: 169.254.1.1-Outgoing [RIB] Withdraw: Can't find route 10.0.0.0/16"
  FortiOS logs neighbor changes when `config router bgp / set log-neighbour-changes enable` (the default). Any other
  system log mentioning BGP and a peer address (PAN-OS routing logs, debug lines) is kept as a generic event.

* Read-only API polling (live state). FortiOS GET /api/v2/monitor/router/bgp/neighbors(6) and /paths(6); PAN-OS
  <show><routing><protocol><bgp><peer>. Every poll stores a sample (state, prefixes received) in bgp_samples. A state
  change becomes a peer_up / peer_down event, and comparing the prefixes received from each peer with the previous
  poll gives route_add / route_withdraw events (bgp_events). The installed BGP routes (FortiOS /monitor/router/ipv4
  ?type=bgp, PAN-OS <show><routing><route>) map each neighbor to its tunnel and give path_change / unreachable events;
  the BGP configuration is read every 6 hours for the audit. Analysis lives in app.bgp_analysis.
"""
from __future__ import annotations

import logging
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from . import bgp_analysis as BA
from .db.models import BgpPeer, BgpRouter, Firewall
from .fortigate.client import FortiGateAuthError, FortiGateError, FortiGateNotSupported
from .vpnmon import _aware, _fw

log = logging.getLogger("bgp")

LOOKBACK = timedelta(days=2)          # state before the window starts
API_FRESH = timedelta(minutes=15)     # an API sample older than this no longer decides the current state
MAX_PATHS = 20_000                    # larger tables are counted, not diffed
MAX_ROUTE_EVENTS = 200                # per peer, kind and poll; the rest is summarised in one event
CONFIG_EVERY = timedelta(hours=6)
EVENT_KINDS = ("peer_down", "peer_up", "notification", "route_add", "route_withdraw", "path_change", "unreachable", "state_change",
               "peer_removed", "new_peer", "bfd_down", "bfd_up", "leak_suspect", "new_prefix", "more_specific", "bogon_prefix",
               "public_via_internal", "default_route", "as_path_change", "fsm", "other")

_IP = r"(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]*:[0-9A-Fa-f:]+)"
_ADJ = re.compile(rf"%BGP-\d-ADJCHANGE:\s*(?:VRF (\S+)\s+)?neighbou?r\s+({_IP})\S*\s+(Up|Down)\b\s*(.*)", re.I)
_NOTIF = re.compile(rf"%BGP-\d-NOTIFICATION:\s*(sending to|sent to|received from)\s+(?:neighbou?r\s+)?({_IP})\s+(\d+)/(\d+)\s*(?:\(([^)]*)\))?", re.I)
_RIB = re.compile(rf"({_IP})-(Outgoing|Incoming)\s+\[(\w+)\]\s+(\w+):?\s*(.*)", re.I)
_RCVD_WD = re.compile(rf"({_IP}) rcvd UPDATE about (\S+) -- withdrawn", re.I)
_RCVD = re.compile(rf"({_IP}) rcvd (\d[\d.]*/\d+|[0-9A-Fa-f:]+/\d+)", re.I)
_FSM = re.compile(rf"({_IP})\S*\s+\[FSM\]\s+(.*)", re.I)
_PREFIX = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}|[0-9A-Fa-f]*:[0-9A-Fa-f:]+/\d{1,3})")
_PEER = re.compile(rf"(?:peer|neighbou?r)\s+(?:address\s+)?({_IP})", re.I)
_UP_WORDS = re.compile(r"\b(established|up)\b", re.I)
_DOWN_WORDS = re.compile(r"\b(down|idle|closed|reset|hold timer expired|disconnected)\b", re.I)


def parse_msg(msg: str) -> dict | None:
    """One BGP / BFD log message → {kind, peer, prefix, direction, detail}; None when it is not about BGP or BFD."""
    low = (msg or "").lower()
    if "bfd" in low and "bgp" not in low:
        m = _PEER.search(msg) or re.search(rf"({_IP})", msg)
        kind = "bfd_down" if _DOWN_WORDS.search(msg) else "bfd_up" if _UP_WORDS.search(msg) else "other"
        return {"kind": kind, "peer": m.group(1) if m else "", "prefix": "", "direction": "", "detail": msg.strip()[:500]}
    if not msg or "bgp" not in low:
        return None
    body = re.sub(r"^\s*BGP:\s*", "", msg).strip()
    m = _ADJ.search(body)
    if m:
        up = m.group(3).lower() == "up"
        reason = m.group(4).strip()
        return {"kind": "peer_up" if up else "peer_down", "peer": m.group(2), "prefix": "", "direction": "",
                "detail": reason or ("neighbor up" if up else "neighbor down")}
    m = _NOTIF.search(body)
    if m:
        sent = not m.group(1).lower().startswith("received")
        text = (m.group(5) or "").strip()
        return {"kind": "notification", "peer": m.group(2), "prefix": "", "direction": "sent" if sent else "received",
                "detail": f"{'sent' if sent else 'received'} {m.group(3)}/{m.group(4)}" + (f" {text}" if text else "")}
    m = _RIB.search(body)
    if m:
        action, rest = m.group(4).lower(), m.group(5).strip()
        kind = "route_withdraw" if action.startswith("withdr") else "route_add" if action in ("announce", "advertise", "update") else "other"
        p = _PREFIX.search(rest)
        return {"kind": kind, "peer": m.group(1), "prefix": p.group(1) if p else "",
                "direction": "sent" if m.group(2).lower() == "outgoing" else "received", "detail": f"[{m.group(3)}] {m.group(4)}: {rest}"}
    m = _RCVD_WD.search(body)
    if m:
        return {"kind": "route_withdraw", "peer": m.group(1), "prefix": m.group(2), "direction": "received", "detail": body}
    m = _RCVD.search(body)
    if m:
        return {"kind": "route_add", "peer": m.group(1), "prefix": m.group(2), "direction": "received", "detail": body}
    m = _FSM.search(body)
    if m:
        return {"kind": "fsm", "peer": m.group(1), "prefix": "", "direction": "", "detail": m.group(2).strip()}
    m = _PEER.search(body)
    peer = m.group(1) if m else ""
    kind = "other"
    if peer and _DOWN_WORDS.search(body):
        kind = "peer_down"
    elif peer and _UP_WORDS.search(body):
        kind = "peer_up"
    return {"kind": kind, "peer": peer, "prefix": "", "direction": "", "detail": body[:500]}


def _established(state: str) -> bool:
    return (state or "").strip().lower() == "established"


# ------------------------------------------------------------------ reporting
async def _log_events(ch, lb: datetime, t1: datetime, p: dict, fw: str) -> list[dict]:
    rows = await ch.aquery(
        "SELECT firewall_id, firewall_name, event_time, log_id, msg FROM events WHERE category = 'system' "
        "AND event_time >= {lb:DateTime64(3)} AND event_time < {t1:DateTime64(3)} "
        "AND (positionCaseInsensitive(msg, 'bgp') > 0 OR positionCaseInsensitive(msg, 'bfd') > 0)"
        f"{fw} ORDER BY event_time LIMIT 50000", {**p, "lb": lb, "t1": t1})
    out = []
    for r in rows:
        ev = parse_msg(r["msg"])
        if ev is None:
            continue
        out.append({**ev, "t": _aware(r["event_time"]), "firewall_id": int(r["firewall_id"]), "firewall_name": r["firewall_name"],
                    "source": "log", "log_id": r["log_id"]})
    return out


async def _api_events(ch, lb: datetime, t1: datetime, p: dict, fw: str) -> list[dict]:
    rows = await ch.aquery(
        "SELECT firewall_id, ts, peer, kind, prefix, detail FROM bgp_events WHERE ts >= {lb:DateTime64(3)} AND ts < {t1:DateTime64(3)}"
        f"{fw} ORDER BY ts LIMIT 50000", {**p, "lb": lb, "t1": t1})
    return [{"t": _aware(r["ts"]), "firewall_id": int(r["firewall_id"]), "peer": r["peer"], "kind": r["kind"], "prefix": r["prefix"],
             "detail": r["detail"], "direction": "received" if r["kind"].startswith("route_") or r["kind"] in BA.SECURITY_KINDS else "",
             "source": "api"} for r in rows]


def _merge_duplicates(events: list[dict]) -> list[dict]:
    """FortiOS logs one ADJCHANGE line per reason for a single drop ("Hold Timer Expired" and "FSM-ERR" in the same
    second): merge same-kind up/down events for a peer within 2 s into one, keeping every reason."""
    out: list[dict] = []
    last: dict[tuple, dict] = {}
    for e in events:
        k = (e["firewall_id"], e["peer"], e["kind"], e["source"])
        prev = last.get(k)
        if e["kind"] in ("peer_down", "peer_up") and prev is not None and (e["t"] - prev["t"]).total_seconds() <= 2:
            if e["detail"] and e["detail"] not in prev["detail"].split("; "):  # sorted: same-millisecond lines arrive in any order
                prev["detail"] = "; ".join(sorted(filter(None, prev["detail"].split("; ") + [e["detail"]])))
            continue
        last[k] = e
        out.append(e)
    return out


def _bucket(t0: datetime, t1: datetime) -> int:
    span = (t1 - t0).total_seconds()
    return next((b for b in (60, 300, 900, 1800, 3600, 10800, 21600) if span / b <= 200), 86400)


async def report(ch, s, t0: datetime, t1: datetime, fw_ids: list[int] | None = None, peer: str | None = None,
                 correlate: bool = False) -> dict:
    p: dict = {}
    fw = _fw(fw_ids, p)
    lb = t0 - LOOKBACK
    log_evs = await _log_events(ch, lb, t1, p, fw)
    api_evs = await _api_events(ch, lb, t1, p, fw)
    names = {f.id: f.name for f in (await s.execute(select(Firewall))).scalars()}
    q = select(BgpPeer)
    if fw_ids:
        q = q.where(BgpPeer.firewall_id.in_([int(x) for x in fw_ids]))
    api_peers = {(b.firewall_id, b.peer_ip): b for b in (await s.execute(q)).scalars()}
    for e in api_evs:
        e["firewall_name"] = names.get(e["firewall_id"], f"#{e['firewall_id']}")
    for e in log_evs:
        e["firewall_name"] = names.get(e["firewall_id"]) or e["firewall_name"]
    events = _merge_duplicates(sorted(log_evs + api_evs, key=lambda e: e["t"]))
    if peer:
        events = [e for e in events if e["peer"] == peer]
        api_peers = {k: v for k, v in api_peers.items() if k[1] == peer}

    now = min(t1, datetime.now(timezone.utc))
    span = (t1 - t0).total_seconds()
    peers: dict[tuple[int, str], dict] = {}

    def pk(fid: int, ip: str, fname: str = "") -> dict:
        k = (fid, ip)
        if k not in peers:
            peers[k] = {"firewall_id": fid, "firewall_name": names.get(fid) or fname or f"#{fid}", "peer": ip, "remote_as": None, "local_ip": "",
                        "state": "", "admin_status": "", "prefixes": None, "state_since": None, "last_polled_at": None,
                        "_log": [], "_api": [], "_bfd": [], "_counts": defaultdict(int), "last_event": None, "last_reason": "",
                        "interface": "", "description": "", "bfd_enabled": None, "first_seen": None}
        return peers[k]

    for (fid, ip), b in api_peers.items():
        x = pk(fid, ip)
        cfg = b.config or {}
        x.update({"remote_as": b.remote_as, "local_ip": b.local_ip, "state": b.state, "admin_status": b.admin_status,
                  "prefixes": b.prefixes, "state_since": _aware(b.state_since) if b.state_since else None,
                  "last_polled_at": _aware(b.last_polled_at) if b.last_polled_at else None, "interface": b.interface or cfg.get("interface", ""),
                  "description": cfg.get("description", ""), "bfd_enabled": cfg.get("bfd"), "first_seen": _aware(b.first_seen).isoformat()})
    for e in events:
        if not e["peer"]:
            continue
        x = pk(e["firewall_id"], e["peer"], e["firewall_name"])
        if e["kind"] in ("peer_up", "peer_down"):
            x["_log" if e["source"] == "log" else "_api"].append((e["t"], e["kind"], e["detail"]))
        elif e["kind"] == "bfd_down":
            x["_bfd"].append(e["t"])
        if e["t"] >= t0:
            x["_counts"][e["kind"]] += 1
            x["last_event"] = e["t"]
            if e["kind"] in ("peer_down", "notification"):
                x["last_reason"] = e["detail"]

    out = []
    for x in peers.values():
        # logs carry exact transition times; API transitions are only as precise as the poll interval
        log_trans, api_trans = x.pop("_log"), x.pop("_api")
        # FortiOS logs one ADJCHANGE line per reason ("Hold Timer Expired" and "FSM-ERR" in the same second): a
        # transition only counts when the state actually changes
        trans = []
        for tr in log_trans or api_trans:
            if not trans or trans[-1][1] != tr[1]:
                trans.append(tr)
        counts = x.pop("_counts")
        bfd_times = x.pop("_bfd")
        downs, start = [], None
        before = [k for t, k, _ in trans if t < t0]
        if before and before[-1] == "peer_down":
            start = t0
        for t, k, _ in [tr for tr in trans if tr[0] >= t0]:
            if k == "peer_down" and start is None:
                start = t
            elif k == "peer_up" and start is not None:
                downs.append((start, t))
                start = None
        fresh = x["last_polled_at"] is not None and now - x["last_polled_at"] <= API_FRESH
        if fresh:
            status = "up" if _established(x["state"]) else "admin_down" if x["admin_status"].lower() in ("down", "disable", "false") else "down"
        elif trans:
            status = "up" if trans[-1][1] == "peer_up" else "down"
        else:
            status = "unknown"
        if start is not None:  # still down per the logs, unless a fresh API sample shows it re-established since
            end = max(start, x["state_since"]) if status == "up" and x["state_since"] else now
            downs.append((start, end))
        if status == "down" and not downs and fresh and x["state_since"]:
            downs.append((max(t0, x["state_since"]), now))
        downtime = sum((b - a).total_seconds() for a, b in downs)
        since = x["state_since"] if fresh else (trans[-1][0] if trans else None)
        x.update({
            "status": status, "state": x["state"] or ({"up": "Established", "down": "Down"}.get(status, "")),
            "since": since.isoformat() if since else None,
            "flaps": sum(1 for t, k, _ in trans if k == "peer_down" and t >= t0), "notifications": counts["notification"],
            "routes_added": counts["route_add"], "routes_withdrawn": counts["route_withdraw"],
            "downtime_s": round(downtime), "availability": round(100 * (span - downtime) / span, 4) if span and (trans or fresh) else None,
            "last_down": downs[-1][0].isoformat() if downs else None,
            "down_periods": [{"start": a.isoformat(), "end": b.isoformat(), "duration_s": round((b - a).total_seconds()),
                              "ongoing": b == now and status == "down",
                              "reason": next((d for t, k, d in trans if k == "peer_down" and t == a), ""),
                              "bfd_before": any(timedelta(0) <= a - bt <= timedelta(seconds=10) for bt in bfd_times)}
                             for a, b in downs][-100:],
            "path_changes": counts["path_change"] + counts["unreachable"], "bfd_events": counts["bfd_down"] + counts["bfd_up"],
            "security_events": sum(counts[k] for k in BA.SECURITY_KINDS),
            "last_event": x["last_event"].isoformat() if x["last_event"] else None,
            "last_polled_at": x["last_polled_at"].isoformat() if x["last_polled_at"] else None,
            "state_since": x["state_since"].isoformat() if x["state_since"] else None,
            "source": "api+log" if x["last_polled_at"] and log_trans else "api" if x["last_polled_at"] else "log",
        })
        x.update(BA.reliability(span, x["down_periods"], x["flaps"]))
        out.append(x)
    # neighbors that are another monitored firewall (one side's peer address is the other side's local address)
    by_local = {(x["local_ip"]): x for x in out if x["local_ip"]}
    for x in out:
        y = by_local.get(x["peer"])
        x["remote_firewall_id"] = y["firewall_id"] if y and y["firewall_id"] != x["firewall_id"] else None
        x["remote_firewall_name"] = y["firewall_name"] if x["remote_firewall_id"] else ""
    base = await BA.baselines(ch, [(x["firewall_id"], x["peer"]) for x in out], datetime.now(timezone.utc))
    for x in out:
        bl = base.get((x["firewall_id"], x["peer"]))
        x["baseline"] = bl
        x["prefix_anomaly"] = x["status"] == "up" and BA.is_anomalous(bl)
    if correlate:
        drops = [dict(d, firewall_id=x["firewall_id"], interface=x["interface"], peer=x["peer"]) for x in out for d in x["down_periods"]]
        await BA.correlate(ch, s, sorted({d["firewall_id"] for d in drops}), t0, t1, drops)
        it = iter(drops)
        for x in out:
            for d in x["down_periods"]:
                c = next(it)
                d["verdict"], d["causes"] = c.get("verdict"), c.get("causes", [])
    order = {"down": 0, "unknown": 1, "admin_down": 2, "up": 3}
    out.sort(key=lambda x: (order.get(x["status"], 9), -x["flaps"], x["firewall_name"], x["peer"]))

    win = [e for e in events if e["t"] >= t0]
    b = _bucket(t0, t1)
    series: dict[int, dict] = {}
    for e in win:
        k = int(e["t"].timestamp()) // b * b
        row = series.setdefault(k, {"t": datetime.fromtimestamp(k, timezone.utc).isoformat(), **{x: 0 for x in EVENT_KINDS}})
        row[e["kind"]] = row.get(e["kind"], 0) + 1
    reasons: dict[str, int] = defaultdict(int)
    for e in win:
        if e["kind"] == "peer_down":
            for r in (e["detail"] or "unspecified").split("; "):
                reasons[r] += 1
    recent = [{"t": e["t"].isoformat(), "firewall_id": e["firewall_id"], "firewall_name": e["firewall_name"], "peer": e["peer"],
               "kind": e["kind"], "prefix": e["prefix"], "direction": e["direction"], "detail": e["detail"], "source": e["source"]}
              for e in reversed(win[-1000:])]
    return {
        "window": {"start": t0.isoformat(), "end": t1.isoformat()}, "bucket_seconds": b,
        "peers": out, "events": recent, "timeline": [series[k] for k in sorted(series)],
        "down_reasons": sorted(({"reason": k, "count": v} for k, v in reasons.items()), key=lambda r: -r["count"]),
        "totals": {"peers": len(out), "up": sum(1 for x in out if x["status"] == "up"), "down": sum(1 for x in out if x["status"] == "down"),
                   "unknown": sum(1 for x in out if x["status"] in ("unknown", "admin_down")),
                   "flaps": sum(x["flaps"] for x in out), "notifications": sum(x["notifications"] for x in out),
                   "routes_added": sum(x["routes_added"] for x in out), "routes_withdrawn": sum(x["routes_withdrawn"] for x in out),
                   "path_changes": sum(x["path_changes"] for x in out), "security_events": sum(x["security_events"] for x in out),
                   "prefix_anomalies": sum(1 for x in out if x["prefix_anomaly"]),
                   "firewalls": len({x["firewall_id"] for x in out}), "events": len(win)},
    }


async def peer_detail(ch, s, fw_id: int, peer: str, t0: datetime, t1: datetime) -> dict | None:
    rep = await report(ch, s, t0, t1, [fw_id], peer, correlate=True)
    if not rep["peers"]:
        return None
    x = rep["peers"][0]
    b = rep["bucket_seconds"]
    rows = await ch.aquery(
        "SELECT toStartOfInterval(ts, toIntervalSecond({b:UInt32})) AS t, max(prefixes) AS prefixes, min(up) AS up FROM bgp_samples "
        "WHERE firewall_id = {f:UInt32} AND peer = {p:String} AND ts >= {t0:DateTime64(3)} AND ts < {t1:DateTime64(3)} GROUP BY t ORDER BY t",
        {"b": b, "f": fw_id, "p": peer, "t0": t0, "t1": t1})
    b_peer = (await s.execute(select(BgpPeer).where(BgpPeer.firewall_id == fw_id, BgpPeer.peer_ip == peer))).scalars().first()
    router = await s.get(BgpRouter, fw_id)
    findings = [f for f in (router.audit or []) if f["peer"] == peer] if router else []
    rib = sorted(pre for pre, paths in ((router.rib or {}) if router else {}).items() if any(p["peer"] == peer for p in paths))
    return {**x, "events": rep["events"], "timeline": rep["timeline"], "bucket_seconds": b,
            "samples": [{"t": _aware(r["t"]).isoformat(), "prefixes": r["prefixes"], "up": int(r["up"])} for r in rows],
            "time_in_state": await BA.time_in_state(ch, fw_id, peer, t0, t1), "state_hint": BA.STATE_HINTS.get((x["state"] or "").lower(), ""),
            "config": (b_peer.config if b_peer else None) or {}, "audit": findings,
            "received": (b_peer.routes or [])[:2000] if b_peer else [], "installed": rib[:2000]}


# ------------------------------------------------------------------ polling (read-only)
def _first(d: dict, *keys, default=None):
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return v
    return default


def _prefix(pre, ln) -> str:
    return f"{pre}/{ln}" if ln is not None and "/" not in str(pre) else str(pre)


async def _fortigate_poll(fw, want_config: bool) -> dict:
    """Neighbors, received prefixes per neighbor, installed BGP routes and (when due) the BGP configuration. GET only."""
    from .fortigate.service import build_client
    client = build_client(fw)
    out: dict = {"peers": [], "rib": None, "config": None}
    try:
        neigh: list = []
        for path in ("/api/v2/monitor/router/bgp/neighbors", "/api/v2/monitor/router/bgp/neighbors6"):
            try:
                neigh += (await client.get(path)).get("results") or []
            except FortiGateNotSupported:
                if path.endswith("neighbors"):
                    raise
        routes: dict[str, set[str]] | None = defaultdict(set)
        for path in ("/api/v2/monitor/router/bgp/paths", "/api/v2/monitor/router/bgp/paths6"):
            try:
                paths = (await client.get(path, {"count": MAX_PATHS})).get("results") or []
            except FortiGateError:
                continue
            if len(paths) >= MAX_PATHS:
                routes = None
                break
            for pth in paths:
                frm = str(_first(pth, "learned_from", "peer", "from", default=""))
                pre = _first(pth, "nlri_prefix", "prefix", "network")
                if frm and pre:
                    routes[frm].add(_prefix(pre, _first(pth, "nlri_prefix_len", "prefix_len", "prefixlen")))
        rib: dict[str, list] | None = defaultdict(list)
        for path in ("/api/v2/monitor/router/ipv4", "/api/v2/monitor/router/ipv6"):
            try:
                rows = (await client.get(path, {"type": "bgp", "count": MAX_PATHS})).get("results") or []
            except FortiGateError:
                if path.endswith("ipv4"):
                    rib = None
                    break
                continue
            if len(rows) >= MAX_PATHS:
                rib = None
                break
            for r in rows:
                pre = str(_first(r, "ip_mask", "ip_prefix", default=""))
                if not pre:
                    continue
                inst = r.get("install_date")
                rib[pre].append({"peer": str(_first(r, "non_rc_gateway", "gateway", default="")), "interface": str(r.get("interface") or ""),
                                 "gateway": str(r.get("gateway") or ""),
                                 "installed": datetime.fromtimestamp(int(inst), timezone.utc).isoformat() if str(inst or "").isdigit() else None})
        out["rib"] = dict(rib) if rib is not None else None
        if want_config:
            try:
                r = (await client.get("/api/v2/cmdb/router/bgp")).get("results")
                out["config"] = BA.sanitize_fortigate_config(r[0] if isinstance(r, list) and r else r or {})
            except FortiGateError as e:
                log.info("bgp config read failed for %s: %s", fw.name, e)
    finally:
        await client.close()
    for n in neigh:
        ip = str(_first(n, "neighbor_ip", "neighbor", "ip", default=""))
        if not ip:
            continue
        r = None if routes is None else routes.get(ip, set())
        ras = _first(n, "remote_as", "remote-as")
        admin = _first(n, "admin_status", default="")
        out["peers"].append({"peer": ip, "remote_as": int(ras) if str(ras or "").isdigit() else None, "local_ip": str(_first(n, "local_ip", default="")),
                             "peer_type": str(_first(n, "type", default="")), "state": str(_first(n, "state", "status", default="unknown")),
                             "admin_status": ("up" if admin else "down") if isinstance(admin, bool) else str(admin),
                             "uptime_s": None, "routes": r, "prefixes": len(r) if r is not None else None})
    return out


PAN_BGP_PEERS = "<show><routing><protocol><bgp><peer></peer></bgp></protocol></routing></show>"


def _host(addr: str) -> str:
    """'10.0.0.1:179' / '[2001:db8::1]:179' / bare address → address."""
    if addr.startswith("["):
        return addr[1:addr.find("]")] if "]" in addr else addr[1:]
    return addr.rsplit(":", 1)[0] if addr.count(":") == 1 else addr


def parse_pan_peers(root) -> list[dict]:
    from .paloalto import _t
    out = []
    for e in root.findall("./result/entry"):
        ip = _host(_t(e, "peer-address"))
        if not ip:
            continue
        pref = 0
        seen = False
        for c in e.findall("./prefix-counter/entry"):
            v = _t(c, "incoming-accepted")
            if v.isdigit():
                pref += int(v)
                seen = True
        dur = _t(e, "status-duration")
        ras = _t(e, "remote-as")
        out.append({"peer": ip, "remote_as": int(ras) if ras.isdigit() else None, "local_ip": _host(_t(e, "local-address")),
                    "peer_type": "", "state": _t(e, "status") or "unknown", "admin_status": "",
                    "uptime_s": int(dur) if dur.isdigit() else None, "routes": None, "prefixes": pref if seen else None})
    return out


PAN_BGP_ROUTES = "<show><routing><route><type>bgp</type></route></routing></show>"


def parse_pan_rib(root) -> dict:
    from .paloalto import _t
    rib: dict[str, list] = defaultdict(list)
    for e in root.findall("./result/entry"):
        pre = _t(e, "destination")
        if pre:
            rib[pre].append({"peer": _t(e, "nexthop"), "interface": _t(e, "interface"), "gateway": _t(e, "nexthop"), "installed": None})
    return dict(rib)


async def _pan_poll(fw, want_config: bool) -> dict:
    from .paloalto import client_for
    async with client_for(fw) as c:
        out = {"peers": parse_pan_peers(await c.op(PAN_BGP_PEERS)), "rib": None, "config": None}
        try:
            out["rib"] = parse_pan_rib(await c.op(PAN_BGP_ROUTES))
        except FortiGateError:
            pass
        if want_config:
            try:
                root = await c.config_get("/config/devices/entry/network/virtual-router")
                vrs = root.findall(".//virtual-router/entry")
                vr = next((v for v in vrs if v.find("./protocol/bgp") is not None), None)
                out["config"] = BA.sanitize_pan_config(vr)
            except FortiGateError as e:
                log.info("bgp config read failed for %s: %s", fw.name, e)
    return out


def diff_peers(existing: dict[str, BgpPeer], polled: list[dict], fw_id: int, now: datetime) -> tuple[list[dict], list[str], dict]:
    """Update peer rows in place; return (bgp_events rows, peer IPs that disappeared, {peer: (added, removed)})."""
    events: list[dict] = []
    deltas: dict[str, tuple[set, set]] = {}

    def ev(peer, kind, detail, prefix=""):
        events.append({"ts": now, "firewall_id": fw_id, "peer": peer, "kind": kind, "prefix": prefix, "detail": detail})

    for n in polled:
        b = existing[n["peer"]]
        known = b.last_polled_at is not None
        if known and b.state != n["state"]:
            was, up = _established(b.state), _established(n["state"])
            kind = "peer_up" if up else "peer_down" if was else "state_change"
            ev(n["peer"], kind, f"{b.state} → {n['state']}")
            b.state_since = now
        elif b.state_since is None:  # first sight: in this state at least since now (FortiOS reports no uptime)
            b.state_since = now - timedelta(seconds=n["uptime_s"]) if n.get("uptime_s") else now
        new = n["routes"]
        if new is not None and b.routes is not None and not b.routes_truncated:
            old = set(b.routes)
            deltas[n["peer"]] = (new - old, old - new)
            for kind, delta in (("route_add", sorted(new - old)), ("route_withdraw", sorted(old - new))):
                for pre in delta[:MAX_ROUTE_EVENTS]:
                    ev(n["peer"], kind, "", pre)
                if len(delta) > MAX_ROUTE_EVENTS:
                    ev(n["peer"], kind, f"and {len(delta) - MAX_ROUTE_EVENTS} more prefixes in this poll")
        b.routes = sorted(new) if new is not None else None
        b.routes_truncated = new is None
        b.state = n["state"]
        b.remote_as = n["remote_as"] if n["remote_as"] is not None else b.remote_as
        b.local_ip = n["local_ip"] or b.local_ip
        b.peer_type = n["peer_type"] or b.peer_type
        b.admin_status = n["admin_status"]
        b.prefixes = n["prefixes"]
        b.last_polled_at = now
    gone = [ip for ip in existing if ip not in {n["peer"] for n in polled}]
    for ip in gone:
        ev(ip, "peer_removed", "no longer configured on the firewall")
    return events, gone, deltas


def _interface_for(n: dict, rib: dict | None, ifaces: list) -> str:
    """Tunnel / port a session runs over: from installed routes via the neighbor, else the interface owning the local IP."""
    for paths in (rib or {}).values():
        for p in paths:
            if p["peer"] == n["peer"] and p.get("interface"):
                return p["interface"]
    local = n.get("local_ip") or ""
    if local in ("", "0.0.0.0", "::"):  # session never came up: no local address to match (and HA ports report 0.0.0.0)
        return ""
    for it in ifaces or []:
        if isinstance(it, dict) and it.get("ip") and str(it["ip"]).split("/")[0] == local:
            return str(it.get("name") or "")
    return ""


async def poll(fw, s, ch) -> None:
    """Poll one firewall's BGP neighbors, routes and (every 6 h) configuration (GET / <show> only); record samples,
    peer / route / path / security events and the configuration audit."""
    now = datetime.now(timezone.utc)
    health = dict(fw.health or {})
    router = await s.get(BgpRouter, fw.id)
    want_config = router is None or router.config_polled_at is None or now - _aware(router.config_polled_at) >= CONFIG_EVERY
    try:
        data = await (_pan_poll(fw, want_config) if fw.vendor == "paloalto" else _fortigate_poll(fw, want_config))
    except FortiGateNotSupported as e:
        health["bgp"] = {"unsupported": "not_found", "detail": str(e)[:200]}
        fw.health = health
        return
    except FortiGateAuthError as e:
        if e.status == 403:
            health["bgp"] = {"unsupported": "forbidden", "detail": "API profile needs read access to router monitoring"}
            fw.health = health
        return
    except FortiGateError as e:
        log.info("bgp poll failed for %s: %s", fw.name, e)
        return
    polled = data["peers"]
    if router is None:
        router = BgpRouter(firewall_id=fw.id)
        s.add(router)
    if data["config"] is not None:
        router.config, router.config_polled_at = data["config"], now
        router.local_as, router.router_id = data["config"].get("local_as"), data["config"].get("router_id", "")
    cfg = router.config or {}
    existing = {b.peer_ip: b for b in (await s.execute(select(BgpPeer).where(BgpPeer.firewall_id == fw.id))).scalars()}
    events: list[dict] = []
    had_peers = bool(existing)
    for n in polled:
        if n["peer"] not in existing:
            b = BgpPeer(firewall_id=fw.id, peer_ip=n["peer"], first_seen=now, state=n["state"])
            s.add(b)
            existing[n["peer"]] = b
            if had_peers:
                events.append({"ts": now, "firewall_id": fw.id, "peer": n["peer"], "kind": "new_peer", "prefix": "",
                               "detail": f"new BGP neighbor AS {n['remote_as'] or '?'} ({n['state']})"})
    first_seen = {ip: b.first_seen for ip, b in existing.items()}
    known_before = {ip: dict(b.known_prefixes or {}) for ip, b in existing.items()}
    ev, gone, deltas = diff_peers(existing, polled, fw.id, now)
    events += ev
    own = [n for n in (BA._net(x) for x in cfg.get("networks", [])) if n]
    for ip, (added, removed) in deltas.items():
        events += BA.security_events(existing[ip], added, removed, known_before.get(ip, {}), first_seen.get(ip), own, fw.id, now)
    for n in polled:
        b = existing[n["peer"]]
        if n["routes"] is not None:
            b.known_prefixes = BA.update_known(b.known_prefixes, n["routes"], now)
        found = _interface_for(n, data["rib"], (health.get("interfaces") if isinstance(health.get("interfaces"), list) else []))
        # keep the last known tunnel while routes are temporarily gone; a session that never came up has none to keep
        b.interface = found or (b.interface if n.get("local_ip") not in ("", "0.0.0.0", "::") else "")
        if cfg.get("neighbors", {}).get(n["peer"]) is not None:
            b.config = cfg["neighbors"][n["peer"]]
    for ip in gone:
        await s.delete(existing[ip])
    if data["rib"] is not None:
        events += BA.rib_diff(router.rib, data["rib"], fw.id, now)
        router.rib, router.rib_polled_at = data["rib"], now
    router.audit = BA.audit(cfg, [{"peer": n["peer"], "state": n["state"], "state_since": existing[n["peer"]].state_since,
                                   "prefixes": n["prefixes"], "interface": existing[n["peer"]].interface} for n in polled], now)
    health["bgp"] = {"peers": len(polled), "established": sum(1 for n in polled if _established(n["state"])), "polled_at": now.isoformat(),
                     "routes": len(data["rib"] or {}), "audit_findings": len(router.audit)}
    fw.health = health
    samples = [{"ts": now.replace(microsecond=0), "firewall_id": fw.id, "peer": n["peer"], "state": n["state"],
                "up": 1 if _established(n["state"]) else 0, "prefixes": n["prefixes"]} for n in polled]
    if samples:
        await ch.ainsert("bgp_samples", samples, ["ts", "firewall_id", "peer", "state", "up", "prefixes"])
    if events:
        await ch.ainsert("bgp_events", events, ["ts", "firewall_id", "peer", "kind", "prefix", "detail"])


# ------------------------------------------------------------------ analysis views
async def _window_events(ch, s, t0: datetime, t1: datetime, fw_ids: list[int] | None) -> tuple[list[dict], dict[int, str]]:
    p: dict = {}
    fw = _fw(fw_ids, p)
    names = {f.id: f.name for f in (await s.execute(select(Firewall))).scalars()}
    evs = await _log_events(ch, t0, t1, p, fw) + await _api_events(ch, t0, t1, p, fw)
    for e in evs:
        e["firewall_name"] = names.get(e["firewall_id"]) or e.get("firewall_name") or f"#{e['firewall_id']}"
    return _merge_duplicates(sorted(evs, key=lambda e: e["t"])), names


async def _critical_nets(s, name: str) -> tuple[bool, list]:
    from .watchlists import load_watchlists
    wl = (await load_watchlists(s, [name])).get(name)
    if not wl:
        return False, []
    return True, [n for n in (BA._net(v) for v in wl["values"]) if n]


async def prefixes_report(ch, s, t0: datetime, t1: datetime, fw_ids: list[int] | None = None,
                          watchlist: str = "bgp_critical_prefixes") -> dict:
    """Installed BGP routes (which neighbor / tunnel each prefix uses, ECMP, route age) and prefix stability."""
    events, names = await _window_events(ch, s, t0, t1, fw_ids)
    now = datetime.now(timezone.utc)
    stab = BA.prefix_stability(events, now)
    by_key = {(x["firewall_id"], x["prefix"]): x for x in stab}
    exists, crit = await _critical_nets(s, watchlist)
    q = select(BgpRouter)
    if fw_ids:
        q = q.where(BgpRouter.firewall_id.in_([int(x) for x in fw_ids]))
    rib = []
    for r in (await s.execute(q)).scalars():
        for pre, paths in sorted((r.rib or {}).items()):
            inst = [_aware(p["installed"]) for p in paths if p.get("installed")]
            st = by_key.get((r.firewall_id, pre), {})
            rib.append({"firewall_id": r.firewall_id, "firewall_name": names.get(r.firewall_id, f"#{r.firewall_id}"), "prefix": pre,
                        "paths": paths, "ecmp": len(paths), "installed": min(inst).isoformat() if inst else None,
                        "age_s": round((now - min(inst)).total_seconds()) if inst else None, "critical": BA.matches_watchlist(pre, crit),
                        "changes": st.get("changes", 0), "path_changes": st.get("path_changes", 0)})
    for x in stab:
        x["critical"] = BA.matches_watchlist(x["prefix"], crit)
    return {"window": {"start": t0.isoformat(), "end": t1.isoformat()}, "rib": rib, "unstable": stab[:500],
            "critical": {"watchlist": watchlist, "exists": exists, "networks": [str(n) for n in crit][:200],
                         "installed": sum(1 for x in rib if x["critical"]),
                         "events": [{"t": e["t"].isoformat(), "firewall_name": e["firewall_name"], "peer": e["peer"], "kind": e["kind"],
                                     "prefix": e["prefix"], "detail": e["detail"]} for e in reversed(events)
                                    if e.get("prefix") and e["kind"] in ("route_withdraw", "path_change", "unreachable", "route_add")
                                    and BA.matches_watchlist(e["prefix"], crit)][:300]},
            "totals": {"installed": len(rib), "ecmp": sum(1 for x in rib if x["ecmp"] > 1), "unstable": sum(1 for x in stab if x["withdrawals"] or x["path_changes"]),
                       "suppressed_now": sum(1 for x in stab if x["suppressed"]), "critical_installed": sum(1 for x in rib if x["critical"])}}


async def audit_report(s, fw_ids: list[int] | None = None) -> dict:
    names = {f.id: f.name for f in (await s.execute(select(Firewall))).scalars()}
    q = select(BgpRouter)
    if fw_ids:
        q = q.where(BgpRouter.firewall_id.in_([int(x) for x in fw_ids]))
    out = []
    for r in (await s.execute(q)).scalars():
        c = r.config or {}
        out.append({"firewall_id": r.firewall_id, "firewall_name": names.get(r.firewall_id, f"#{r.firewall_id}"), "local_as": r.local_as,
                    "router_id": r.router_id, "holdtime": c.get("holdtime"), "keepalive": c.get("keepalive"),
                    "graceful_restart": c.get("graceful_restart"), "dampening": c.get("dampening"), "networks": c.get("networks", []),
                    "neighbors": len(c.get("neighbors", {})), "bfd_neighbors": sum(1 for n in c.get("neighbors", {}).values() if n.get("bfd")),
                    "config_polled_at": _aware(r.config_polled_at).isoformat() if r.config_polled_at else None,
                    "findings": r.audit or []})
    sev: dict[str, int] = defaultdict(int)
    checks: dict[str, int] = defaultdict(int)
    for f in out:
        for x in f["findings"]:
            sev[x["severity"]] += 1
            checks[x["title"] if not x["peer"] else x["check"]] += 1
    return {"firewalls": out, "by_severity": dict(sev), "by_check": dict(sorted(checks.items(), key=lambda kv: -kv[1]))}


async def security_report(ch, s, t0: datetime, t1: datetime, fw_ids: list[int] | None = None) -> dict:
    """Route-leak / hijack signals in the window plus what is present in the received routes right now."""
    events, names = await _window_events(ch, s, t0, t1, fw_ids)
    sec = [e for e in events if e["kind"] in BA.SECURITY_KINDS]
    q = select(BgpPeer)
    if fw_ids:
        q = q.where(BgpPeer.firewall_id.in_([int(x) for x in fw_ids]))
    routers = {r.firewall_id: r for r in (await s.execute(select(BgpRouter))).scalars()}
    present = []
    for b in (await s.execute(q)).scalars():
        own = [n for n in (BA._net(x) for x in ((routers.get(b.firewall_id).config or {}) if routers.get(b.firewall_id) else {}).get("networks", [])) if n]
        for pre in b.routes or []:
            for kind, detail in BA.classify_prefix(pre, own, b.remote_as):
                present.append({"firewall_id": b.firewall_id, "firewall_name": names.get(b.firewall_id, ""), "peer": b.peer_ip, "kind": kind,
                                "prefix": pre, "detail": detail})
    by_kind: dict[str, int] = defaultdict(int)
    for e in sec:
        by_kind[e["kind"]] += 1
    return {"events": [{"t": e["t"].isoformat(), "firewall_id": e["firewall_id"], "firewall_name": e["firewall_name"], "peer": e["peer"],
                        "kind": e["kind"], "prefix": e["prefix"], "detail": e["detail"]} for e in reversed(sec)][:1000],
            "present": present[:1000], "by_kind": dict(by_kind),
            "present_by_kind": {k: sum(1 for x in present if x["kind"] == k) for k in {x["kind"] for x in present}}}
