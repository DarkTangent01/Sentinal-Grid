"""BGP analysis built on the data collected by app.bgp:

* configuration audit (read-only GET of the firewall's BGP configuration; secrets are reduced to "set / not set")
* route-leak / hijack signals on every change in the prefixes a neighbor sends
* best-path (installed route) changes: which neighbor / tunnel a prefix uses and when it moved
* root-cause correlation of neighbor drops with the underlay (IPsec tunnel, ISP / SD-WAN link, ICMP, firewall health)
* prefix stability (flaps, route-flap-dampening penalty, lifetime), time in each BGP state, prefix-count baselines
"""
from __future__ import annotations

import ipaddress
import math
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from .vpnmon import _aware

UNSET = 4294967295  # FortiOS: "inherit the global value"
STALE_DOWN = timedelta(hours=24)
BOGONS = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "127.0.0.0/8", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4", "::/8", "2001:db8::/32", "fe80::/10", "ff00::/8")]
DEFAULTS = {"0.0.0.0/0", "::/0"}
SECURITY_KINDS = ("leak_suspect", "new_prefix", "more_specific", "bogon_prefix", "public_via_internal", "default_route",
                  "new_peer", "as_path_change")
STATE_HINTS = {
    "idle": "Not trying to connect: neighbor shut down, no route to the peer address, or the session was reset after an error.",
    "connect": "Waiting for the TCP/179 connection: the underlay (IPsec tunnel / link) is down, a policy or ACL blocks port 179, "
               "or the peer is not configured / not listening.",
    "active": "Retrying TCP/179: the peer refuses the connection (wrong neighbor IP, update-source mismatch, peer not configured).",
    "opensent": "OPEN sent, no valid reply: AS number, router-id, hold-time or capability mismatch, or an MD5 password mismatch.",
    "openconfirm": "OPEN accepted, waiting for KEEPALIVE: usually a transient state; if stuck, a capability or timer mismatch.",
    "established": "Session up and exchanging routes.",
}


def private_as(asn: int | None) -> bool:
    return asn is not None and (64512 <= asn <= 65534 or 4_200_000_000 <= asn <= 4_294_967_294)


def _net(p: str):
    try:
        return ipaddress.ip_network(p, strict=False)
    except ValueError:
        return None


def classify_prefix(prefix: str, own: list, remote_as: int | None) -> list[tuple[str, str]]:
    """Security signals for one newly received prefix: [(kind, detail)]."""
    if prefix in DEFAULTS:
        return [("default_route", "default route received")]
    n = _net(prefix)
    if n is None:
        return []
    out = []
    for b in BOGONS:
        if n.version == b.version and n.subnet_of(b):
            out.append(("bogon_prefix", f"bogon / reserved range {b}"))
            break
    for o in own:
        if o.version == n.version and n != o and n.subnet_of(o):
            out.append(("more_specific", f"more-specific of this firewall's own network {o}"))
            break
    if private_as(remote_as) and n.is_global and n.prefixlen > 0:
        out.append(("public_via_internal", f"public prefix from a private-AS (internal) neighbor AS {remote_as}"))
    return out


# ------------------------------------------------------------------ configuration (read-only)
def _cidr(v: str) -> str | None:
    """'172.29.0.0 255.255.0.0' / '10.0.0.0/8' → '172.29.0.0/16'."""
    v = (v or "").strip()
    if not v:
        return None
    try:
        if " " in v:
            a, m = v.split()[:2]
            return str(ipaddress.ip_network(f"{a}/{m}", strict=False))
        n = ipaddress.ip_network(v, strict=False)
        return None if n.prefixlen == n.max_prefixlen and n.network_address.is_unspecified else str(n)
    except ValueError:
        return None


def sanitize_fortigate_config(raw: dict) -> dict:
    """Keep the settings the audit needs; secrets become booleans and are never stored."""
    g = raw or {}
    nets = [c for c in (_cidr(x.get("prefix", "")) for x in g.get("network") or []) if c]
    nets += [c for c in (_cidr(x.get("prefix6", "")) for x in g.get("network6") or []) if c]

    def t(v):
        return None if v in (None, "", UNSET) else int(v)

    neighbors = {}
    for n in g.get("neighbor") or []:
        ip = str(n.get("ip") or "")
        if not ip:
            continue
        neighbors[ip] = {
            "remote_as": int(n["remote-as"]) if str(n.get("remote-as", "")).isdigit() else None,
            "description": str(n.get("description") or "")[:120], "shutdown": n.get("shutdown") == "enable",
            "bfd": n.get("bfd") == "enable", "password": bool(n.get("password")) or bool(n.get("auth-options")),
            "holdtime": t(n.get("holdtime-timer")), "keepalive": t(n.get("keep-alive-timer")),
            "max_prefix": int(n.get("maximum-prefix") or 0),
            "filter_in": any(n.get(k) for k in ("route-map-in", "prefix-list-in", "distribute-list-in", "filter-list-in")),
            "filter_out": any(n.get(k) for k in ("route-map-out", "prefix-list-out", "distribute-list-out", "filter-list-out")),
            "graceful_restart": n.get("capability-graceful-restart") == "enable",
            "interface": str(n.get("interface") or n.get("update-source") or ""),
        }
    return {"vendor": "fortinet", "local_as": int(g["as"]) if str(g.get("as", "")).isdigit() else None,
            "router_id": str(g.get("router-id") or ""), "holdtime": int(g.get("holdtime-timer") or 180),
            "keepalive": int(g.get("keepalive-timer") or 60), "graceful_restart": g.get("graceful-restart") == "enable",
            "dampening": g.get("dampening") == "enable", "log_changes": g.get("log-neighbour-changes", "enable") == "enable",
            "networks": nets, "neighbors": neighbors}


def sanitize_pan_config(vr) -> dict:
    """PAN-OS virtual-router XML (config get) → the same shape as the FortiGate config."""
    from .paloalto import _t
    bgp = vr.find(".//protocol/bgp") if vr is not None else None
    neighbors = {}
    if bgp is not None:
        for grp in bgp.findall("./peer-group/entry"):
            for p in grp.findall("./peer/entry"):
                ip = _t(p, "peer-address/ip").split("/")[0]
                if not ip:
                    continue
                opts = p.find("connection-options")
                hold = _t(opts, "hold-time") if opts is not None else ""
                ka = _t(opts, "keep-alive-interval") if opts is not None else ""
                neighbors[ip] = {"remote_as": int(_t(p, "peer-as")) if _t(p, "peer-as").isdigit() else None, "description": p.get("name", ""),
                                 "shutdown": _t(p, "enable") == "no", "bfd": bool(_t(p, "bfd/profile")) and _t(p, "bfd/profile") != "None",
                                 "password": bool(_t(opts, "authentication")) if opts is not None else False,
                                 "holdtime": int(hold) if hold.isdigit() else None, "keepalive": int(ka) if ka.isdigit() else None,
                                 "max_prefix": 0, "filter_in": bool(bgp.findall("./policy/import/rules/entry")),
                                 "filter_out": bool(bgp.findall("./policy/export/rules/entry")), "graceful_restart": False, "interface": ""}
    asn = _t(bgp, "local-as") if bgp is not None else ""
    return {"vendor": "paloalto", "local_as": int(asn) if asn.isdigit() else None, "router_id": _t(bgp, "router-id") if bgp is not None else "",
            "holdtime": 90, "keepalive": 30, "graceful_restart": bool(bgp is not None and _t(bgp, "graceful-restart/enable") == "yes"),
            "dampening": False, "log_changes": True, "networks": [], "neighbors": neighbors}


def _cli(ip: str, *lines: str) -> str:
    body = "\n".join(f"            {x}" for x in lines)
    return f'config router bgp\n    config neighbor\n        edit "{ip}"\n{body}\n        next\n    end\nend'


def audit(cfg: dict | None, peers: list[dict], now: datetime) -> list[dict]:
    """Findings for one firewall. `peers`: current neighbor rows (peer, state, state_since, prefixes, interface)."""
    if not cfg:
        return []
    out = []
    fgt = cfg.get("vendor") == "fortinet"

    def f(sev, peer, check, title, detail, cli=""):
        out.append({"severity": sev, "peer": peer, "check": check, "title": title, "detail": detail, "cli": cli if fgt else ""})

    if not cfg.get("log_changes"):
        f("medium", "", "log_changes", "Neighbor changes are not logged", "Without log-neighbour-changes the SIEM loses BGP history.",
          "config router bgp\n    set log-neighbour-changes enable\nend")
    if not cfg.get("graceful_restart"):
        f("low", "", "graceful_restart", "Graceful restart disabled", "A firewall failover or restart drops all routes until sessions re-form.",
          "config router bgp\n    set graceful-restart enable\nend")
    state = {p["peer"]: p for p in peers}
    for ip, n in sorted(cfg.get("neighbors", {}).items()):
        p = state.get(ip, {})
        st = (p.get("state") or "").lower()
        if n.get("shutdown"):
            f("info", ip, "shutdown", "Neighbor administratively shut down", "Configured but disabled: remove it if it is no longer needed.")
            continue
        since = p.get("state_since")
        if since and st and st != "established" and now - _aware(since) >= STALE_DOWN:
            days = (now - _aware(since)).total_seconds() / 86400
            f("medium", ip, "stale", f"Neighbor not established for {days:.1f} days",
              f"State {p.get('state')}. Fix the underlay / peer, or shut it down so it stops alerting and retrying.",
              _cli(ip, "set shutdown enable"))
        tunnel = (p.get("interface") or n.get("interface") or "")
        if not n.get("password"):
            over_ipsec = ip.startswith("169.254.") or "tun" in tunnel.lower()
            f("low" if over_ipsec else "medium", ip, "password", "No session authentication (TCP-MD5 password)",
              "Inside an IPsec tunnel the risk is lower, but a password still stops spoofed/rogue sessions." if over_ipsec else
              "Anyone who can reach TCP/179 from the peer address can reset or hijack the session.",
              _cli(ip, "set password <shared-secret>"))
        if not n.get("bfd"):
            hold = n.get("holdtime") or cfg.get("holdtime") or 180
            f("low", ip, "bfd", "BFD not enabled", f"Failure is detected only when the {hold} s hold timer expires; BFD detects it in under a second.",
              _cli(ip, "set bfd enable") + "\n# BFD must also be enabled on the interface: config system interface / edit <if> / set bfd enable")
        hold = n.get("holdtime") or cfg.get("holdtime") or 180
        if hold >= 90:
            f("low", ip, "holdtime", f"Slow failure detection (hold timer {hold} s)",
              "With the default 180 s, traffic is black-holed for up to 3 minutes before failover.",
              _cli(ip, "set keep-alive-timer 10", "set holdtime-timer 30"))
        if not n.get("max_prefix"):
            cur = p.get("prefixes") or 0
            lim = max(100, int(math.ceil(cur * 2 / 100.0) * 100))
            f("medium", ip, "max_prefix", "No maximum-prefix limit", f"A route leak from this neighbor ({cur} prefixes today) would be accepted in full.",
              _cli(ip, f"set maximum-prefix {lim}", "set maximum-prefix-threshold 75", "set maximum-prefix-warning-only enable"))
        if not n.get("filter_in"):
            f("medium", ip, "filter_in", "No inbound route filter", "Every prefix the neighbor sends is accepted (no route-map / prefix-list in).",
              _cli(ip, 'set route-map-in "<allowed-prefixes>"'))
        if not n.get("filter_out"):
            f("low", ip, "filter_out", "No outbound route filter", "Every route this firewall knows may be advertised to the neighbor.",
              _cli(ip, 'set route-map-out "<advertised-prefixes>"'))
    sev = {"high": 0, "medium": 1, "low": 2, "info": 3}
    out.sort(key=lambda x: (sev[x["severity"]], x["peer"], x["check"]))
    return out


# ------------------------------------------------------------------ installed routes (RIB) and path changes
def rib_diff(old: dict | None, new: dict, fw_id: int, now: datetime, max_events: int = 200) -> list[dict]:
    """path_change when a prefix moves to a different neighbor / tunnel (or loses an ECMP member); unreachable when it
    leaves the routing table entirely while its neighbors are still known."""
    if old is None:
        return []
    ev = []

    def via(paths):
        return sorted({(p["peer"], p.get("interface", "")) for p in paths})

    def label(v):
        return " + ".join(f"{i or '?'} ({p})" for p, i in v) or "nothing"

    for prefix in sorted(set(old) | set(new)):
        a, b = via(old.get(prefix, [])), via(new.get(prefix, []))
        if a == b or not a:
            continue
        peer = (b or a)[0][0]
        if not b:
            ev.append({"ts": now, "firewall_id": fw_id, "peer": a[0][0], "kind": "unreachable", "prefix": prefix,
                       "detail": f"removed from the routing table (was via {label(a)})"})
        else:
            ev.append({"ts": now, "firewall_id": fw_id, "peer": peer, "kind": "path_change", "prefix": prefix,
                       "detail": f"via {label(a)} → via {label(b)}"})
        if len(ev) >= max_events:
            ev.append({"ts": now, "firewall_id": fw_id, "peer": "", "kind": "path_change", "prefix": "",
                       "detail": "more path changes in this poll were not recorded individually"})
            break
    return ev


def security_events(peer, added: set[str], removed: set[str], known: dict, first_seen: datetime | None, own: list, fw_id: int,
                    now: datetime, max_events: int = 100) -> list[dict]:
    """Leak / hijack signals for one neighbor's received-prefix delta."""
    ev = []

    def e(kind, prefix, detail):
        ev.append({"ts": now, "firewall_id": fw_id, "peer": peer.peer_ip, "kind": kind, "prefix": prefix, "detail": detail})

    for d in sorted(removed & DEFAULTS):
        e("default_route", d, "default route withdrawn")
    for pre in sorted(added):
        for kind, detail in classify_prefix(pre, own, peer.remote_as):
            e(kind, pre, detail)
    settled = first_seen is not None and now - _aware(first_seen) >= timedelta(hours=24) and known
    if settled:
        unseen = sorted(p for p in added if p not in known)
        if unseen and len(unseen) >= max(20, len(known) // 2):
            e("leak_suspect", "", f"{len(unseen)} prefixes never seen from this neighbor in 7 days arrived at once "
                                  f"(it normally sends ~{len(known)}): possible route leak")
        for pre in unseen[:max_events]:
            e("new_prefix", pre, "first time this neighbor announced this prefix in 7 days")
    return ev


def update_known(known: dict | None, current: set[str], now: datetime) -> dict:
    keep = {p: t for p, t in (known or {}).items() if now - datetime.fromisoformat(t) <= timedelta(days=7)}
    stamp = now.isoformat()
    for p in current:
        keep[p] = stamp
    return keep


# ------------------------------------------------------------------ reporting helpers
def reliability(span_s: float, downs: list[dict], drops: int) -> dict:
    down = sum(d["duration_s"] for d in downs)
    return {"mtbf_s": round((span_s - down) / drops) if drops else None, "mttr_s": round(down / drops) if drops else None,
            "longest_s": max((d["duration_s"] for d in downs), default=0),
            "flap_score": round(drops / max(span_s / 86400, 1 / 24), 2)}


async def baselines(ch, keys: list[tuple[int, str]], now: datetime) -> dict[tuple[int, str], dict]:
    """7-day prefix-count baseline per neighbor (established samples only)."""
    if not keys:
        return {}
    rows = await ch.aquery(
        "SELECT firewall_id, peer, count() AS n, quantileExact(0.5)(prefixes) AS med, quantileExact(0.05)(prefixes) AS lo, "
        "quantileExact(0.95)(prefixes) AS hi, argMax(prefixes, ts) AS cur FROM bgp_samples "
        "WHERE ts >= {t0:DateTime64(3)} AND up = 1 AND prefixes IS NOT NULL GROUP BY firewall_id, peer",
        {"t0": now - timedelta(days=7)})
    out = {}
    for r in rows:
        med = r["med"]
        cur = r["cur"]
        dev = round(100 * (cur - med) / med, 1) if med else None
        out[(int(r["firewall_id"]), r["peer"])] = {"samples": int(r["n"]), "median": med, "p05": r["lo"], "p95": r["hi"],
                                                   "current": cur, "deviation_pct": dev}
    return out


def is_anomalous(b: dict | None, min_samples: int = 30, pct: float = 30.0, min_abs: int = 5) -> bool:
    if not b or b["samples"] < min_samples or b["median"] in (None, 0) or b["current"] is None:
        return False
    return abs(b["current"] - b["median"]) >= max(min_abs, b["median"] * pct / 100)


async def time_in_state(ch, fw_id: int, peer: str, t0: datetime, t1: datetime) -> dict:
    rows = await ch.aquery(
        "SELECT ts, state FROM bgp_samples WHERE firewall_id = {f:UInt32} AND peer = {p:String} AND ts >= {t0:DateTime64(3)} "
        "AND ts < {t1:DateTime64(3)} ORDER BY ts", {"f": fw_id, "p": peer, "t0": t0, "t1": t1})
    pts = [(_aware(r["ts"]), r["state"]) for r in rows]
    gaps = sorted((b[0] - a[0]).total_seconds() for a, b in zip(pts, pts[1:]))
    cap = 3 * gaps[len(gaps) // 2] if gaps else 0
    acc: dict[str, float] = defaultdict(float)
    for (ta, sa), (tb, _) in zip(pts, pts[1:]):
        acc[sa] += min((tb - ta).total_seconds(), cap)
    total = sum(acc.values())
    return {"states": [{"state": k, "seconds": round(v), "pct": round(100 * v / total, 2) if total else 0,
                        "hint": STATE_HINTS.get(k.lower(), "")} for k, v in sorted(acc.items(), key=lambda x: -x[1])],
            "samples": len(pts)}


async def correlate(ch, s, fw_ids: list[int], t0: datetime, t1: datetime, drops: list[dict], window_s: int = 120) -> None:
    """Attach a likely cause to each neighbor drop: firewall restart, ISP / WAN outage, IPsec tunnel down, ICMP loss,
    CPU saturation, BFD, or a BGP-only reset. `drops`: dicts with firewall_id, interface, start, reason; updated in place."""
    if not drops:
        return
    from . import fwhealth, vpnmon
    from .db.models import IcmpEvent, IcmpTarget
    lo, hi = t0 - timedelta(seconds=window_s), t1 + timedelta(seconds=window_s)
    try:
        tunnels = (await vpnmon.tunnels(ch, lo, hi, fw_ids))["tunnels"]
    except Exception:
        tunnels = []
    tdown = defaultdict(list)
    for t in tunnels:
        for d in t["down_periods"]:
            tdown[(t["firewall_id"], t["tunnel"])].append((_aware(d["start"]), _aware(d["end"])))
    try:
        from .isp import report as isp_report
        isp = (await isp_report(ch, s, lo, hi, fw_ids, 30))["timeline"]
    except Exception:
        isp = []
    try:
        samples = await fwhealth.perf_samples(ch, lo - timedelta(hours=2), hi, fw_ids)
        boots = fwhealth.reboots(samples)
    except Exception:
        samples, boots = [], []
    icmp = (await s.execute(select(IcmpEvent, IcmpTarget.name).join(IcmpTarget, IcmpTarget.id == IcmpEvent.target_id)
                            .where(IcmpEvent.at >= lo, IcmpEvent.at <= hi, IcmpEvent.to_state == "down"))).all()
    w = timedelta(seconds=window_s)
    for d in drops:
        t, fid = _aware(d["start"]), d["firewall_id"]
        causes = []
        for b in boots:
            if b["firewall_id"] == fid and abs(_aware(b["boot_time"]) - t) <= timedelta(minutes=10):
                causes.append({"type": "reboot", "detail": f"{b['member']} restarted at {_aware(b['boot_time']):%H:%M} UTC"})
        for o in isp:
            if o.get("firewall_id", fid) == fid and _aware(o["start"]) - w <= t <= _aware(o["end"]) + w:
                causes.append({"type": "isp", "detail": f"{o.get('isp_name') or 'WAN'} outage on {o['interface']} "
                                                        f"({_aware(o['start']):%H:%M}–{_aware(o['end']):%H:%M} UTC)"})
        tun = d.get("interface") or ""
        for (tf, name), periods in tdown.items():
            if tf != fid or (tun and name != tun):
                continue
            for a, b in periods:
                if a - w <= t <= b + w:
                    causes.append({"type": "tunnel", "detail": f"IPsec tunnel {name} down {a:%H:%M}–{b:%H:%M} UTC"})
                    break
        for ev, name in icmp:
            if abs(_aware(ev.at) - t) <= w:
                causes.append({"type": "icmp", "detail": f"ICMP target {name} went down at {_aware(ev.at):%H:%M:%S} UTC"})
        for smp in samples:
            if smp.get("firewall_id") == fid and smp.get("cpu") is not None and smp["cpu"] >= 90 and abs(smp["t"] - t) <= timedelta(minutes=5):
                causes.append({"type": "cpu", "detail": f"firewall CPU {smp['cpu']:.0f}% at {smp['t']:%H:%M} UTC"})
                break
        if d.get("bfd_before"):
            causes.append({"type": "bfd", "detail": "BFD reported the loss first"})
        reason = (d.get("reason") or "").lower()
        order = ["reboot", "isp", "tunnel", "icmp", "cpu", "bfd"]
        causes.sort(key=lambda c: order.index(c["type"]))
        if causes:
            verdict = {"reboot": "Firewall restart", "isp": "WAN / ISP outage", "tunnel": "Underlay IPsec tunnel down",
                       "icmp": "Upstream reachability loss", "cpu": "Firewall overloaded", "bfd": "Link failure (BFD)"}[causes[0]["type"]]
        elif "hold timer" in reason:
            verdict = "Keepalive loss (no underlay event logged)"
        elif "notification" in reason or "fsm" in reason or "cease" in reason:
            verdict = "BGP-level reset"
        else:
            verdict = "BGP / peer side"
        d["verdict"], d["causes"] = verdict, causes[:6]


def prefix_stability(events: list[dict], now: datetime, half_life_min: float = 15.0) -> list[dict]:
    """Per (firewall, prefix): withdrawals, announcements, path changes, current route-flap-dampening penalty
    (withdraw 1000, path change 500, half-life 15 min; suppress ≥ 2000, reuse < 750) and mean lifetime."""
    k = math.log(2) / (half_life_min * 60)
    acc: dict[tuple, dict] = {}
    for e in events:
        if not e.get("prefix") or e["kind"] not in ("route_add", "route_withdraw", "path_change", "unreachable"):
            continue
        key = (e["firewall_id"], e["prefix"])
        a = acc.setdefault(key, {"firewall_id": e["firewall_id"], "firewall_name": e["firewall_name"], "prefix": e["prefix"], "peers": set(),
                                 "withdrawals": 0, "announcements": 0, "path_changes": 0, "penalty": 0.0, "max_penalty": 0.0,
                                 "_t": None, "_up": None, "_life": [], "last_change": None})
        if e["peer"]:
            a["peers"].add(e["peer"])
        t = e["t"]
        if a["_t"] is not None:
            a["penalty"] *= math.exp(-k * (t - a["_t"]).total_seconds())
        a["_t"] = t
        if e["kind"] in ("route_withdraw", "unreachable"):
            a["withdrawals"] += 1
            a["penalty"] += 1000
            if a["_up"] is not None:
                a["_life"].append((t - a["_up"]).total_seconds())
                a["_up"] = None
        elif e["kind"] == "route_add":
            a["announcements"] += 1
            a["_up"] = a["_up"] or t
        else:
            a["path_changes"] += 1
            a["penalty"] += 500
        a["max_penalty"] = max(a["max_penalty"], a["penalty"])
        a["last_change"] = t
    out = []
    for a in acc.values():
        pen = a["penalty"] * math.exp(-k * (now - a["_t"]).total_seconds()) if a["_t"] else 0
        life = a.pop("_life")
        a.pop("_t")
        a.pop("_up")
        out.append({**a, "peers": sorted(a["peers"]), "penalty": round(pen), "max_penalty": round(a["max_penalty"]),
                    "suppressed": pen >= 2000, "would_have_been_suppressed": a["max_penalty"] >= 2000,
                    "mean_lifetime_s": round(sum(life) / len(life)) if life else None,
                    "last_change": a["last_change"].isoformat() if a["last_change"] else None,
                    "changes": a["withdrawals"] + a["announcements"] + a["path_changes"]})
    out.sort(key=lambda x: (-x["max_penalty"], -x["changes"]))
    return out


def matches_watchlist(prefix: str, nets: list) -> bool:
    n = _net(prefix)
    return bool(n) and any(w.version == n.version and (n.overlaps(w)) for w in nets)
