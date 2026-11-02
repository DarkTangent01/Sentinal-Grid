"""Layer-2 topology from LLDP / CDP neighbors: nodes, links and link health.

* A neighbor is matched to a monitored switch by management IP, then system name (domain stripped), then chassis /
  interface MAC; and to a registered firewall by management IP or name. Anything else becomes an external node typed
  from its advertised capabilities (router, bridge, AP, phone, station).
* The same cable is usually seen from both ends: the two observations are merged into one link (keyed by both
  endpoints' normalised port names).
* Link status: lost (the neighbor disappeared within the look-back window), down (an end's interface is not up),
  degraded (utilisation ≥ 80 % or errors in the last poll on either end), up, or unknown (local port not mapped).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import Firewall, Switch, SwitchInterface, SwitchNeighbor
from .collect import port_key

ENDPOINT_TYPES = {"phone", "host", "ap", "device"}
RANK = {"lost": 4, "down": 3, "degraded": 2, "unknown": 1, "up": 0}


def _aware(v):
    if v is None:
        return None
    return v if v.tzinfo else v.replace(tzinfo=timezone.utc)


def _short(name: str) -> str:
    return (name or "").strip().split(".")[0].split("(")[0].strip().lower()


def node_type(caps: list[str], descr: str) -> str:
    d = (descr or "").lower()
    if "fortigate" in d or "fortios" in d:
        return "firewall"
    c = set(caps or [])
    if "wlan_ap" in c:
        return "ap"
    if "telephone" in c:
        return "phone"
    if "router" in c and "bridge" not in c:
        return "router"
    if "bridge" in c:
        return "switch"
    if "router" in c:
        return "router"
    if "station" in c:
        return "host"
    return "device"


def _ifinfo(r: SwitchInterface | None) -> dict | None:
    if r is None:
        return None
    errs = [x for x in (r.in_errors_delta, r.out_errors_delta, r.crc_delta) if x is not None]
    return {"ifindex": r.ifindex, "name": r.name, "alias": r.alias, "oper": r.oper, "admin": r.admin, "speed_bps": r.speed_bps,
            "rx_util": r.rx_util, "tx_util": r.tx_util, "rx_bps": r.rx_bps, "tx_bps": r.tx_bps, "errors": sum(errs) if errs else None,
            "lag_ifindex": r.lag_ifindex, "kind": r.kind}


def link_status(present: bool, ends: list[dict | None]) -> str:
    if not present:
        return "lost"
    known = [e for e in ends if e]
    if not known:
        return "unknown"
    if any(e["oper"] != "up" for e in known):
        return "down"
    if any(max(e["rx_util"] or 0, e["tx_util"] or 0) >= 80 or (e["errors"] or 0) > 0 for e in known):
        return "degraded"
    return "up"


async def build(s: AsyncSession, *, site: str | None = None, endpoints: bool = False, lost_hours: int = 24,
                now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    sws = (await s.execute(select(Switch))).scalars().all()
    by_id = {x.id: x for x in sws}
    fws = (await s.execute(select(Firewall).where(Firewall.is_demo.is_(False)))).scalars().all()
    scope = {x.id for x in sws if not site or x.site == site}
    nbrs = (await s.execute(select(SwitchNeighbor).where(SwitchNeighbor.switch_id.in_(scope or {0}),
                                                         or_(SwitchNeighbor.present.is_(True),
                                                             SwitchNeighbor.last_seen >= now - timedelta(hours=lost_hours)))))
    nbrs = nbrs.scalars().all()
    ifrows = (await s.execute(select(SwitchInterface).where(SwitchInterface.present.is_(True)))).scalars().all()
    if_by_ix = {(r.switch_id, r.ifindex): r for r in ifrows}
    if_by_name: dict[tuple, SwitchInterface] = {}
    for r in ifrows:
        for n in (r.name, r.descr):
            if n:
                if_by_name.setdefault((r.switch_id, port_key(n)), r)
    ip_sw = {x.address: x.id for x in sws}
    name_sw = {}
    for x in sws:
        for n in (x.name, x.sys_name):
            if n:
                name_sw.setdefault(_short(n), x.id)
    mac_sw = {}
    for r in ifrows:
        if r.mac:
            mac_sw.setdefault(r.mac, r.switch_id)
    for x in sws:
        for m in ((x.health or {}).get("stack") or {}).get("members") or []:
            if m.get("mac"):
                mac_sw.setdefault(m["mac"], x.id)
    ip_fw = {f.host: f.id for f in fws}
    name_fw = {_short(f.name): f.id for f in fws}

    nodes: dict[str, dict] = {}

    def sw_node(sid: int) -> str:
        nid = f"sw:{sid}"
        if nid not in nodes:
            x = by_id[sid]
            nodes[nid] = {"id": nid, "kind": "switch", "type": "switch", "label": x.name, "switch_id": sid, "site": x.site, "address": x.address,
                          "vendor": x.vendor, "model": x.model, "status": "paused" if x.monitoring == "paused" else x.state, "managed": True,
                          "in_scope": sid in scope}
        return nid

    for sid in scope:
        sw_node(sid)
    hidden = 0
    links: dict[tuple, dict] = {}
    for n in nbrs:
        a = sw_node(n.switch_id)
        rid = ip_sw.get(n.remote_mgmt_ip) or name_sw.get(_short(n.remote_name)) or mac_sw.get(n.chassis_id)
        if rid == n.switch_id:
            continue  # a switch seeing itself (stack loop-back, misreported chassis): not a link
        if rid:
            b = sw_node(rid)
            b_if = if_by_name.get((rid, port_key(n.remote_port))) or if_by_name.get((rid, port_key(n.remote_port_desc)))
        else:
            fid = ip_fw.get(n.remote_mgmt_ip) or name_fw.get(_short(n.remote_name))
            b_if = None
            if fid:
                b = f"fw:{fid}"
                f = next(x for x in fws if x.id == fid)
                nodes.setdefault(b, {"id": b, "kind": "firewall", "type": "firewall", "label": f.name, "firewall_id": fid, "site": f.site,
                                     "address": f.host, "vendor": f.vendor, "model": "", "status": f.api_status or "", "managed": True, "in_scope": True})
            else:
                typ = node_type(n.capabilities, n.remote_descr)
                if typ in ENDPOINT_TYPES and not endpoints:
                    hidden += 1
                    continue
                b = f"ext:{n.remote_key}"
                nodes.setdefault(b, {"id": b, "kind": "external", "type": typ, "label": n.remote_name or n.chassis_id or n.remote_key,
                                     "address": n.remote_mgmt_ip, "chassis_id": n.chassis_id, "descr": n.remote_descr, "capabilities": n.capabilities,
                                     "status": "", "managed": False, "in_scope": True})
        a_if = if_by_ix.get((n.switch_id, n.local_ifindex)) if n.local_ifindex is not None else None
        a_key = (a, port_key(a_if.name if a_if else n.local_port))
        b_key = (b, port_key(b_if.name if b_if else n.remote_port))
        key = tuple(sorted([a_key, b_key]))
        end_a = {"node": a, "port": a_if.name if a_if else n.local_port, "interface": _ifinfo(a_if)}
        end_b = {"node": b, "port": b_if.name if b_if else n.remote_port, "port_desc": n.remote_port_desc, "interface": _ifinfo(b_if)}
        cur = links.get(key)
        if cur is None:
            links[key] = {"id": f"{key[0][0]}|{key[0][1]}|{key[1][0]}|{key[1][1]}", "a": end_a, "b": end_b, "protocols": {n.protocol},
                          "present": n.present, "seen_by": [a], "last_seen": _aware(n.last_seen), "first_seen": _aware(n.first_seen)}
        else:  # the same cable seen from the other end: fill in that end's interface, merge state
            for e in (cur["a"], cur["b"]):
                if e["node"] == a and e["interface"] is None:
                    e.update(end_a)
                if e["node"] == b and e["interface"] is None and end_b["interface"]:
                    e.update(end_b)
            cur["protocols"].add(n.protocol)
            cur["present"] = cur["present"] or n.present
            cur["seen_by"].append(a)
            if _aware(n.last_seen) and (cur["last_seen"] is None or _aware(n.last_seen) > cur["last_seen"]):
                cur["last_seen"] = _aware(n.last_seen)
    out_links = []
    for lk in links.values():
        st = link_status(lk["present"], [lk["a"]["interface"], lk["b"]["interface"]])
        speeds = [e["interface"]["speed_bps"] for e in (lk["a"], lk["b"]) if e["interface"] and e["interface"]["speed_bps"]]
        utils = [max(e["interface"]["rx_util"] or 0, e["interface"]["tx_util"] or 0) for e in (lk["a"], lk["b"])
                 if e["interface"] and (e["interface"]["rx_util"] is not None or e["interface"]["tx_util"] is not None)]
        lag = next((e["interface"]["lag_ifindex"] for e in (lk["a"], lk["b"]) if e["interface"] and e["interface"]["lag_ifindex"]), None)
        out_links.append({**lk, "protocols": sorted(lk["protocols"]), "status": st, "speed_bps": min(speeds) if speeds else None,
                          "util": round(max(utils), 1) if utils else None, "lag_ifindex": lag, "bidirectional": len(set(lk["seen_by"])) > 1,
                          "last_seen": lk["last_seen"].isoformat() if lk["last_seen"] else None,
                          "first_seen": lk["first_seen"].isoformat() if lk["first_seen"] else None})
    deg: dict[str, int] = {}
    for lk in out_links:
        for e in (lk["a"], lk["b"]):
            deg[e["node"]] = deg.get(e["node"], 0) + 1
    for nid, nd in nodes.items():
        nd["degree"] = deg.get(nid, 0)
    no_lldp = []
    for sid in scope:
        caps = (by_id[sid].capabilities or {})
        lldp = caps.get("switch_lldp_neighbors") or {}
        if not any(n.switch_id == sid for n in nbrs):
            no_lldp.append({"switch_id": sid, "switch": by_id[sid].name, "reason": lldp.get("reason") or
                            ("not collected yet" if not lldp else "no neighbors reported")})
    out_links.sort(key=lambda x: (-RANK[x["status"]], x["id"]))
    return {"generated_at": now.isoformat(), "site": site, "nodes": sorted(nodes.values(), key=lambda n: (n["kind"] != "switch", n["label"].lower())),
            "links": out_links,
            "totals": {"nodes": len(nodes), "links": len(out_links), **{k: sum(1 for x in out_links if x["status"] == k) for k in RANK},
                       "external": sum(1 for n in nodes.values() if n["kind"] == "external"), "hidden_endpoints": hidden, "switches_without_neighbors": len(no_lldp)},
            "without_neighbors": no_lldp, "lost_hours": lost_hours}


def path(topo: dict, src: str, dst: str, *, usable=("up", "degraded")) -> dict:
    """Shortest path between two nodes over links in a usable state (BFS). Returns the hops or why there is none."""
    adj: dict[str, list] = {}
    for lk in topo["links"]:
        if lk["status"] in usable:
            adj.setdefault(lk["a"]["node"], []).append((lk["b"]["node"], lk))
            adj.setdefault(lk["b"]["node"], []).append((lk["a"]["node"], lk))
    prev: dict[str, tuple] = {src: (None, None)}
    q = [src]
    while q:
        cur = q.pop(0)
        if cur == dst:
            break
        for nxt, lk in adj.get(cur, []):
            if nxt not in prev:
                prev[nxt] = (cur, lk)
                q.append(nxt)
    if dst not in prev:
        return {"connected": False, "hops": []}
    hops = []
    cur = dst
    while prev[cur][0] is not None:
        p, lk = prev[cur]
        hops.append({"from": p, "to": cur, "link": lk["id"], "status": lk["status"]})
        cur = p
    return {"connected": True, "hops": list(reversed(hops))}
