"""Layer-3 and WAN topology: routing adjacencies, VPN tunnels and ISP circuits, built only from data Sentinel already
collects. Every edge says where it comes from, so observed relationships are never confused with inferred ones:

  ospf    OSPF-MIB ospfNbrTable of a polled device (observed by SNMP)
  bgp     BGP4-MIB bgpPeerTable of a polled device, or the FortiGate BGP API (observed)
  ipsec   FortiGate VPN event logs: tunnel name, remote gateway, up / down (observed from logs)
  isp     the circuit inventory (isp_links): firewall interface → provider (configured), state from open WAN outages

A neighbour address is matched to an inventory device when it is that device's management address, one of the IP
interfaces the device reported (IP-MIB ipAddrTable), a registered firewall's address, or a BGP local address; otherwise
it becomes an external node (another AS, a VPN peer, an OSPF router Sentinel does not poll). Matching by address is the
only inference made, and it is recorded on the edge (`matched_by`).
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import BgpPeer, BgpRouter, Firewall, IspLink, Switch, WanOutage

GOOD = {"ospf": "full", "bgp": "established"}


def _ip(v: str) -> str | None:
    try:
        return str(ipaddress.ip_address((v or "").strip()))
    except ValueError:
        return None


class Graph:
    def __init__(self):
        self.nodes: dict[str, dict] = {}
        self.edges: dict[tuple, dict] = {}

    def node(self, nid: str, **kw) -> str:
        self.nodes.setdefault(nid, {"id": nid, **kw})
        return nid

    def edge(self, a: str, b: str, protocol: str, layer: str, source: str, state: str, **kw) -> None:
        # a routing adjacency is one edge whichever end reported it (each end names the other's address); tunnels and
        # circuits keep their own name, so two tunnels between the same firewalls stay two edges
        key = (protocol, *sorted((a, b))) if protocol in ("ospf", "bgp") else (protocol, *sorted((a, b)), kw.get("detail", ""))
        cur = self.edges.get(key)
        if cur is None:
            self.edges[key] = {"a": a, "b": b, "protocol": protocol, "layer": layer, "source": source, "state": state, "reported_by": [kw.pop("by", "")], **kw}
        else:  # the same adjacency reported from the other end
            cur["reported_by"] = sorted(set(cur["reported_by"] + [kw.get("by", "")]) - {""})
            if state == "up" or cur["state"] != "up":
                cur["state"] = state if cur["state"] != "down" else cur["state"]


async def build(s: AsyncSession, ch=None, site: str | None = None, now: datetime | None = None, tunnels: list[dict] | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    g = Graph()
    sws = (await s.execute(select(Switch))).scalars().all()
    fws = (await s.execute(select(Firewall))).scalars().all()
    if site:
        sws = [x for x in sws if (x.site or "").lower() == site.lower()]
        fws = [x for x in fws if (x.site or "").lower() == site.lower()]
    owner: dict[str, tuple[str, str]] = {}                      # ip → (node id, how it was matched)
    for x in sws:
        nid = g.node(f"sw:{x.id}", kind="device", type=(x.device_type or "switch"), label=x.name, switch_id=x.id, site=x.site, address=x.address,
                     status=x.state, managed=True)
        if _ip(x.address):
            owner[_ip(x.address)] = (nid, "management address")
        for a in ((x.health or {}).get("routing") or {}).get("ip_interfaces") or []:
            if _ip(a.get("ip")):
                owner.setdefault(_ip(a["ip"]), (nid, "interface address (IP-MIB)"))
    for f in fws:
        nid = g.node(f"fw:{f.id}", kind="device", type="firewall", label=f.name, firewall_id=f.id, site=f.site, address=f.host, managed=True)
        if _ip(f.host):
            owner.setdefault(_ip(f.host), (nid, "firewall address"))
    fw_ids = {f.id for f in fws}
    peers = (await s.execute(select(BgpPeer))).scalars().all()
    for p in peers:                                              # BGP local addresses identify the firewall too
        if p.firewall_id in fw_ids and _ip(p.local_ip):
            owner.setdefault(_ip(p.local_ip), (f"fw:{p.firewall_id}", "BGP local address"))
    local_as = {r.firewall_id: r.local_as for r in (await s.execute(select(BgpRouter))).scalars()}

    def far(ip: str, *, kind: str, label: str, **kw) -> tuple[str, str]:
        hit = owner.get(_ip(ip) or "")
        if hit:
            return hit
        return g.node(f"{kind}:{label}", kind="external", type=kind, label=label, managed=False, **kw), "not in inventory"

    # routing adjacencies reported by polled devices (SNMP)
    for x in sws:
        r = (x.health or {}).get("routing") or {}
        for n in r.get("ospf") or []:
            b, how = far(n.get("neighbor", ""), kind="ospf_router", label=f"OSPF {n.get('router_id') or n.get('neighbor')}", address=n.get("neighbor"))
            g.edge(f"sw:{x.id}", b, "ospf", "l3", "SNMP OSPF-MIB", "up" if n.get("state") == "full" else "down",
                   detail=n.get("neighbor", ""), peer_state=n.get("state"), matched_by=how, by=x.name)
        for n in r.get("bgp") or []:
            asn = n.get("remote_as")
            b, how = far(n.get("peer", ""), kind="as", label=f"AS{asn}" if asn else f"BGP {n.get('peer')}", asn=asn)
            g.edge(f"sw:{x.id}", b, "bgp", "l3", "SNMP BGP4-MIB", "up" if n.get("state") == "established" else "down",
                   detail=n.get("peer", ""), peer_state=n.get("state"), remote_as=asn, matched_by=how, by=x.name)
    # BGP from the FortiGate API
    for p in peers:
        if p.firewall_id not in fw_ids:
            continue
        b, how = far(p.peer_ip, kind="as", label=f"AS{p.remote_as}" if p.remote_as else f"BGP {p.peer_ip}", asn=p.remote_as)
        g.edge(f"fw:{p.firewall_id}", b, "bgp", "l3", "FortiGate BGP API", "up" if (p.state or "").lower() == "established" else "down",
               detail=p.peer_ip, peer_state=p.state, remote_as=p.remote_as, local_as=local_as.get(p.firewall_id), prefixes=p.prefixes,
               matched_by=how, by=f"fw:{p.firewall_id}")
    # IPsec tunnels from the VPN logs
    if tunnels is None and ch is not None:
        try:
            from ..vpnmon import tunnels as vpn_tunnels
            tunnels = (await vpn_tunnels(ch, now - timedelta(hours=24), now, sorted(fw_ids) or None))["tunnels"]
        except Exception:
            tunnels = []
    for t in tunnels or []:
        if t.get("firewall_id") not in fw_ids or not t.get("remote_ip"):
            continue
        b, how = far(t["remote_ip"], kind="vpn_peer", label=f"VPN {t['remote_ip']}", address=t["remote_ip"])
        g.edge(f"fw:{t['firewall_id']}", b, "ipsec", "wan", "FortiGate VPN logs", "up" if t.get("status") == "up" else ("down" if t.get("status") == "down" else "unknown"),
               detail=t.get("tunnel", ""), tunnel=t.get("tunnel"), matched_by=how, by=f"fw:{t['firewall_id']}")
    # ISP circuits (inventory) and their open outages
    links = (await s.execute(select(IspLink).where(IspLink.enabled.is_(True), IspLink.hidden.is_(False)))).scalars().all()
    open_out = {o.isp_link_id for o in (await s.execute(select(WanOutage).where(WanOutage.recovered_at.is_(None)))).scalars() if o.isp_link_id}
    for lk in links:
        if site and (lk.site or "").lower() != site.lower():
            continue
        isp = lk.isp_name or lk.as_org or lk.alias or "unknown provider"
        b = g.node(f"isp:{isp}", kind="external", type="isp", label=isp, managed=False)
        a = f"fw:{lk.firewall_id}" if lk.firewall_id in fw_ids else g.node(f"site:{lk.site or lk.name}", kind="external", type="site",
                                                                            label=lk.site or lk.name or "site", managed=False)
        g.edge(a, b, "isp", "wan", "circuit inventory", "down" if lk.id in open_out else "up", detail=lk.interface or lk.name,
               circuit=lk.name or lk.circuit_id, role=lk.role, bandwidth_mbps=lk.bandwidth_mbps, matched_by="configured", by="")
    used = {e["a"] for e in g.edges.values()} | {e["b"] for e in g.edges.values()}
    nodes = [n for n in g.nodes.values() if n["id"] in used]
    edges = sorted(g.edges.values(), key=lambda e: (e["layer"], e["protocol"], e["a"], e["b"]))
    by_proto: dict[str, dict] = {}
    for e in edges:
        c = by_proto.setdefault(e["protocol"], {"total": 0, "down": 0})
        c["total"] += 1
        c["down"] += e["state"] == "down"
    return {"generated_at": now.isoformat(), "site": site, "nodes": nodes, "edges": edges, "summary": by_proto,
            "external": sum(1 for n in nodes if not n.get("managed"))}
