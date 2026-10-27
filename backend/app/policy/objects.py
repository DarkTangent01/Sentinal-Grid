"""Resolve FortiGate address/service objects (as returned by /api/v2/cmdb) into exact sets.

Objects whose semantics cannot be determined statically (FQDN, geography, dynamic/SDN, wildcard masks, MAC,
interface-subnet, ISDB, user identity) are reported as *uncertain*; the analyzer then refuses to prove coverage."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from .sets import AddrSpace, IntervalSet, ServiceSpace

PREDEFINED_SERVICES = {
    # used only when the service object list was not collected (e.g. permission denied)
    "ALL": ServiceSpace.any(),
    "ALL_TCP": ServiceSpace({6: IntervalSet([(1, 65535)])}),
    "ALL_UDP": ServiceSpace({17: IntervalSet([(1, 65535)])}),
    "ALL_ICMP": ServiceSpace(protos=IntervalSet([(1, 1)])),
    "HTTP": ServiceSpace({6: IntervalSet([(80, 80)])}),
    "HTTPS": ServiceSpace({6: IntervalSet([(443, 443)])}),
    "DNS": ServiceSpace({6: IntervalSet([(53, 53)]), 17: IntervalSet([(53, 53)])}),
    "SSH": ServiceSpace({6: IntervalSet([(22, 22)])}),
    "NTP": ServiceSpace({6: IntervalSet([(123, 123)]), 17: IntervalSet([(123, 123)])}),
    "PING": ServiceSpace(protos=IntervalSet([(1, 1)])),
}


@dataclass
class Resolved:
    space: object = None
    uncertain: list[str] = field(default_factory=list)  # human-readable reasons
    missing: list[str] = field(default_factory=list)


def _names(v) -> list[str]:
    if not v:
        return []
    if isinstance(v, str):
        return [v]
    return [x.get("name") if isinstance(x, dict) else str(x) for x in v if x]


def parse_portrange(text: str) -> tuple[IntervalSet, bool]:
    """FortiOS 'tcp-portrange' format: space-separated 'dstlow[-dsthigh][:srclow[-srchigh]]'.
    Returns (destination ports, source_port_restricted)."""
    dst, src_restricted = [], False
    for tok in (text or "").split():
        d, _, s = tok.partition(":")
        lo, _, hi = d.partition("-")
        if not lo.isdigit():
            continue
        dst.append((int(lo), int(hi) if hi.isdigit() else int(lo)))
        if s and s not in ("1-65535", "0-65535"):
            src_restricted = True
    return IntervalSet(dst), src_restricted


class ObjectResolver:
    def __init__(self, objects: dict):
        """objects: {"address": [...], "addrgrp": [...], "address6": [...], "addrgrp6": [...],
                     "service_custom": [...], "service_group": [...]} as raw cmdb results."""
        self.addr = {o.get("name"): o for o in objects.get("address", []) or []}
        self.addrgrp = {o.get("name"): o for o in objects.get("addrgrp", []) or []}
        self.addr6 = {o.get("name"): o for o in objects.get("address6", []) or []}
        self.addrgrp6 = {o.get("name"): o for o in objects.get("addrgrp6", []) or []}
        self.svc = {o.get("name"): o for o in objects.get("service_custom", []) or []}
        self.svcgrp = {o.get("name"): o for o in objects.get("service_group", []) or []}
        self.have_services = bool(objects.get("service_custom"))
        self.have_addresses = bool(objects.get("address"))

    # ---------------- addresses
    def address(self, names: list[str], depth: int = 0) -> Resolved:
        r = Resolved(AddrSpace())
        for n in names:
            one = self._address_one(n, depth)
            r.space = r.space.union(one.space)
            r.uncertain += one.uncertain
            r.missing += one.missing
        return r

    def _address_one(self, name: str, depth: int) -> Resolved:
        if depth > 16:
            return Resolved(AddrSpace(), [f"address group nesting too deep at {name}"])
        if name in ("all",):
            return Resolved(AddrSpace.any4())
        if name in ("all6", "::/0"):
            return Resolved(AddrSpace.any6())
        if name == "none":
            return Resolved(AddrSpace())
        if name in self.addrgrp or name in self.addrgrp6:
            g = self.addrgrp.get(name) or self.addrgrp6.get(name)
            r = self.address(_names(g.get("member")), depth + 1)
            if g.get("exclude") == "enable" and _names(g.get("exclude-member")):
                ex = self.address(_names(g.get("exclude-member")), depth + 1)
                if ex.uncertain:
                    r.uncertain.append(f"group {name} excludes uncertain members")
                r.space = r.space.difference(ex.space)
            if g.get("type") not in (None, "", "default", "folder"):
                r.uncertain.append(f"group {name} type {g.get('type')}")
            return r
        o = self.addr.get(name) or self.addr6.get(name)
        if o is None:
            return Resolved(AddrSpace(), [f"address {name} not found in collected objects"], [name])
        t = (o.get("type") or "ipmask").lower()
        try:
            if t in ("ipmask", "ipprefix"):
                if name in self.addr6 or "ip6" in o:
                    return Resolved(AddrSpace.from_network(o.get("ip6") or "::/128"))
                subnet = (o.get("subnet") or "0.0.0.0 0.0.0.0").split()
                net = f"{subnet[0]}/{subnet[1]}" if len(subnet) == 2 else subnet[0]
                return Resolved(AddrSpace.from_network(net))
            if t == "iprange":
                return Resolved(AddrSpace.from_range(o.get("start-ip"), o.get("end-ip")))
        except (ValueError, TypeError, IndexError) as e:
            return Resolved(AddrSpace(), [f"address {name}: unparseable ({e})"])
        return Resolved(AddrSpace(), [f"address {name} is type '{t}' (resolved at runtime; cannot be evaluated statically)"])

    # ---------------- services
    def service(self, names: list[str], depth: int = 0) -> Resolved:
        r = Resolved(ServiceSpace())
        for n in names:
            one = self._service_one(n, depth)
            r.space = r.space.union(one.space)
            r.uncertain += one.uncertain
            r.missing += one.missing
        return r

    def _service_one(self, name: str, depth: int) -> Resolved:
        if depth > 16:
            return Resolved(ServiceSpace(), [f"service group nesting too deep at {name}"])
        if name in self.svcgrp:
            return self.service(_names(self.svcgrp[name].get("member")), depth + 1)
        o = self.svc.get(name)
        if o is None:
            if name.upper() in PREDEFINED_SERVICES and not self.have_services:
                return Resolved(PREDEFINED_SERVICES[name.upper()], [f"service {name} assumed to have default FortiOS definition"])
            if name == "ALL":
                return Resolved(ServiceSpace.any())
            return Resolved(ServiceSpace(), [f"service {name} not found in collected objects"], [name])
        proto = (o.get("protocol") or "TCP/UDP/SCTP").upper()
        unc = []
        if o.get("iprange") not in (None, "", "0.0.0.0") or o.get("fqdn"):
            unc.append(f"service {name} is restricted to a destination address/FQDN")
        if proto in ("TCP/UDP/SCTP", "TCP/UDP/UDP-LITE/SCTP"):
            ports = {}
            for key, p in (("tcp-portrange", 6), ("udp-portrange", 17), ("sctp-portrange", 132)):
                iv, src = parse_portrange(o.get(key, ""))
                if iv:
                    ports[p] = iv
                if src:
                    unc.append(f"service {name} restricts source ports")
            return Resolved(ServiceSpace(ports), unc)
        if proto in ("ICMP", "ICMP6"):
            return Resolved(ServiceSpace(protos=IntervalSet([(1, 1)] if proto == "ICMP" else [(58, 58)])),
                            unc + ([f"service {name} matches specific ICMP type"] if o.get("icmptype") not in (None, "", 0) else []))
        if proto == "IP":
            n = int(o.get("protocol-number") or 0)
            return Resolved(ServiceSpace.any() if n == 0 else ServiceSpace(protos=IntervalSet([(n, n)])), unc)
        return Resolved(ServiceSpace(), unc + [f"service {name} protocol {proto} not modelled"])


def ip_in(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False
