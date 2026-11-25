"""Network ranges, zones and direction.

Administrators define ranges (traffic_networks): CIDR, internal or not, site, VLAN, zone. An address belongs to the
most specific range containing it. Until at least one internal range is defined, the private address blocks below
count as internal (RFC 1918, RFC 6598 shared space, RFC 4193 unique local, link-local); no site subnet is built in.

Direction of a flow, from the two endpoints:
  internal → internal  east-west     internal → external  outbound
  external → internal  inbound       external → external  transit
"""
from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import TrafficNetwork, TrafficVlanPolicy

PRIVATE = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "fc00::/7", "fe80::/10"]
ZONES = ("corporate", "guest", "iot", "cctv", "management", "server", "dmz", "vpn", "voice", "other")
DIRECTIONS = ("east_west", "outbound", "inbound", "transit")
MAX_SQL_NETWORKS = 500

# zone policies seeded once (editable / removable). They only take effect for ranges an administrator tags with a zone.
DEFAULT_POLICIES = [
    ("pol-guest-internal", "Guest must not reach internal zones", "zone:guest", "zone:corporate", "high"),
    ("pol-guest-mgmt", "Guest must not reach management", "zone:guest", "zone:management", "high"),
    ("pol-guest-server", "Guest must not reach servers", "zone:guest", "zone:server", "high"),
    ("pol-iot-corp", "IoT must not reach corporate", "zone:iot", "zone:corporate", "medium"),
    ("pol-iot-mgmt", "IoT must not reach management", "zone:iot", "zone:management", "high"),
    ("pol-cctv-corp", "CCTV must not reach corporate", "zone:cctv", "zone:corporate", "medium"),
    ("pol-cctv-guest", "CCTV must not reach guest", "zone:cctv", "zone:guest", "medium"),
    ("pol-cctv-external", "CCTV must not reach the internet", "zone:cctv", "external", "medium"),
    ("pol-corp-mgmt", "Only management may reach management (corporate)", "zone:corporate", "zone:management", "medium"),
]


async def ensure_default_policies(s: AsyncSession) -> int:
    have = {k for (k,) in (await s.execute(select(TrafficVlanPolicy.builtin_key))).all()}
    from .settings import load_settings, save_settings
    st = await load_settings(s)
    seeded = set(st.get("_seeded_policies") or [])
    n = 0
    for key, name, src, dst, sev in DEFAULT_POLICIES:
        if key in have or key in seeded:
            continue
        s.add(TrafficVlanPolicy(name=name, src=src, dst=dst, action="deny", severity=sev, builtin_key=key, updated_by="built-in",
                                description="Built-in zone policy; applies once ranges are tagged with these zones"))
        n += 1
    await save_settings(s, {"_seeded_policies": sorted(seeded | {p[0] for p in DEFAULT_POLICIES})}, "built-in")
    return n


@dataclass
class Net:
    net: ipaddress._BaseNetwork
    cidr: str
    name: str = ""
    site: str = ""
    vlan: int | None = None
    zone: str = ""
    internal: bool = True


@dataclass
class Networks:
    nets: list[Net] = field(default_factory=list)        # most specific first
    configured: bool = False

    @property
    def internal_cidrs(self) -> list[str]:
        own = [n.cidr for n in self.nets if n.internal]
        return own if own else list(PRIVATE)

    def lookup(self, ip: str) -> Net | None:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for n in self.nets:
            if a.version == n.net.version and a in n.net:
                return n
        return None

    def is_internal(self, ip: str) -> bool:
        n = self.lookup(ip)
        if n is not None:
            return n.internal
        if any(x.internal for x in self.nets):
            return False
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in ipaddress.ip_network(c) for c in PRIVATE if ipaddress.ip_network(c).version == a.version)

    def direction(self, src: str, dst: str) -> str:
        si, di = self.is_internal(src), self.is_internal(dst)
        return "east_west" if si and di else "outbound" if si else "inbound" if di else "transit"

    # ---------------------------------------------------------------- SQL (ClickHouse) expressions
    def sql_internal(self, col: str, pname: str = "inet") -> tuple[str, dict]:
        """1 when the address is internal. Explicit non-internal ranges inside an internal one win (most specific)."""
        cidrs = self.internal_cidrs[:MAX_SQL_NETWORKS]
        ext = [n.cidr for n in self.nets if not n.internal][:MAX_SQL_NETWORKS]
        expr = f"arrayExists(c -> isIPAddressInRange({col}, c), {{{pname}:Array(String)}})"
        p = {pname: cidrs}
        if ext:
            expr = f"({expr} AND NOT arrayExists(c -> isIPAddressInRange({col}, c), {{{pname}_x:Array(String)}}))"
            p[pname + "_x"] = ext
        return expr, p

    def sql_attr(self, col: str, attr: str, pname: str) -> tuple[str, dict]:
        """VLAN / zone / site / name of the most specific configured range, '' (or 0 for VLAN) when none."""
        rows = [n for n in self.nets if getattr(n, attr) not in (None, "")][:MAX_SQL_NETWORKS]
        if not rows:
            return ("toUInt16(0)" if attr == "vlan" else "''"), {}
        cidrs = [n.cidr for n in rows]
        vals = [int(n.vlan) for n in rows] if attr == "vlan" else [str(getattr(n, attr)) for n in rows]
        typ = "UInt16" if attr == "vlan" else "String"
        idx = f"arrayFirstIndex(c -> isIPAddressInRange({col}, c), {{{pname}_c:Array(String)}})"
        default = "toUInt16(0)" if attr == "vlan" else "''"
        return f"if({idx} = 0, {default}, arrayElement({{{pname}_v:Array({typ})}}, {idx}))", {pname + "_c": cidrs, pname + "_v": vals}


_CACHE: dict = {"t": 0.0, "nets": None}


async def load(s: AsyncSession, max_age: float = 30.0) -> Networks:
    if _CACHE["nets"] is not None and time.monotonic() - _CACHE["t"] < max_age:
        return _CACHE["nets"]
    out = []
    for r in (await s.execute(select(TrafficNetwork))).scalars():
        try:
            net = ipaddress.ip_network(r.cidr, strict=False)
        except ValueError:
            continue
        out.append(Net(net=net, cidr=str(net), name=r.name, site=r.site, vlan=r.vlan, zone=r.zone or "", internal=r.internal))
    out.sort(key=lambda n: (-n.net.prefixlen, n.net.version))
    nets = Networks(nets=out, configured=bool(out))
    _CACHE.update(t=time.monotonic(), nets=nets)
    return nets


def invalidate() -> None:
    _CACHE.update(t=0.0, nets=None)


def endpoint_matches(spec: str, zone: str, vlan: int, internal: bool) -> bool:
    """Policy endpoint: "any", "external", "internal", "zone:<name>", "vlan:<id>"."""
    spec = (spec or "").strip().lower()
    if spec == "any":
        return True
    if spec == "external":
        return not internal
    if spec == "internal":
        return internal
    if spec.startswith("zone:"):
        return internal and zone == spec[5:]
    if spec.startswith("vlan:"):
        try:
            return vlan == int(spec[5:])
        except ValueError:
            return False
    return False


def valid_endpoint(spec: str) -> bool:
    spec = (spec or "").strip().lower()
    if spec in ("any", "external", "internal"):
        return True
    if spec.startswith("zone:"):
        return spec[5:] in ZONES
    if spec.startswith("vlan:"):
        return spec[5:].isdigit() and 0 < int(spec[5:]) < 4095
    return False
