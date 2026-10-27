"""Exact interval-set arithmetic for IP address spaces and port ranges."""
from __future__ import annotations

import ipaddress


class IntervalSet:
    """Sorted, merged, inclusive integer intervals."""

    __slots__ = ("iv",)

    def __init__(self, intervals=()):
        self.iv: list[tuple[int, int]] = []
        for lo, hi in sorted(intervals):
            if lo > hi:
                continue
            if self.iv and lo <= self.iv[-1][1] + 1:
                self.iv[-1] = (self.iv[-1][0], max(self.iv[-1][1], hi))
            else:
                self.iv.append((lo, hi))

    def __bool__(self):
        return bool(self.iv)

    def __eq__(self, other):
        return isinstance(other, IntervalSet) and self.iv == other.iv

    def __repr__(self):
        return f"IntervalSet({self.iv})"

    def size(self) -> int:
        return sum(hi - lo + 1 for lo, hi in self.iv)

    def union(self, other: IntervalSet) -> IntervalSet:
        return IntervalSet(self.iv + other.iv)

    def intersection(self, other: IntervalSet) -> IntervalSet:
        out, i, j = [], 0, 0
        a, b = self.iv, other.iv
        while i < len(a) and j < len(b):
            lo, hi = max(a[i][0], b[j][0]), min(a[i][1], b[j][1])
            if lo <= hi:
                out.append((lo, hi))
            if a[i][1] < b[j][1]:
                i += 1
            else:
                j += 1
        return IntervalSet(out)

    def difference(self, other: IntervalSet) -> IntervalSet:
        out = []
        for lo, hi in self.iv:
            cur = lo
            for olo, ohi in other.iv:
                if ohi < cur or olo > hi:
                    continue
                if olo > cur:
                    out.append((cur, olo - 1))
                cur = max(cur, ohi + 1)
                if cur > hi:
                    break
            if cur <= hi:
                out.append((cur, hi))
        return IntervalSet(out)

    def covers(self, other: IntervalSet) -> bool:
        return not other.difference(self)


V4_ALL = (0, 2**32 - 1)
V6_ALL = (0, 2**128 - 1)


class AddrSpace:
    """IPv4 + IPv6 address space as two interval sets."""

    __slots__ = ("v4", "v6")

    def __init__(self, v4: IntervalSet | None = None, v6: IntervalSet | None = None):
        self.v4 = v4 or IntervalSet()
        self.v6 = v6 or IntervalSet()

    @classmethod
    def any4(cls):
        return cls(IntervalSet([V4_ALL]))

    @classmethod
    def any6(cls):
        return cls(v6=IntervalSet([V6_ALL]))

    @classmethod
    def from_network(cls, text: str) -> AddrSpace:
        net = ipaddress.ip_network(text, strict=False)
        rng = (int(net.network_address), int(net.broadcast_address))
        return cls(IntervalSet([rng])) if net.version == 4 else cls(v6=IntervalSet([rng]))

    @classmethod
    def from_range(cls, start: str, end: str) -> AddrSpace:
        a, b = ipaddress.ip_address(start), ipaddress.ip_address(end)
        if a.version != b.version:
            raise ValueError("mixed address family range")
        iv = IntervalSet([(int(a), int(b))])
        return cls(iv) if a.version == 4 else cls(v6=iv)

    def union(self, o: AddrSpace) -> AddrSpace:
        return AddrSpace(self.v4.union(o.v4), self.v6.union(o.v6))

    def intersection(self, o: AddrSpace) -> AddrSpace:
        return AddrSpace(self.v4.intersection(o.v4), self.v6.intersection(o.v6))

    def difference(self, o: AddrSpace) -> AddrSpace:
        return AddrSpace(self.v4.difference(o.v4), self.v6.difference(o.v6))

    def covers(self, o: AddrSpace) -> bool:
        return self.v4.covers(o.v4) and self.v6.covers(o.v6)

    def __bool__(self):
        return bool(self.v4) or bool(self.v6)

    def describe(self) -> str:
        parts = []
        if self.v4:
            parts.append(f"{self.v4.size():,} IPv4")
        if self.v6:
            parts.append("IPv6 range(s)")
        return ", ".join(parts) or "empty"


ALL_PORTS = (0, 65535)
PORT_PROTOCOLS = (6, 17, 132)  # TCP, UDP, SCTP carry ports


class ServiceSpace:
    """Destination ports per port-protocol plus a set of whole IP protocols (ICMP, GRE, ...)."""

    __slots__ = ("ports", "protos")

    def __init__(self, ports: dict[int, IntervalSet] | None = None, protos: IntervalSet | None = None):
        self.ports = {p: s for p, s in (ports or {}).items() if s}
        self.protos = protos or IntervalSet()  # whole protocols, all ports included

    @classmethod
    def any(cls):
        return cls(protos=IntervalSet([(0, 255)]))

    def _ports_for(self, proto: int) -> IntervalSet:
        if self.protos.intersection(IntervalSet([(proto, proto)])):
            return IntervalSet([ALL_PORTS])
        return self.ports.get(proto, IntervalSet())

    def union(self, o: ServiceSpace) -> ServiceSpace:
        keys = set(self.ports) | set(o.ports)
        return ServiceSpace({k: self.ports.get(k, IntervalSet()).union(o.ports.get(k, IntervalSet())) for k in keys},
                            self.protos.union(o.protos))

    def covers(self, o: ServiceSpace) -> bool:
        if not self.protos.covers(o.protos.difference(IntervalSet([(p, p) for p in PORT_PROTOCOLS]))):
            return False
        for p in PORT_PROTOCOLS:
            if not self._ports_for(p).covers(o._ports_for(p)):
                return False
        return True

    def intersects(self, o: ServiceSpace) -> bool:
        non_port = IntervalSet([(p, p) for p in PORT_PROTOCOLS])
        if self.protos.difference(non_port).intersection(o.protos.difference(non_port)):
            return True
        return any(self._ports_for(p).intersection(o._ports_for(p)) for p in PORT_PROTOCOLS)

    def describe(self) -> str:
        if self.protos.covers(IntervalSet([(0, 255)])):
            return "all services"
        names = {6: "TCP", 17: "UDP", 132: "SCTP"}
        parts = []
        for p in PORT_PROTOCOLS:
            s = self._ports_for(p)
            if s:
                parts.append(f"{names[p]} " + ",".join(f"{a}" if a == b else f"{a}-{b}" for a, b in s.iv[:6]) + ("…" if len(s.iv) > 6 else ""))
        other = self.protos.difference(IntervalSet([(p, p) for p in PORT_PROTOCOLS]))
        if other:
            parts.append("IP proto " + ",".join(f"{a}" if a == b else f"{a}-{b}" for a, b in other.iv))
        return "; ".join(parts) or "none"
