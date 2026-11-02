"""Threat-intelligence indicators: feed parsing and fast in-memory matching."""
from __future__ import annotations

import bisect
import ipaddress
import re
from dataclasses import dataclass

IPV4_CIDR = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(/\d{1,2})?(?![\d.])")
DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
SKIP_DOMAINS = {"localhost", "localhost.localdomain", "local", "broadcasthost"}


def parse_feed(text: str, kind: str, max_items: int = 500_000) -> list[tuple[str, str]]:
    """Extract (indicator, type) from plain/CSV/JSON-lines feeds. Comment lines (#, ;, //) are skipped.
    kind: ip | cidr | domain | mixed."""
    out: list[tuple[str, str]] = []
    seen = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#;" or line.startswith("//"):
            continue
        if kind in ("ip", "cidr", "mixed"):
            for ip, mask in IPV4_CIDR.findall(line):
                try:
                    net = ipaddress.ip_network(ip + (mask or ""), strict=False)
                except ValueError:
                    continue
                if not net.is_global:
                    continue  # never treat private/reserved space as an IOC
                ind, typ = (str(net.network_address), "ip") if net.prefixlen == 32 else (str(net), "cidr")
                if ind not in seen:
                    seen.add(ind)
                    out.append((ind, typ))
                if kind != "mixed":
                    break
        if kind in ("domain", "mixed"):
            token = line.split()[-1].lower().strip(",;\"'").rstrip(".")
            if token.startswith(("http://", "https://")):
                token = token.split("/")[2].split(":")[0]
            if DOMAIN.match(token) and token not in SKIP_DOMAINS and token not in seen:
                seen.add(token)
                out.append((token, "domain"))
        if len(out) >= max_items:
            break
    return out


def _ipv4_int(ip: str) -> int | None:
    """Dotted-quad → int, with ipaddress.IPv4Address's rules (no leading zeros, 0-255) but ~10x faster."""
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    v = 0
    for p in parts:
        if not p.isdigit() or not p.isascii() or len(p) > 3 or (len(p) > 1 and p[0] == "0"):
            return None
        n = int(p)
        if n > 255:
            return None
        v = (v << 8) | n
    return v


@dataclass
class Hit:
    indicator: str
    source: str
    category: str


def _flatten(nets: list[tuple[int, int, "Hit"]]) -> list[tuple[int, int, "Hit"]]:
    """CIDR blocks are nested or disjoint, so they flatten into non-overlapping [start, end] segments in which the most
    specific block wins. A lookup is then one binary search. Scanning back from the nearest start (the old way) cost
    O(blocks starting inside the widest block) per lookup: one /8 in a feed meant thousands of steps for every event."""
    out: list[tuple[int, int, Hit]] = []
    stack: list[tuple[int, int, Hit]] = []
    cursor = 0

    def emit(a: int, b: int, h: Hit) -> None:
        if a <= b:
            out.append((a, b, h))

    for a, b, h in sorted(nets, key=lambda n: (n[0], -n[1])):  # parents before the blocks nested inside them
        while stack and stack[-1][1] < a:
            sa, sb, sh = stack.pop()
            emit(max(cursor, sa), sb, sh)
            cursor = sb + 1
        if stack:
            emit(cursor, a - 1, stack[-1][2])                   # enclosing block covers the gap before this one
        cursor = a
        stack.append((a, b, h))
    while stack:
        sa, sb, sh = stack.pop()
        emit(max(cursor, sa), sb, sh)
        cursor = sb + 1
    return out


class IndicatorSet:
    def __init__(self, rows: list[tuple[str, str, str, str]] = ()):
        """rows: (indicator, type, source, category)"""
        self.ips: dict[str, Hit] = {}
        self.domains: dict[str, Hit] = {}
        self._starts: list[int] = []
        self._nets: list[tuple[int, int, Hit]] = []
        nets = []
        for ind, typ, src, cat in rows:
            h = Hit(ind, src, cat)
            if typ == "ip":
                self.ips[ind] = h
            elif typ == "domain":
                self.domains[ind.lower()] = h
            elif typ == "cidr":
                try:
                    n = ipaddress.ip_network(ind, strict=False)
                except ValueError:
                    continue
                if n.version == 4:
                    nets.append((int(n.network_address), int(n.broadcast_address), h))
        self._nets = nets
        self._segs = _flatten(nets)
        self._starts = [a for a, _, _ in self._segs]

    def __len__(self):
        return len(self.ips) + len(self.domains) + len(self._nets)

    def match_ip(self, ip: str) -> Hit | None:
        if not ip:
            return None
        h = self.ips.get(ip)
        if h or not self._nets or ":" in ip:
            return h
        v = _ipv4_int(ip)
        if v is None:
            return None
        i = bisect.bisect_right(self._starts, v) - 1
        if i >= 0 and v <= self._segs[i][1]:
            return self._segs[i][2]
        return None

    def match_domain(self, name: str) -> Hit | None:
        if not name or not self.domains:
            return None
        labels = name.lower().rstrip(".").split(".")
        for i in range(len(labels) - 1):  # exact name, then parent domains (evil.com matches a.b.evil.com)
            h = self.domains.get(".".join(labels[i:]))
            if h:
                return h
        return None

    def match_event(self, ev: dict) -> Hit | None:
        return (self.match_ip(ev.get("dst_ip", "")) or self.match_ip(ev.get("src_ip", ""))
                or self.match_domain(ev.get("dns_qname", "")) or self.match_domain(ev.get("hostname", "")))
