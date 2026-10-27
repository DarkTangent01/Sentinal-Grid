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
        nets.sort(key=lambda x: x[0])
        self._nets = nets
        self._starts = [n[0] for n in nets]
        self._maxspan = max((b - a for a, b, _ in nets), default=0)

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
        # scan back over networks that could still contain v (bounded by the widest network)
        while i >= 0 and self._nets[i][0] >= v - self._maxspan:
            a, b, hit = self._nets[i]
            if a <= v <= b:
                return hit
            i -= 1
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
