"""Outbound destination checks (SSRF guard) for admin-configured hosts: FortiGates, webhooks, TI feeds, SMTP relays.

Private (RFC 1918 / ULA) addresses are legitimate destinations here: FortiGate management networks and internal relays
live there. What is refused: loopback, link-local (which includes cloud metadata at 169.254.169.254), unspecified,
multicast and reserved ranges, plus the names of this deployment's own containers. OUTBOUND_ALLOWED_HOSTS exempts
specific names/addresses when an operator really needs one of them.

Residual risk: a hostname is resolved and checked before the request, then resolved again by the HTTP client, so a
DNS server under attacker control could still rebind between the two lookups. Network egress rules remain the
stronger control.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from urllib.parse import urlsplit

import httpx

from .config import get_settings

# docker-compose service names of this stack and well-known metadata aliases
BLOCKED_HOSTNAMES = {"localhost", "postgres", "clickhouse", "api", "web", "worker", "syslog", "migrate",
                     "metadata", "metadata.google.internal", "instance-data"}
METADATA_IPS = {ipaddress.ip_address("fd00:ec2::254")}  # AWS IMDS over IPv6 (ULA, so not caught as link-local)


class DestinationError(ValueError):
    pass


def _allowed() -> set[str]:
    return {h.strip().lower() for h in get_settings().outbound_allowed_hosts.split(",") if h.strip()}


def _norm(host: str) -> str:
    return (host or "").strip().strip("[]").rstrip(".").lower()


def check_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address | str) -> None:
    ip = ipaddress.ip_address(ip) if isinstance(ip, str) else ip
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if (ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast or ip.is_reserved
            or ip in METADATA_IPS):
        raise DestinationError(f"destination address {ip} is not allowed (loopback, link-local/metadata or reserved)")


def check_host_static(host: str) -> str:
    """Checks that need no DNS: literal IPs and blocked names. Returns the normalised host."""
    h = _norm(host)
    if not h:
        raise DestinationError("destination host is empty")
    if h in _allowed():
        return h
    if h in BLOCKED_HOSTNAMES or h.endswith(".localhost"):
        raise DestinationError(f"destination host '{h}' is not allowed (internal service name)")
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return h  # a name; resolved addresses are checked by acheck_host
    check_ip(ip)
    return h


async def acheck_host(host: str, port: int = 443) -> None:
    """Static checks plus every address the name currently resolves to. Unresolvable names pass: the connection
    attempt fails on its own and reports that."""
    h = check_host_static(host)
    if h in _allowed():
        return
    try:
        ipaddress.ip_address(h)
        return
    except ValueError:
        pass
    for addr in await resolve(h):
        check_ip(addr)


_dns_cache: dict[str, tuple[float, list[str]]] = {}
DNS_TTL = 60.0


async def resolve(host: str) -> list[str]:
    """Addresses a name resolves to (cached briefly; failures and timeouts give [])."""
    now = time.monotonic()
    hit = _dns_cache.get(host)
    if hit and hit[0] > now:
        return hit[1]
    try:
        infos = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM), 5)
        addrs = sorted({i[4][0].split("%")[0] for i in infos})
    except (OSError, UnicodeError, asyncio.TimeoutError):
        addrs = []
    if len(_dns_cache) > 4096:
        _dns_cache.clear()
    _dns_cache[host] = (now + DNS_TTL, addrs)
    return addrs


def check_url_static(url: str, schemes: tuple[str, ...] = ("https",)) -> str:
    parts = urlsplit(url or "")
    if parts.scheme.lower() not in schemes:
        raise DestinationError(f"URL scheme must be one of {', '.join(s + '://' for s in schemes)}")
    if parts.username or parts.password:
        raise DestinationError("credentials in the URL are not allowed")
    check_host_static(parts.hostname or "")
    return url


def request_guard(schemes: tuple[str, ...] = ("https",)):
    """httpx request event hook: validates the first request and every redirect hop."""
    async def hook(request: httpx.Request) -> None:
        if request.url.scheme not in schemes:
            raise DestinationError(f"URL scheme {request.url.scheme}:// is not allowed")
        await acheck_host(request.url.host, request.url.port or (443 if request.url.scheme == "https" else 80))
    return hook
