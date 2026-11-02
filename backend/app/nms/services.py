"""Service checks (Zabbix simple checks / web scenarios, LibreNMS services): TCP connect, HTTP(S) request, DNS lookup
and TLS certificate expiry, run by the worker against operator-defined targets.

* Read-only probes: a TCP connect, one HTTP GET (no redirects followed, body read capped), a resolver lookup, a TLS
  handshake. Nothing is sent beyond what the protocol needs.
* TLS certificates are always verified (system trust store). A certificate that does not verify is a critical result
  with the verifier's reason; there is no option to skip verification.
* A latency the check could not measure (refused, timed out, resolver error) is stored as NULL, never 0.
* State: ok / warning (slow, certificate expiring, unexpected but answered) / critical (failed). Alerts require
  `min_failures` consecutive critical results (nms_service_down) so a single lost packet does not page anyone.
"""
from __future__ import annotations

import asyncio
import logging
import re
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import NmsService

log = logging.getLogger("nms.services")
KINDS = ("tcp", "http", "dns", "tls")
DNS_RECORDS = ("A", "AAAA")
RESULT_COLS = ["ts", "service_id", "state", "latency_ms", "message"]
MAX_BODY = 256 * 1024
_inflight: set[int] = set()


@dataclass
class Result:
    state: str                    # ok | warning | critical
    latency_ms: float | None
    message: str
    cert_expires_at: datetime | None = None


def parse_expect(expect: str) -> list[tuple[int, int]]:
    """"200,204,300-399" → [(200, 200), (204, 204), (300, 399)]; empty → 200-399."""
    out = []
    for part in (expect or "200-399").replace(" ", "").split(","):
        if not part:
            continue
        m = re.fullmatch(r"(\d{3})(?:-(\d{3}))?", part)
        if not m:
            raise ValueError(f"invalid status code or range: {part}")
        a, b = int(m.group(1)), int(m.group(2) or m.group(1))
        if not 100 <= a <= b <= 599:
            raise ValueError(f"invalid status code range: {part}")
        out.append((a, b))
    return out


def validate(kind: str, target: str, port: int | None, expect: str, record: str) -> None:
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {', '.join(KINDS)}")
    if kind == "http":
        u = urlsplit(target)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise ValueError("an HTTP check needs an http:// or https:// URL")
        if u.username or u.password:
            raise ValueError("credentials in the URL are not allowed")
        parse_expect(expect)
    else:
        if not re.fullmatch(r"[A-Za-z0-9.\-:_\[\]]{1,253}", target or ""):
            raise ValueError("target must be a host name or IP address")
    if kind in ("tcp", "tls") and not (port and 1 <= port <= 65535):
        raise ValueError("a TCP / TLS check needs a port (1-65535)")
    if kind == "dns" and record not in DNS_RECORDS:
        raise ValueError(f"record must be one of {', '.join(DNS_RECORDS)}")


def _ms(t0: float) -> float:
    return round((time.monotonic() - t0) * 1000, 1)


def _slow(svc: NmsService, r: Result) -> Result:
    if r.state == "ok" and svc.latency_warn_ms and r.latency_ms is not None and r.latency_ms > svc.latency_warn_ms:
        return Result("warning", r.latency_ms, f"{r.message}; slow: {r.latency_ms:.0f} ms > {svc.latency_warn_ms} ms", r.cert_expires_at)
    return r


async def check_tcp(svc: NmsService, timeout: float) -> Result:
    t0 = time.monotonic()
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(svc.target, svc.port), timeout)
    except asyncio.TimeoutError:
        return Result("critical", None, f"no TCP answer from {svc.target}:{svc.port} within {timeout:.0f}s")
    except OSError as e:
        return Result("critical", None, f"TCP {svc.target}:{svc.port}: {e.strerror or e}")
    ms = _ms(t0)
    w.close()
    try:
        await w.wait_closed()
    except OSError:
        pass
    return Result("ok", ms, f"TCP {svc.target}:{svc.port} accepted the connection")


async def check_http(svc: NmsService, timeout: float, transport=None) -> Result:
    ranges = parse_expect(svc.expect)
    t0 = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, verify=True, transport=transport,
                                     headers={"User-Agent": "SentinelNMS-ServiceCheck/1.0"}) as c:
            async with c.stream("GET", svc.target) as resp:
                body = b""
                async for chunk in resp.aiter_bytes():
                    body += chunk
                    if len(body) >= MAX_BODY:
                        break
                ms = _ms(t0)
    except httpx.TimeoutException:
        return Result("critical", None, f"no HTTP response within {timeout:.0f}s")
    except httpx.ConnectError as e:
        reason = str(e)
        if "CERTIFICATE_VERIFY_FAILED" in reason or "certificate" in reason.lower():
            return Result("critical", None, f"TLS certificate verification failed: {reason[:240]}")
        return Result("critical", None, f"connection failed: {reason[:240]}")
    except httpx.HTTPError as e:
        return Result("critical", None, f"HTTP error: {type(e).__name__}: {str(e)[:200]}")
    code = resp.status_code
    if not any(a <= code <= b for a, b in ranges):
        return Result("critical", ms, f"HTTP {code} (expected {svc.expect or '200-399'})")
    if svc.match and svc.match.encode() not in body:
        return Result("critical", ms, f"HTTP {code}, but the response does not contain the expected text")
    return Result("ok", ms, f"HTTP {code} in {ms:.0f} ms")


async def check_dns(svc: NmsService, timeout: float) -> Result:
    fam = socket.AF_INET6 if svc.record == "AAAA" else socket.AF_INET
    t0 = time.monotonic()
    try:
        infos = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(svc.target, None, family=fam, type=socket.SOCK_STREAM), timeout)
    except asyncio.TimeoutError:
        return Result("critical", None, f"no {svc.record} answer for {svc.target} within {timeout:.0f}s")
    except socket.gaierror as e:
        return Result("critical", None, f"{svc.record} lookup of {svc.target} failed: {e.strerror or e}")
    ms = _ms(t0)
    addrs = sorted({i[4][0] for i in infos})
    if svc.match and svc.match.strip() not in addrs:
        return Result("critical", ms, f"{svc.target} resolves to {', '.join(addrs) or 'nothing'}, expected {svc.match.strip()}")
    return Result("ok", ms, f"{svc.target} → {', '.join(addrs[:4])}{' …' if len(addrs) > 4 else ''}")


def cert_state(expires: datetime, now: datetime, warn_days: int) -> tuple[str, str]:
    days = (expires - now).total_seconds() / 86400
    if days < 0:
        return "critical", f"certificate expired {abs(days):.0f} day(s) ago ({expires:%Y-%m-%d})"
    if days < warn_days:
        return "warning", f"certificate expires in {days:.0f} day(s) ({expires:%Y-%m-%d})"
    return "ok", f"certificate valid for {days:.0f} more day(s) (until {expires:%Y-%m-%d})"


async def check_tls(svc: NmsService, timeout: float, now: datetime) -> Result:
    ctx = ssl.create_default_context()   # verifies the chain and the host name; never disabled
    t0 = time.monotonic()
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(svc.target, svc.port, ssl=ctx, server_hostname=svc.target), timeout)
    except asyncio.TimeoutError:
        return Result("critical", None, f"no TLS handshake with {svc.target}:{svc.port} within {timeout:.0f}s")
    except ssl.SSLCertVerificationError as e:
        return Result("critical", None, f"certificate verification failed: {e.verify_message or e.reason or e}")
    except (ssl.SSLError, OSError) as e:
        return Result("critical", None, f"TLS {svc.target}:{svc.port}: {getattr(e, 'reason', None) or e}")
    ms = _ms(t0)
    cert = w.get_extra_info("peercert") or {}
    w.close()
    try:
        await w.wait_closed()
    except (OSError, ssl.SSLError):
        pass
    if not cert.get("notAfter"):
        return Result("warning", ms, "handshake succeeded but the certificate has no expiry date")
    exp = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
    st, msg = cert_state(exp, now, svc.cert_warn_days or 21)
    return Result(st, ms, msg, exp)


async def run_check(svc: NmsService, now: datetime | None = None, *, http_transport=None) -> Result:
    now = now or datetime.now(timezone.utc)
    timeout = max(1.0, min(60.0, (svc.timeout_ms or 5000) / 1000))
    if svc.kind == "tcp":
        r = await check_tcp(svc, timeout)
    elif svc.kind == "http":
        r = await check_http(svc, timeout, http_transport)
    elif svc.kind == "dns":
        r = await check_dns(svc, timeout)
    elif svc.kind == "tls":
        r = await check_tls(svc, timeout, now)
    else:
        r = Result("critical", None, f"unknown check kind {svc.kind}")
    return _slow(svc, r)


def apply(svc: NmsService, r: Result, now: datetime) -> bool:
    """Update the live state; True when the state changed."""
    changed = svc.state != r.state
    if changed:
        svc.state, svc.state_since = r.state, now
    svc.fail_streak = svc.fail_streak + 1 if r.state == "critical" else 0
    svc.last_check_at = now
    svc.last_latency_ms = r.latency_ms
    svc.last_message = r.message[:2000]
    if r.cert_expires_at:
        svc.cert_expires_at = r.cert_expires_at
    return changed


def _aware(v):
    if v is None:
        return None
    return v if v.tzinfo else v.replace(tzinfo=timezone.utc)


def due(svc: NmsService, now: datetime) -> bool:
    last = _aware(svc.last_check_at)
    return svc.enabled and (last is None or (now - last).total_seconds() >= max(30, svc.interval_seconds or 60) - 2)


async def run_due(ch, s: AsyncSession, now: datetime | None = None, concurrency: int = 20) -> dict:
    now = now or datetime.now(timezone.utc)
    svcs = [x for x in (await s.execute(select(NmsService).where(NmsService.enabled.is_(True)))).scalars() if due(x, now) and x.id not in _inflight]
    sem = asyncio.Semaphore(concurrency)

    async def one(svc):
        async with sem:
            try:
                return svc, await run_check(svc, now)
            except Exception as e:  # a defect in one check must not stop the others
                log.exception("service check %s failed", svc.id)
                return svc, Result("critical", None, f"internal error: {type(e).__name__}")
    _inflight.update(x.id for x in svcs)
    try:
        results = await asyncio.gather(*(one(x) for x in svcs))
    finally:
        _inflight.difference_update(x.id for x in svcs)
    changes = sum(apply(svc, r, now) for svc, r in results)
    await s.commit()
    rows = [{"ts": now.replace(microsecond=0), "service_id": svc.id, "state": r.state, "latency_ms": r.latency_ms, "message": r.message[:500]}
            for svc, r in results]
    if rows and ch is not None:
        try:
            await ch.ainsert("service_results", rows, RESULT_COLS)
        except Exception:
            log.exception("clickhouse insert into service_results failed")
    return {"checked": len(results), "changes": changes}


def row(svc: NmsService, now: datetime, switch_names: dict[int, str] | None = None) -> dict:
    exp = _aware(svc.cert_expires_at)
    return {"id": svc.id, "name": svc.name, "kind": svc.kind, "target": svc.target, "port": svc.port, "expect": svc.expect, "match": svc.match,
            "record": svc.record, "switch_id": svc.switch_id, "switch": (switch_names or {}).get(svc.switch_id or 0), "site": svc.site,
            "interval_seconds": svc.interval_seconds, "timeout_ms": svc.timeout_ms, "latency_warn_ms": svc.latency_warn_ms,
            "cert_warn_days": svc.cert_warn_days, "enabled": svc.enabled, "state": svc.state if svc.enabled else "paused",
            "state_since": _iso(svc.state_since), "fail_streak": svc.fail_streak, "last_check_at": _iso(svc.last_check_at),
            "last_latency_ms": svc.last_latency_ms, "last_message": svc.last_message, "cert_expires_at": _iso(exp),
            "cert_days_left": round((exp - now).total_seconds() / 86400, 1) if exp else None}


def _iso(v):
    v = _aware(v)
    return v.isoformat() if v else None


def stale_after(svc: NmsService) -> timedelta:
    return timedelta(seconds=3 * max(30, svc.interval_seconds or 60) + 60)
