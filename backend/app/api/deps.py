import hmac
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta

from fastapi import Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from ..analytics.filters import EventFilter
from ..config import get_settings
from ..db.ch import ClickHouse, get_ch
from ..db.models import AuditLog, User
from ..db.pg import get_session
from ..security import decode_session_token

SESSION_COOKIE = "siem_session"
CSRF_COOKIE = "siem_csrf"
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}


class RateLimiter:
    """In-process sliding-window limiter (per API replica)."""

    def __init__(self):
        self.hits: dict[str, deque] = defaultdict(deque)

    def check(self, key: str, limit: int, window: float = 60.0) -> bool:
        now = time.monotonic()
        q = self.hits[key]
        while q and now - q[0] > window:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        if len(self.hits) > 50_000:
            # drop only idle keys: clearing everything would let a flood of new keys reset every client's window
            for k in [k for k, v in self.hits.items() if not v or now - v[-1] > window]:
                del self.hits[k]
        return True


limiter = RateLimiter()


def client_ip(request: Request) -> str:
    # Nginx sets X-Real-IP; it is the only trusted proxy in the deployment.
    return request.headers.get("x-real-ip") or (request.client.host if request.client else "")


def ch_dep() -> ClickHouse:
    return get_ch()


async def current_user(request: Request, s: AsyncSession = Depends(get_session)) -> User:
    token = request.cookies.get(SESSION_COOKIE)
    claims = decode_session_token(token) if token else None
    if not claims:
        raise HTTPException(401, "not authenticated")
    if request.method in UNSAFE:
        sent, bound = request.headers.get("x-csrf-token") or "", claims.get("csrf") or ""
        if not bound or not hmac.compare_digest(sent.encode(), bound.encode()):
            raise HTTPException(403, "CSRF token missing or invalid")
    user = await s.get(User, int(claims["sub"]))
    if not user or not user.is_active:
        raise HTTPException(401, "account disabled")
    if claims.get("ver", 0) != (user.session_version or 0):
        raise HTTPException(401, "session expired")  # logout, password or role change revoked this session
    if not limiter.check(f"api:{user.id}", get_settings().api_rate_limit_per_minute):
        raise HTTPException(429, "rate limit exceeded")
    request.state.user = user
    return user


async def require_admin(user: User = Depends(current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(403, "administrator role required")
    return user


async def audit(s: AsyncSession, request: Request, username: str, action: str, target: str = "",
                detail: dict | None = None, success: bool = True) -> None:
    s.add(AuditLog(username=username, action=action, target=target, detail=detail or {}, client_ip=client_ip(request),
                   success=success))
    await s.commit()


def event_filter(
    start: datetime | None = None, end: datetime | None = None, range: str | None = Query("24h", pattern=r"^(5m|15m|1h|24h|7d|30d)$"),
    firewall_id: list[int] = Query(default=[]), site: list[str] = Query(default=[]),
    category: list[str] = Query(default=[]), event_type: str | None = None, event_subtype: str | None = None,
    src_ip: str | None = None, dst_ip: str | None = None, ip: str | None = None,
    src_port: int | None = Query(None, ge=0, le=65535), dst_port: int | None = Query(None, ge=0, le=65535),
    proto: int | None = Query(None, ge=0, le=255), app: str | None = Query(None, max_length=128),
    domain: str | None = Query(None, max_length=253), dns_query: str | None = Query(None, max_length=253),
    dns_qtype: str | None = Query(None, max_length=16), dns_rcode: str | None = Query(None, max_length=16),
    action: list[str] = Query(default=[]), verdict: str | None = Query(None, pattern=r"^(allowed|denied)$"),
    policy_id: int | None = Query(None, ge=0), severity: list[str] = Query(default=[]),
    url_category: str | None = Query(None, max_length=128), source: str | None = Query(None, max_length=16),
    user: str | None = Query(None, max_length=128), q: str | None = Query(None, max_length=200),
    ql: str | None = Query(None, max_length=2000),
) -> EventFilter:
    f = EventFilter(start=start, end=end, range=range, firewall_id=firewall_id, site=site, category=category,
                    event_type=event_type, event_subtype=event_subtype, src_ip=src_ip, dst_ip=dst_ip, ip=ip,
                    src_port=src_port, dst_port=dst_port, proto=proto, app=app, domain=domain, dns_query=dns_query,
                    dns_qtype=dns_qtype, dns_rcode=dns_rcode, action=action, verdict=verdict, policy_id=policy_id,
                    severity=severity, url_category=url_category, source=source, user=user, q=q, ql=ql)
    try:
        t0, t1 = f.window()
    except ValueError as e:
        raise HTTPException(422, str(e))
    days = get_settings().max_query_range_days
    if t1 - t0 > timedelta(days=days):  # unbounded custom ranges turn into full-table scans
        raise HTTPException(422, f"time range is limited to {days} days")
    return f


def csv_safe(v):
    """Neutralise spreadsheet formula injection in exported cells (OWASP: = + - @ tab CR, also after leading spaces)."""
    if isinstance(v, str) and v.lstrip(" ")[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v


def iso(dt) -> str | None:
    """Serialize datetimes as explicit UTC (some drivers return naive values for timestamptz)."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        from datetime import timezone
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()
