"""Append-only, hash-chained access audit. Each row commits to the previous row's hash, so a changed, removed or
reordered row breaks the chain at that point (verify()). The application never updates or deletes these rows."""
from __future__ import annotations

import asyncio
import hashlib
import json
import weakref
from datetime import datetime, timezone

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import NmsAccessAudit

# one writer at a time in this process (SQLite has no advisory lock; PostgreSQL also locks below); one lock per event loop
_LOCKS: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock]" = weakref.WeakKeyDictionary()


def _lock() -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    lk = _LOCKS.get(loop)
    if lk is None:
        lk = _LOCKS[loop] = asyncio.Lock()
    return lk
_SECRET_KEYS = ("password", "secret", "private_key", "token", "ticket", "passphrase", "key")


def _redact(d):
    if isinstance(d, dict):
        return {k: ("<redacted>" if any(x in k.lower() for x in _SECRET_KEYS) and k.lower() not in ("host_key_changed",) else _redact(v))
                for k, v in d.items()}
    if isinstance(d, list):
        return [_redact(x) for x in d]
    return d


def _aware(v: datetime) -> datetime:
    return v if v.tzinfo else v.replace(tzinfo=timezone.utc)


def _body(ts: datetime, username: str, action: str, switch_id, session_id: str, target: str, detail: dict, client_ip: str, success: bool) -> str:
    return json.dumps({"ts": _aware(ts).isoformat(), "username": username, "action": action, "switch_id": switch_id, "session_id": session_id,
                       "target": target, "detail": detail, "client_ip": client_ip, "success": success}, sort_keys=True, default=str)


async def record(s: AsyncSession, username: str, action: str, *, switch_id: int | None = None, session_id: str = "", target: str = "",
                 detail: dict | None = None, client_ip: str = "", success: bool = True) -> NmsAccessAudit:
    async with _lock():
        return await _record(s, username, action, switch_id=switch_id, session_id=session_id, target=target, detail=detail,
                             client_ip=client_ip, success=success)


async def _record(s: AsyncSession, username: str, action: str, *, switch_id, session_id, target, detail, client_ip, success) -> NmsAccessAudit:
    if s.bind.dialect.name == "postgresql":
        await s.execute(text("SELECT pg_advisory_xact_lock(724520)"))   # one chain across the gateway and the worker
    last = (await s.execute(select(NmsAccessAudit.hash).order_by(NmsAccessAudit.id.desc()).limit(1))).scalar() or ""
    ts = datetime.now(timezone.utc).replace(microsecond=0)
    det = _redact(detail or {})
    row = NmsAccessAudit(ts=ts, username=username[:64], action=action[:64], switch_id=switch_id, session_id=session_id, target=target[:255],
                         detail=det, client_ip=client_ip[:64], success=success, prev_hash=last,
                         hash=hashlib.sha256((last + _body(ts, username[:64], action[:64], switch_id, session_id, target[:255], det, client_ip[:64], success)).encode()).hexdigest())
    s.add(row)
    await s.commit()           # the chain lock is held until the row is committed
    return row


async def verify(s: AsyncSession) -> dict:
    prev, n = "", 0
    for r in (await s.execute(select(NmsAccessAudit).order_by(NmsAccessAudit.id))).scalars():
        h = hashlib.sha256((prev + _body(r.ts, r.username, r.action, r.switch_id, r.session_id, r.target, r.detail, r.client_ip, r.success)).encode()).hexdigest()
        if r.prev_hash != prev or r.hash != h:
            return {"ok": False, "checked": n, "broken_at": r.id}
        prev, n = r.hash, n + 1
    return {"ok": True, "checked": n}
