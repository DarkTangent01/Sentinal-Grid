"""Browser SSH terminal: WebSocket ⇄ SSH PTY bridge inside the gateway.

Opening a session takes two steps:
  1. POST /api/nms/access/devices/{id}/sessions (session cookie + CSRF, permission nms.device.access.ssh, session caps)
     creates a pending session and returns a one-time ticket (only its SHA-256 is stored; valid ACCESS_TICKET_SECONDS).
  2. The browser opens the WebSocket /api/nms/access/ws. The gateway checks the Origin, the session cookie (same rules
     as the REST API: active account, current session version, NMS product, permission) and then expects
     {"t": "auth", "session": id, "ticket": ...} as the first message. The ticket must belong to that user and that
     session, be unexpired and unused. Only then does the gateway connect to the device.

Messages, client → gateway: {"t": "i", "d": keystrokes}, {"t": "r", "cols", "rows"}, {"t": "close"}, {"t": "ping"}.
Gateway → client: {"t": "o", "d": output}, {"t": "status", ...}, {"t": "blocked", "command", "risk", "reason"},
{"t": "closed", "reason"}.

The session ends on: explicit disconnect, the device closing it, idle timeout, maximum duration, termination by an
administrator, the user's account or session being revoked, or the gateway shutting down. Every end is recorded.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

from fastapi import WebSocket, WebSocketDisconnect
from sqlalchemy import select

from ..config import get_settings
from ..configs.backup import mask
from ..db.models import NmsAccessCommand, NmsAccessRecording, NmsAccessSession, NmsChangeRequest, User
from ..db.pg import session_factory
from ..products import products_of
from ..security import decode_session_token
from . import audit, rbac
from .commands import H, L, LineGuard
from .channels import open_channel
from .gateway import AccessError

log = logging.getLogger("access.terminal")
_LIVE: dict[str, tuple] = {}               # session id → (stop event, stats) for sessions served by this process


def now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(v):
    return v if v is None or v.tzinfo else v.replace(tzinfo=timezone.utc)


def ticket_hash(ticket: str) -> str:
    return hashlib.sha256(ticket.encode()).hexdigest()


def origin_allowed(ws: WebSocket) -> bool:
    origin = ws.headers.get("origin") or ""
    if not origin:
        return False
    allowed = [o.strip().rstrip("/") for o in get_settings().access_allowed_origins.split(",") if o.strip()]
    if allowed:
        return origin.rstrip("/") in allowed
    host = ws.headers.get("x-forwarded-host") or ws.headers.get("host") or ""
    return bool(host) and urlsplit(origin).netloc == host


async def ws_user(ws: WebSocket, s) -> User | None:
    from ..api.deps import SESSION_COOKIE
    token = ws.cookies.get(SESSION_COOKIE)
    claims = decode_session_token(token) if token else None
    if not claims:
        return None
    user = await s.get(User, int(claims["sub"]))
    if not user or not user.is_active or claims.get("ver", 0) != (user.session_version or 0):
        return None
    if "nms" not in products_of(user) or not rbac.has(user, "nms.device.access.ssh"):
        return None
    return user


async def _still_allowed(user_id: int, version: int) -> bool:
    async with session_factory()() as s:
        u = await s.get(User, user_id)
        return bool(u and u.is_active and (u.session_version or 0) == version and rbac.has(u, "nms.device.access.ssh"))


async def _send(ws: WebSocket, msg: dict) -> None:
    await ws.send_text(json.dumps(msg))


async def handle(ws: WebSocket) -> None:
    st = get_settings()
    client_ip = ws.headers.get("x-real-ip") or (ws.client.host if ws.client else "")
    if not st.access_terminal_enabled:
        await ws.close(code=4403)
        return
    if not origin_allowed(ws):
        async with session_factory()() as s:
            await audit.record(s, "-", "terminal_refused", detail={"reason": "origin", "origin": ws.headers.get("origin", "")[:200]},
                               client_ip=client_ip, success=False)
        await ws.close(code=4403)
        return
    async with session_factory()() as s:
        user = await ws_user(ws, s)
    if user is None:
        await ws.close(code=4401)
        return
    await ws.accept()
    try:
        first = json.loads(await asyncio.wait_for(ws.receive_text(), 10))
    except (asyncio.TimeoutError, ValueError, WebSocketDisconnect):
        await ws.close(code=4400)
        return
    sid, ticket = str(first.get("session") or ""), str(first.get("ticket") or "")
    cols, rows = int(first.get("cols") or 120), int(first.get("rows") or 32)
    cols, rows = max(20, min(cols, 400)), max(5, min(rows, 200))

    async with session_factory()() as s:
        row = await s.get(NmsAccessSession, sid) if sid else None
        ok = (row is not None and row.user_id == user.id and row.state == "pending" and row.ticket_hash
              and hmac.compare_digest(row.ticket_hash, ticket_hash(ticket)) and _aware(row.ticket_expires_at) and _aware(row.ticket_expires_at) > now())
        if not ok:
            await audit.record(s, user.username, "terminal_refused", session_id=sid[:36], detail={"reason": "ticket"}, client_ip=client_ip, success=False)
            if row is not None and row.user_id == user.id and row.state == "pending":
                row.state, row.result, row.ended_at, row.ticket_hash = "expired", "refused", now(), ""
                await s.commit()
            await _send(ws, {"t": "closed", "reason": "invalid or expired ticket"})
            await ws.close(code=4403)
            return
        row.ticket_hash = ""                         # single use
        row.client_ip = client_ip or row.client_ip
        await s.commit()
        try:
            max_risk = L
            if row.mode == "change":
                cr = await s.get(NmsChangeRequest, row.change_id) if row.change_id else None
                if cr is None or cr.status not in ("approved", "executing") or cr.switch_id != row.switch_id:
                    raise AccessError(409, "the change request is not approved for this device")
                max_risk = H
            channel, latency, how, banner, detail = await open_channel(s, user, row, cols, rows)
        except AccessError as e:
            row.state, row.result, row.ended_at, row.termination_reason = "failed", e.kind, now(), e.message[:64]
            await s.commit()
            await audit.record(s, user.username, "terminal_connect", switch_id=row.switch_id, session_id=sid, target=row.device_name,
                               detail={"result": e.kind, "error": e.message[:300], "protocol": row.protocol}, client_ip=client_ip, success=False)
            await _send(ws, {"t": "closed", "reason": e.message})
            await ws.close(code=4409)
            return
        row.state, row.result, row.connected_at, row.last_activity_at, row.latency_ms = "active", "connected", now(), now(), latency
        await s.commit()
        await audit.record(s, user.username, "terminal_connect", switch_id=row.switch_id, session_id=sid, target=row.device_name,
                           detail={"result": "connected", "mode": row.mode, "change_id": row.change_id, "credential": how, "latency_ms": latency,
                                   **detail}, client_ip=client_ip)
        recording, switch_id, device_name, mode, change_id = row.recording, row.switch_id, row.device_name, row.mode, row.change_id

    stop = asyncio.Event()
    guard = LineGuard(max_risk=max_risk)
    stats = {"in": 0, "out": 0, "commands": 0, "blocked": 0, "last": time.monotonic(), "reason": ""}
    _LIVE[sid] = (stop, stats)
    transcript: list[str] = []
    tsize = [0]
    pending: list[NmsAccessCommand] = []
    started = time.monotonic()
    if banner:                                          # what the device printed while the gateway logged in (Telnet)
        guard.device_output(banner)
        await _send(ws, {"t": "o", "d": banner})
    await _send(ws, {"t": "status", "state": "connected", "device": device_name, "mode": mode, "latency_ms": latency, "protocol": detail.get("protocol"),
                     "cleartext": bool(detail.get("cleartext")),
                     "idle_timeout": st.access_idle_timeout_seconds, "max_seconds": st.access_max_session_seconds})

    async def from_device():
        while not stop.is_set():
            data = await channel.read()
            if not data:
                stats["reason"] = stats["reason"] or "closed by the device"
                stop.set()
                return
            stats["out"] += len(data)
            guard.device_output(data)
            if recording == "full" and tsize[0] < st.access_recording_max_bytes:
                transcript.append(data)
                tsize[0] += len(data)
            await _send(ws, {"t": "o", "d": data})

    async def from_browser():
        while not stop.is_set():
            try:
                msg = json.loads(await ws.receive_text())
            except WebSocketDisconnect:
                stats["reason"] = stats["reason"] or "browser disconnected"
                stop.set()
                return
            except ValueError:
                continue
            kind = msg.get("t")
            if kind == "i":
                data = str(msg.get("d") or "")[:8192]
                stats["in"] += len(data)
                stats["last"] = time.monotonic()
                fwd, decisions = guard.feed(data)
                if fwd:
                    channel.write(fwd)
                for d in decisions:
                    if d.secret or (not d.command and d.allowed):
                        continue
                    stats["commands"] += 1
                    if not d.allowed:
                        stats["blocked"] += 1
                        await _send(ws, {"t": "blocked", "command": mask(d.command)[:300], "risk": d.risk, "reason": d.reason})
                    if recording != "off":
                        pending.append(NmsAccessCommand(session_id=sid, change_id=change_id, switch_id=switch_id, username=user.username,
                                                        command=mask(d.command)[:2000], risk=d.risk, allowed=d.allowed, reason=d.reason[:255]))
            elif kind == "r":
                try:
                    channel.resize(max(20, min(int(msg.get("cols", 120)), 400)), max(5, min(int(msg.get("rows", 32)), 200)))
                except (TypeError, ValueError):
                    pass
            elif kind == "close":
                stats["reason"] = "disconnected by the user"
                stop.set()
                return
            elif kind == "ping":
                await _send(ws, {"t": "pong"})

    async def watchdog():
        version = user.session_version or 0
        while not stop.is_set():
            await asyncio.sleep(2)
            if time.monotonic() - stats["last"] > st.access_idle_timeout_seconds:
                stats["reason"] = "idle timeout"
            elif time.monotonic() - started > st.access_max_session_seconds:
                stats["reason"] = "maximum session duration"
            else:
                async with session_factory()() as s2:
                    r = await s2.get(NmsAccessSession, sid)
                    if r is not None and r.terminate_requested_by:
                        stats["reason"] = f"terminated by {r.terminate_requested_by}"
                    if pending:
                        s2.add_all(pending[:])
                        pending.clear()
                    if r is not None:
                        r.bytes_in, r.bytes_out, r.commands, r.blocked = stats["in"], stats["out"], stats["commands"], stats["blocked"]
                        r.last_activity_at = now()
                    await s2.commit()
                if not stats["reason"] and not await _still_allowed(user.id, version):
                    stats["reason"] = "account or permission revoked"
            if stats["reason"]:
                stop.set()

    tasks = [asyncio.create_task(x()) for x in (from_device, from_browser, watchdog)]
    stopper = asyncio.create_task(stop.wait())
    try:
        await asyncio.wait([stopper, *tasks], return_when=asyncio.FIRST_COMPLETED)
        stop.set()
    except asyncio.CancelledError:
        stats["reason"] = stats["reason"] or "gateway shutting down"
    finally:
        for x in (*tasks, stopper):
            x.cancel()
        try:
            channel.close()
        except Exception:
            pass
        _LIVE.pop(sid, None)
        if pending:
            async with session_factory()() as s2:
                s2.add_all(pending)
                await s2.commit()
        state = "terminated" if stats["reason"].startswith(("terminated", "account")) else "closed"
        await _finish(sid, user, stats, transcript, recording, client_ip, state)
        try:
            await _send(ws, {"t": "closed", "reason": stats["reason"] or "closed"})
            await ws.close()
        except Exception:
            pass


async def _finish(sid: str, user: User, stats: dict, transcript: list[str], recording: str, client_ip: str, state: str) -> None:
    async with session_factory()() as s:
        r = await s.get(NmsAccessSession, sid)
        if r is None:
            return
        r.state, r.ended_at = state, now()
        r.termination_reason = (stats.get("reason") or "")[:64]
        r.bytes_in, r.bytes_out, r.commands, r.blocked = stats["in"], stats["out"], stats["commands"], stats["blocked"]
        if recording == "full" and transcript:
            text = mask("".join(transcript))
            s.add(NmsAccessRecording(session_id=sid, text=text, truncated=sum(map(len, transcript)) >= get_settings().access_recording_max_bytes))
        await s.commit()
        await audit.record(s, user.username, "terminal_end", switch_id=r.switch_id, session_id=sid, target=r.device_name,
                           detail={"reason": r.termination_reason, "commands": r.commands, "blocked": r.blocked, "bytes_in": r.bytes_in,
                                   "bytes_out": r.bytes_out}, client_ip=client_ip)


def stop_local(sid: str, reason: str) -> bool:
    """End a session served by this process now (the watchdog also picks up the database flag within 2 s)."""
    live = _LIVE.get(sid)
    if live is None:
        return False
    live[1]["reason"] = live[1]["reason"] or reason
    live[0].set()
    return True


async def close_orphans() -> int:
    """Gateway start: sessions left pending / active by a previous process have no connection any more."""
    from ..db.models import NmsAccessSession as S
    async with session_factory()() as s:
        n = 0
        for r in (await s.execute(select(S).where(S.state.in_(("pending", "active"))))).scalars():
            r.state, r.ended_at, r.ticket_hash, n = "closed", now(), "", n + 1
            r.termination_reason = r.termination_reason or "gateway restarted"
        await s.commit()
        return n


async def purge_recordings(s, now: datetime | None = None) -> int:
    """Worker housekeeping: terminal output recordings older than ACCESS_RECORDING_RETENTION_DAYS are deleted. Session
    rows, command records and the hash-chained audit are kept (they are the access audit)."""
    from datetime import timedelta
    from sqlalchemy import delete
    now = now or datetime.now(timezone.utc)
    res = await s.execute(delete(NmsAccessRecording).where(NmsAccessRecording.created_at < now - timedelta(days=get_settings().access_recording_retention_days)))
    return res.rowcount or 0
