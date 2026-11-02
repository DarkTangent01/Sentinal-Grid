"""TACACS+ worker jobs: accounting / AAA log ingestion, server health, deployment jobs, housekeeping.

Ingestion reads the managed server's log files from the shared volume (read-only) with a cursor per file (inode +
offset). Rotation is detected by an inode change or a shrinking file; an incomplete last line is left for the next
pass; lines are fingerprinted so a re-read never inserts duplicates (in-process set + ReplacingMergeTree). Parse
errors are counted per file and the last one kept for the Health page.

Deployments write a candidate file and a request into the shared config volume and wait for the agent's result; the
SIEM never executes anything on the TACACS+ server itself.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import time
from collections import OrderedDict
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db.models import TacClient, TacConfigVersion, TacDeployJob, TacHealthCheck, TacServer
from ..netguard import DestinationError, acheck_host
from .parse import FIELDS, LOG_FILES, compile_redactions, parse_line
from .service import settings as tac_settings, unseal
from .vendors import categorize

log = logging.getLogger("tacacs")
EVENT_COLS = ["ts", "server_id", "log", "msgid", "event_type", "result", "username", "device_address", "device_name", "client_id", "vendor", "site",
              "port", "remote_addr", "service", "priv_lvl", "profile", "rule", "server_address", "identity_source", "action", "cmd", "cmd_category",
              "task_id", "session_id", "elapsed_s", "hint", "raw", "fingerprint"]
MAX_READ = 5_000_000
_seen: dict[int, OrderedDict] = {}


def _dirs() -> tuple[str, str]:
    st = get_settings()
    return st.tacacs_config_dir, st.tacacs_log_dir


# ------------------------------------------------------------------ ingestion
def _later(a, b):
    if a is not None and a.tzinfo is None:
        a = a.replace(tzinfo=timezone.utc)
    return b if a is None or b > a else a


def _read_new(path: str, cur: dict) -> tuple[list[str], dict]:
    try:
        stt = os.stat(path)
    except FileNotFoundError:
        return [], {**cur, "missing": True}
    off = int(cur.get("offset") or 0)
    if cur.get("inode") != stt.st_ino or stt.st_size < off:
        off = 0  # rotated or truncated
    with open(path, "rb") as f:
        f.seek(off)
        data = f.read(MAX_READ)
    nl = data.rfind(b"\n")
    if nl < 0:
        return [], {**cur, "inode": stt.st_ino, "offset": off, "missing": False, "size": stt.st_size}
    chunk = data[:nl + 1]
    lines = chunk.decode("utf-8", "replace").splitlines()
    return lines, {**cur, "inode": stt.st_ino, "offset": off + len(chunk), "missing": False, "size": stt.st_size}


_probe_cache: tuple[float, frozenset[str]] = (0.0, frozenset())


def probe_addresses() -> frozenset[str]:
    """Addresses the SIEM's own TCP/49 health checks come from (loopback, this container, the api container): their
    connection-log lines are health probes, not unknown devices. Refreshed every 5 minutes; resolution is best effort."""
    global _probe_cache
    if time.monotonic() - _probe_cache[0] < 300:
        return _probe_cache[1]
    out = {"127.0.0.1", "::1"}
    for name in (socket.gethostname(), "api", "worker"):
        try:
            out.update(ai[4][0] for ai in socket.getaddrinfo(name, None))
        except OSError:
            pass
    _probe_cache = (time.monotonic(), frozenset(out))
    return _probe_cache[1]


async def ingest(s: AsyncSession, ch, server: TacServer, log_dir: str | None = None) -> dict:
    log_dir = log_dir or _dirs()[1]
    cfg = await tac_settings(s)
    rules = compile_redactions(cfg.get("redaction_rules"))
    clients = {c.address: c for c in (await s.execute(select(TacClient))).scalars()}
    seen = _seen.setdefault(server.id, OrderedDict())
    probes = probe_addresses()
    state = dict(server.ingestion or {})
    rows, stats = [], {}
    last_ts: dict[str, datetime] = {}
    for kind in FIELDS:
        cur = dict(state.get(kind) or {})
        lines, cur = _read_new(os.path.join(log_dir, LOG_FILES[kind]), cur)
        n = errs = dup = 0
        for line in lines:
            if not line.strip():
                continue
            ev = parse_line(kind, line, server.id, rules)
            if ev["fingerprint"] in seen:
                dup += 1
                continue
            seen[ev["fingerprint"]] = 1
            if len(seen) > 200_000:
                seen.popitem(last=False)
            if not ev["parse_ok"]:
                errs += 1
                cur["last_parse_error"] = {"at": datetime.now(timezone.utc).isoformat(), "reason": ev["parse_error"], "line": ev["raw"][:300]}
            c = clients.get(ev.get("device_address", ""))
            if kind == "conn" and c is None and ev.get("event_type", "").startswith("conn_") and ev.get("device_address") in probes:
                ev.update(event_type="conn_probe", result="health_check")
            ev.update(client_id=c.id if c else 0, vendor=c.vendor if c else "", site=c.site if c else "",
                      cmd_category=categorize(c.vendor if c else "other", ev.get("cmd", "")) if ev.get("cmd") else "")
            if ev["parse_ok"]:
                last_ts[kind] = max(last_ts.get(kind, ev["ts"]), ev["ts"])
                if c is not None and kind == "acct":
                    c.last_accounting_at = _later(c.last_accounting_at, ev["ts"])
                elif c is not None and kind == "authc":
                    c.last_authentication_at = _later(c.last_authentication_at, ev["ts"])
            rows.append({k: ev.get(k) for k in EVENT_COLS} | {"ts": ev["ts"]})
            n += 1
        cur.update(lines=int(cur.get("lines") or 0) + n, parse_errors=int(cur.get("parse_errors") or 0) + errs, duplicates=int(cur.get("duplicates") or 0) + dup,
                   last_read=datetime.now(timezone.utc).isoformat())
        if kind in last_ts:
            cur["last_event_at"] = last_ts[kind].isoformat()
        state[kind] = cur
        stats[kind] = {"new": n, "parse_errors": errs, "duplicates": dup}
    if rows:
        for r in rows:
            for k in ("username", "device_address", "device_name", "port", "remote_addr", "service", "profile", "rule", "server_address", "identity_source",
                      "action", "cmd", "cmd_category", "task_id", "session_id", "hint", "raw", "msgid", "event_type", "result", "vendor", "site"):
                r[k] = r.get(k) or ""
        await ch.ainsert("tacacs_events", rows, EVENT_COLS)
    if "acct" in last_ts:
        server.last_accounting_at = last_ts["acct"]
    if "authc" in last_ts:
        server.last_authentication_at = last_ts["authc"]
    server.ingestion = state
    await s.commit()
    return stats


# ------------------------------------------------------------------ health
async def tcp_check(host: str, port: int, timeout: float = 3.0) -> tuple[bool, float | None, str]:
    try:
        await acheck_host(host, port)
    except DestinationError as e:
        return False, None, str(e)
    t0 = time.monotonic()
    try:
        _r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        w.close()
        try:
            await w.wait_closed()
        except (OSError, ConnectionError):
            pass
        return True, round((time.monotonic() - t0) * 1000, 1), ""
    except asyncio.TimeoutError:
        return False, None, f"no TCP answer on {host}:{port} within {timeout:g}s"
    except (OSError, socket.gaierror) as e:
        return False, None, f"TCP {host}:{port}: {e.strerror or type(e).__name__}"


def agent_status(config_dir: str | None = None) -> dict | None:
    path = os.path.join(config_dir or _dirs()[0], "status.json")
    try:
        with open(path) as f:
            st = json.load(f)
    except (OSError, ValueError):
        return None
    st["age_s"] = round(time.time() - float(st.get("time") or 0), 1)
    return st


async def health(s: AsyncSession, server: TacServer, now: datetime | None = None, config_dir: str | None = None) -> TacHealthCheck:
    now = now or datetime.now(timezone.utc)
    ok, ms, err = await tcp_check(server.management_address, server.port)
    agent_ok = None
    detail = err
    if server.kind == "managed":
        st = agent_status(config_dir)
        if st is None:
            agent_ok, detail = False, (detail + "; " if detail else "") + "agent status not available (is the tacacs service running with the shared volume?)"
        else:
            server.agent = st
            server.version = f"tac_plus-ng {st.get('commit', '')[:12]}".strip()
            agent_ok = st["age_s"] < 60 and st.get("running") and st.get("listening")
            if not agent_ok:
                detail = (detail + "; " if detail else "") + f"agent: running={st.get('running')} listening={st.get('listening')} age={st['age_s']}s"
            if st.get("active_sha256"):
                server.deployed_sha256 = st["active_sha256"]
    status = "up" if ok and agent_ok is not False else "degraded" if ok or agent_ok else "down"
    server.fail_streak = 0 if status == "up" else (server.fail_streak or 0) + 1
    shown = status if status != "down" or server.fail_streak >= 2 else (server.status if server.status != "unknown" else "degraded")
    if shown != server.status:
        server.status, server.status_since = shown, now
    server.last_check_at = now
    if status == "up":
        server.last_ok_at = now
    server.last_error = detail[:1000]
    hc = TacHealthCheck(server_id=server.id, at=now, tcp_ok=ok, latency_ms=ms, agent_ok=agent_ok, status=status, detail=detail[:1000])
    s.add(hc)
    await s.commit()
    return hc


# ------------------------------------------------------------------ deployments
async def run_job(s: AsyncSession, job: TacDeployJob, *, config_dir: str | None = None, timeout: float | None = None) -> TacDeployJob:
    config_dir = config_dir or _dirs()[0]
    timeout = timeout or get_settings().tacacs_deploy_timeout_seconds
    ver = await s.get(TacConfigVersion, job.version_id)
    server = await s.get(TacServer, job.server_id)
    job.status, job.started_at = "running", datetime.now(timezone.utc)
    await s.commit()
    try:
        full = unseal(ver.content_ciphertext)
        cand = os.path.join(config_dir, "candidates", f"{job.id}.cfg")
        tmp = cand + ".tmp"
        with open(tmp, "w") as f:
            f.write(full)
        os.chmod(tmp, 0o640)
        os.replace(tmp, cand)
        req = os.path.join(config_dir, "requests", f"{job.id}.json")
        with open(req + ".tmp", "w") as f:
            json.dump({"id": job.id, "action": job.action, "sha256": ver.sha256}, f)
        os.replace(req + ".tmp", req)
        res_path = os.path.join(config_dir, "results", f"{job.id}.json")
        deadline = time.monotonic() + timeout
        res = None
        while time.monotonic() < deadline:
            if os.path.exists(res_path):
                with open(res_path) as f:
                    res = json.load(f)
                break
            await asyncio.sleep(1)
        if res is None:
            job.status, job.result = "failed", {"reason": f"no answer from the deploy agent within {timeout:.0f}s (is the tacacs service running?)"}
            if os.path.exists(req):
                os.remove(req)  # do not let a stale request be applied later
        else:
            job.result = res
            job.status = {"deployed": "succeeded", "valid": "succeeded", "invalid": "invalid", "rolled_back": "rolled_back"}.get(res.get("status"), "failed")
            if job.action == "deploy" and job.status == "succeeded":
                server.deployed_version_id, server.deployed_sha256, server.last_deploy_at = ver.id, ver.sha256, datetime.now(timezone.utc)
                names = {c["name"] for c in (ver.model or {}).get("clients", [])}
                await s.execute(update(TacClient).where(TacClient.name.in_(names or {""})).values(sync_status="in_sync"))
            try:
                os.remove(cand)
            except OSError:
                pass
    except OSError as e:
        job.status, job.result = "failed", {"reason": f"cannot write to the shared configuration volume: {e.strerror}"}
    job.finished_at = datetime.now(timezone.utc)
    await s.commit()
    return job


async def tick(ch, session_factory, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    out = {}
    async with session_factory() as s:
        servers = (await s.execute(select(TacServer).where(TacServer.monitoring.is_(True)))).scalars().all()
        for srv in servers:
            if srv.last_check_at is None or (now - (srv.last_check_at if srv.last_check_at.tzinfo else srv.last_check_at.replace(tzinfo=timezone.utc))
                                             ).total_seconds() >= 30:
                try:
                    await health(s, srv, now)
                except Exception:
                    log.exception("tacacs health %s failed", srv.name)
                    await s.rollback()
            if srv.kind == "managed":
                try:
                    out[srv.name] = await ingest(s, ch, srv)
                except Exception:
                    log.exception("tacacs ingestion %s failed", srv.name)
                    await s.rollback()
        job = (await s.execute(select(TacDeployJob).where(TacDeployJob.status == "queued").order_by(TacDeployJob.id).limit(1))).scalars().first()
        if job is not None:
            claimed = await s.execute(update(TacDeployJob).where(TacDeployJob.id == job.id, TacDeployJob.status == "queued").values(status="running"))
            await s.commit()
            if claimed.rowcount == 1:
                await s.refresh(job)
                await run_job(s, job)
                out["job"] = {job.id: job.status}
    return out


async def housekeeping(s: AsyncSession, now: datetime | None = None) -> None:
    now = now or datetime.now(timezone.utc)
    await s.execute(delete(TacHealthCheck).where(TacHealthCheck.at < now - timedelta(days=14)).execution_options(synchronize_session=False))
    await s.commit()
