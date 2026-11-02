"""Read side: overview, accounting explorer, sessions, timeline. Everything is computed from ingested events and stored
state; a metric the deployment cannot provide is returned as unavailable (None + reason), never as 0."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import Alert, TacClient, TacConfigVersion, TacDeployJob, TacServer
from .parse import FIELDS

RANGES = {"1h": 3600, "6h": 21600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}
SEVERITY_SQL = ("multiIf(event_type IN ('auth_backend_error', 'protocol_error'), 'high', event_type IN ('authz_deny', 'auth_policy_deny', 'conn_reject'), "
                "'medium', event_type = 'auth_failure', 'low', 'informational')")


def window(r: str) -> tuple[datetime, datetime]:
    now = datetime.now(timezone.utc)
    return now - timedelta(seconds=RANGES[r]), now


def _iso(v):
    if v is None:
        return None
    if isinstance(v, str):
        return v.replace(" ", "T") + ("" if "+" in v or v.endswith("Z") else "Z")
    return (v if v.tzinfo else v.replace(tzinfo=timezone.utc)).isoformat()


def where(f: dict) -> tuple[str, dict]:
    conds = ["ts >= {t0:DateTime64(3)}", "ts < {t1:DateTime64(3)}"]
    p = {"t0": f["t0"], "t1": f["t1"]}
    for k, col in (("user", "username"), ("device", "device_address"), ("vendor", "vendor"), ("site", "site"), ("category", "cmd_category"),
                   ("result", "result"), ("event_type", "event_type"), ("task_id", "task_id"), ("log", "log")):
        if f.get(k):
            conds.append(f"{col} = {{{k}:String}}")
            p[k] = f[k]
    if f.get("server_id"):
        conds.append("server_id = {server_id:UInt32}")
        p["server_id"] = int(f["server_id"])
    if f.get("priv_lvl") is not None:
        conds.append("priv_lvl = {priv_lvl:UInt8}")
        p["priv_lvl"] = int(f["priv_lvl"])
    if f.get("q"):
        conds.append("(positionCaseInsensitive(cmd, {q:String}) > 0 OR positionCaseInsensitive(username, {q:String}) > 0 "
                     "OR positionCaseInsensitive(device_name, {q:String}) > 0)")
        p["q"] = f["q"]
    if f.get("severity"):
        conds.append(f"{SEVERITY_SQL} = {{severity:String}}")
        p["severity"] = f["severity"]
    return " AND ".join(conds), p


async def overview(s: AsyncSession, ch, f: dict) -> dict:
    w, p = where(f)
    by = {r["event_type"]: int(r["n"]) for r in await ch.aquery(f"SELECT event_type, count() AS n FROM tacacs_events FINAL WHERE {w} GROUP BY event_type", p)}
    agg = (await ch.aquery(f"SELECT uniqExactIf(username, event_type = 'auth_success') AS admins, uniqExactIf(device_address, device_address != '') AS devices, "
                           f"uniqExactIf(device_address, client_id = 0 AND log != 'conn' AND device_address != '') AS unknown_devices, "
                           f"countIf(parse_ok_flag = 0) AS bad FROM (SELECT *, if(msgid = '', 0, 1) AS parse_ok_flag FROM tacacs_events FINAL WHERE {w})", p))[0]
    denials = await ch.aquery(f"SELECT ts, username, device_address, device_name, cmd, cmd_category, rule, profile FROM tacacs_events FINAL WHERE {w} "
                              "AND event_type = 'authz_deny' ORDER BY ts DESC LIMIT 20", p)
    open_sessions = await ch.aquery(
        f"SELECT username, device_address, device_name, port, task_id, min(ts) AS started FROM tacacs_events FINAL WHERE {w} AND log = 'acct' "
        "AND task_id != '' AND service = 'shell' AND cmd = '' GROUP BY username, device_address, device_name, port, task_id "
        "HAVING countIf(event_type = 'acct_start') > 0 AND countIf(event_type = 'acct_stop') = 0 ORDER BY started DESC LIMIT 200", p)
    servers = (await s.execute(select(TacServer).order_by(TacServer.name))).scalars().all()
    clients = (await s.execute(select(TacClient))).scalars().all()
    pending = (await s.execute(select(TacDeployJob).where(TacDeployJob.status.in_(["pending_approval", "queued", "running"])))).scalars().all()
    versions = (await s.execute(select(TacConfigVersion).where(TacConfigVersion.created_at >= f["t0"]).order_by(TacConfigVersion.id.desc()))).scalars().all()
    deploys = (await s.execute(select(TacDeployJob).where(TacDeployJob.created_at >= f["t0"]).order_by(TacDeployJob.id.desc()).limit(20))).scalars().all()
    alerts = (await s.execute(select(Alert).where(Alert.rule_key.like("tacacs_%"), Alert.status.in_(["new", "investigating"]))
                              .order_by(Alert.last_seen.desc()).limit(20))).scalars().all()
    managed = [x for x in servers if x.kind == "managed"]
    ingestion_issues = []
    for x in managed:
        for kind in FIELDS:
            st = (x.ingestion or {}).get(kind) or {}
            if st.get("missing") and st.get("inode"):  # tac_plus-ng creates each file on its first event: only a file that was read and vanished is an issue
                ingestion_issues.append({"server": x.name, "log": kind, "issue": "log file disappeared from the shared volume (rotated away or deleted)"})
            elif st.get("parse_errors"):
                ingestion_issues.append({"server": x.name, "log": kind, "issue": f"{st['parse_errors']} unparsed line(s)", "last": st.get("last_parse_error")})
    sessions_supported = any(k in by for k in ("acct_start", "acct_stop"))
    return {
        "servers": [{"id": x.id, "name": x.name, "kind": x.kind, "role": x.role, "status": x.status, "status_since": _iso(x.status_since),
                     "last_ok_at": _iso(x.last_ok_at), "last_check_at": _iso(x.last_check_at), "version": x.version, "last_error": x.last_error,
                     "uptime_s": round((x.agent or {}).get("time", 0) - (x.agent or {}).get("started_at", 0)) if (x.agent or {}).get("started_at") else None,
                     "last_accounting_at": _iso(x.last_accounting_at), "last_authentication_at": _iso(x.last_authentication_at)} for x in servers],
        "totals": {"auth_success": by.get("auth_success", 0), "auth_failure": by.get("auth_failure", 0), "auth_backend_error": by.get("auth_backend_error", 0),
                   "auth_policy_deny": by.get("auth_policy_deny", 0), "authz_permit": by.get("authz_permit", 0), "authz_deny": by.get("authz_deny", 0),
                   "accounting": sum(by.get(k, 0) for k in ("acct_start", "acct_stop", "acct_update", "acct_unknown", "acct_system")),
                   "protocol_error": by.get("protocol_error", 0), "conn_reject": by.get("conn_reject", 0),
                   "active_sessions": len(open_sessions) if sessions_supported else None,
                   "active_sessions_note": "" if sessions_supported else "unavailable: no exec accounting start/stop records received in this range",
                   "unique_admins": int(agg["admins"]), "devices_seen": int(agg["devices"]), "unknown_devices": int(agg["unknown_devices"]),
                   "clients": len(clients), "clients_enabled": sum(1 for c in clients if c.enabled),
                   "clients_failed_tests": sum(1 for c in clients if c.last_auth_test_ok is False),
                   "clients_out_of_sync": sum(1 for c in clients if c.enabled and c.sync_status != "in_sync"),
                   "pending_operations": len(pending), "open_alerts": len(alerts), "ingestion_issues": len(ingestion_issues),
                   "servers_down": sum(1 for x in servers if x.status == "down"), "managed_servers": len(managed)},
        "recent_denials": [{**r, "ts": _iso(r["ts"])} for r in denials],
        "active_sessions": [{**r, "started": _iso(r["started"])} for r in open_sessions[:50]],
        "alerts": [{"id": a.id, "name": a.name, "severity": a.severity, "last_seen": _iso(a.last_seen), "explanation": a.explanation} for a in alerts],
        "config_changes": [{"type": "version", "id": v.id, "number": v.number, "by": v.created_by, "at": _iso(v.created_at), "message": v.message} for v in versions[:20]]
                          + [{"type": "deploy", "id": j.id, "version_id": j.version_id, "status": j.status, "by": j.requested_by, "approved_by": j.approved_by,
                              "at": _iso(j.created_at)} for j in deploys],
        "pending": [{"id": j.id, "status": j.status, "requested_by": j.requested_by, "version_id": j.version_id, "server_id": j.server_id,
                     "at": _iso(j.created_at)} for j in pending],
        "ingestion_issues": ingestion_issues,
    }


async def events(ch, f: dict, limit: int, offset: int, raw: bool) -> dict:
    w, p = where(f)
    total = int((await ch.aquery(f"SELECT count() AS n FROM tacacs_events FINAL WHERE {w}", p))[0]["n"])
    cols = ("ts, server_id, log, msgid, event_type, result, username, device_address, device_name, vendor, site, port, remote_addr, service, priv_lvl, "
            f"profile, rule, identity_source, action, cmd, cmd_category, task_id, session_id, elapsed_s, hint, {SEVERITY_SQL} AS severity" + (", raw" if raw else ""))
    rows = await ch.aquery(f"SELECT {cols} FROM tacacs_events FINAL WHERE {w} ORDER BY ts DESC LIMIT {int(limit)} OFFSET {int(offset)}", p)
    return {"total": total, "items": [{**r, "ts": _iso(r["ts"])} for r in rows]}


async def timeline(ch, f: dict) -> dict:
    w, p = where(f)
    span = (f["t1"] - f["t0"]).total_seconds()
    b = next(x for x in (60, 300, 900, 3600, 10800, 21600, 86400) if span / x <= 300 or x == 86400)
    rows = await ch.aquery(f"SELECT toStartOfInterval(ts, INTERVAL {b} SECOND) AS t, event_type, count() AS n FROM tacacs_events FINAL WHERE {w} "
                           "GROUP BY t, event_type ORDER BY t", p)
    pts: dict[str, dict] = {}
    for r in rows:
        pts.setdefault(_iso(r["t"]), {"t": _iso(r["t"])})[r["event_type"]] = int(r["n"])
    return {"bucket_seconds": b, "points": list(pts.values())}


async def sessions(ch, f: dict, limit: int, offset: int) -> dict:
    """Exec sessions from accounting start/stop (task_id), with the commands recorded on the same device / user / port
    while the session was open. Only as complete as the device's accounting configuration."""
    w, p = where({**f, "log": "acct"})
    rows = await ch.aquery(
        f"SELECT username, device_address, any(device_name) AS device_name, any(vendor) AS vendor, any(site) AS site, port, task_id, "
        "minIf(ts, event_type = 'acct_start') AS started, maxIf(ts, event_type = 'acct_stop') AS stopped, max(elapsed_s) AS elapsed, "
        "countIf(event_type = 'acct_start') AS starts, countIf(event_type = 'acct_stop') AS stops, any(priv_lvl) AS priv_lvl, any(remote_addr) AS remote "
        f"FROM tacacs_events FINAL WHERE {w} AND task_id != '' AND cmd = '' GROUP BY username, device_address, port, task_id "
        f"ORDER BY started DESC LIMIT {int(limit)} OFFSET {int(offset)}", p)
    out = []
    for r in rows:
        st = r["started"] if r["starts"] else None
        sp = r["stopped"] if r["stops"] else None
        cp = {**p, "u": r["username"], "d": r["device_address"], "po": r["port"], "a": st or f["t0"], "b": sp or f["t1"]}
        cmds = await ch.aquery(f"SELECT ts, cmd, cmd_category, event_type, result FROM tacacs_events FINAL WHERE {w} AND username = {{u:String}} "
                               "AND device_address = {d:String} AND port = {po:String} AND cmd != '' AND ts >= {a:DateTime64(3)} AND ts <= {b:DateTime64(3)} "
                               "ORDER BY ts LIMIT 500", cp)
        out.append({**{k: r[k] for k in ("username", "device_address", "device_name", "vendor", "site", "port", "task_id", "priv_lvl", "remote")},
                    "started": _iso(st), "stopped": _iso(sp), "elapsed_s": r["elapsed"], "state": "closed" if sp else "open" if st else "partial",
                    "commands": [{**c, "ts": _iso(c["ts"])} for c in cmds]})
    return {"items": out, "note": "Sessions come from exec accounting (start / stop with task_id). Commands appear only if the device sends command "
            "accounting; FortiGates and devices without 'aaa accounting commands' show sessions without commands."}


async def version_list(s: AsyncSession) -> list[dict]:
    rows = (await s.execute(select(TacConfigVersion).order_by(TacConfigVersion.number.desc()).limit(100))).scalars().all()
    deployed = {x.deployed_version_id for x in (await s.execute(select(TacServer))).scalars()}
    return [{"id": v.id, "number": v.number, "message": v.message, "sha256": v.sha256, "created_by": v.created_by, "created_at": _iso(v.created_at),
             "validation": v.validation, "deployed": v.id in deployed} for v in rows]


async def counts(s: AsyncSession) -> dict:
    return {"clients": (await s.execute(select(func.count()).select_from(TacClient))).scalar_one()}
