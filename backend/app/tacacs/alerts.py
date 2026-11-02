"""TACACS+ detections for the SIEM alert engine.

Each detection carries rule id, severity, affected user / device, timestamps, the logic in words, evidence, investigation
steps and related events. De-duplication comes from the engine's group keys (one open alert per user / device /
condition; later evaluations update it), threshold windows come from rule parameters, the engine's interval acts as a
cooldown, and state-type rules (server down, accounting gaps) resolve themselves with a recovery notification.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from ..db.models import AuditLog, TacClient, TacDeployJob, TacRole, TacRoleMapping, TacServer, TacUser
from ..db.pg import session_factory

M = lambda tactic="", *t: ({"tactic": tactic, "techniques": list(t)} if tactic else {})  # noqa: E731

STEPS = {
    "tacacs_auth_failures": ["Check whether the user is mistyping or a script / scanner is guessing", "Look at the source (rem_addr) and devices involved",
                             "Contact the user; reset the password if it may be known"],
    "tacacs_authz_denials": ["Compare the denied commands with the user's role (Authorization → Explain)", "Decide whether the role is too narrow or "
                             "the activity is unexpected"],
    "tacacs_success_after_failures": ["Confirm with the user that they logged in", "Review the session's commands in Session Audit"],
    "tacacs_privileged_off_hours": ["Confirm a change ticket or on-call activity", "Review the commands of the session"],
    "tacacs_unexpected_client": ["Check where the source address is (VPN pool, jump host, new laptop)", "Ask the user to confirm"],
    "tacacs_unknown_device": ["Is a new device being onboarded without being registered as a client?", "Otherwise treat it as a rogue client"],
    "tacacs_disabled_user": ["The account is disabled in the SIEM registry: find out who is using it and why"],
    "tacacs_server_down": ["Check the tacacs container (docker compose ps tacacs / logs)", "Devices fall back to the secondary server or local accounts"],
    "tacacs_accounting_gap": ["Check the agent status and the shared log volume", "Check that devices still send accounting to this server"],
    "tacacs_protocol_errors": ["Usually a shared-secret mismatch: compare the device's key with the client's current secret (rotation in progress?)"],
    "tacacs_backend_failures": ["Run the identity source bind test", "Check LDAP / AD reachability and certificates from the tacacs container"],
    "tacacs_config_change": ["Review the deployed version's diff and approval in Configuration Studio"],
    "tacacs_privileged_role_assigned": ["Confirm the assignment was requested and approved", "Check the mapping's scope and expiry"],
    "tacacs_unauthorized_policy_change": ["Someone without the required TACACS+ role tried to change policy or approve their own change"],
    "tacacs_emergency_use": ["Break-glass account used: confirm the emergency, review every command, rotate the password afterwards"],
    "tacacs_multi_device_activity": ["Check whether this is planned maintenance; otherwise possible lateral movement with a stolen credential"],
    "tacacs_missing_accounting": ["The device normally sends accounting: check its AAA accounting configuration and reachability to the server"],
}

DEFAULT_RULES = [
    {"key": "tacacs_auth_failures", "name": "TACACS+: repeated authentication failures", "severity": "medium", "mitre": M("TA0006", "T1110"),
     "description": "Many wrong-password failures (not backend outages) for one user within the window.", "params": {"window_minutes": 15, "min_failures": 5}},
    {"key": "tacacs_authz_denials", "name": "TACACS+: repeated command authorization denials", "severity": "medium", "mitre": M("TA0004", "T1078"),
     "description": "A user was denied many commands within the window.", "params": {"window_minutes": 30, "min_denials": 5}},
    {"key": "tacacs_success_after_failures", "name": "TACACS+: successful login after repeated failures", "severity": "high", "mitre": M("TA0006", "T1110.001"),
     "description": "A successful network-device login right after several wrong-password failures for the same user.",
     "params": {"window_minutes": 30, "min_failures": 3}},
    {"key": "tacacs_privileged_off_hours", "name": "TACACS+: privileged access outside business hours", "severity": "medium", "mitre": M("TA0004", "T1078"),
     "description": "A login that received a privileged profile (priv-lvl 15 / Ruckus 0 / privileged role) outside the configured hours.",
     "params": {"window_minutes": 15, "work_start_hour": 7, "work_end_hour": 21, "weekend": True}},
    {"key": "tacacs_unexpected_client", "name": "TACACS+: login from an unexpected client address", "severity": "medium", "mitre": M("TA0001", "T1078"),
     "description": "A successful login from a client address (rem_addr) the user has not used in the baseline period.",
     "params": {"window_minutes": 15, "baseline_days": 30}},
    {"key": "tacacs_unknown_device", "name": "TACACS+: request from an unknown device", "severity": "medium", "mitre": M("TA0001", "T1200"),
     "description": "The server rejected a connection from an address that is not a registered client, or events arrived from an unregistered device.",
     "params": {"window_minutes": 30}},
    {"key": "tacacs_disabled_user", "name": "TACACS+: disabled user attempting access", "severity": "high", "mitre": M("TA0001", "T1078"),
     "description": "An authentication attempt by an account disabled in the SIEM's TACACS+ registry.", "params": {"window_minutes": 30}},
    {"key": "tacacs_server_down", "name": "TACACS+: server down", "severity": "high", "mitre": {},
     "description": "A monitored TACACS+ server is not answering on TCP/49 or its agent reports the daemon down.", "params": {"min_down_minutes": 2}},
    {"key": "tacacs_accounting_gap", "name": "TACACS+: accounting stopped on a server", "severity": "medium", "mitre": M("TA0005", "T1562.006"),
     "description": "A managed server that received accounting before has received none within the gap period.", "params": {"gap_hours": 6}},
    {"key": "tacacs_protocol_errors", "name": "TACACS+: protocol / shared-secret errors", "severity": "medium", "mitre": {},
     "description": "Undecodable or invalid TACACS+ requests from a device (often a key mismatch).", "params": {"window_minutes": 30, "min_errors": 3}},
    {"key": "tacacs_backend_failures", "name": "TACACS+: identity backend failures", "severity": "high", "mitre": {},
     "description": "Authentication failed because the identity backend (LDAP / AD / PAM) did not answer, repeatedly.",
     "params": {"window_minutes": 15, "min_failures": 3}},
    {"key": "tacacs_config_change", "name": "TACACS+: server configuration deployed", "severity": "low", "mitre": M("TA0005", "T1556"),
     "description": "A TACACS+ configuration version was deployed to a server.", "params": {"window_minutes": 30}},
    {"key": "tacacs_privileged_role_assigned", "name": "TACACS+: privileged role assigned", "severity": "medium", "mitre": M("TA0003", "T1098"),
     "description": "A user or group was mapped to a privileged TACACS+ role.", "params": {"window_minutes": 60}},
    {"key": "tacacs_unauthorized_policy_change", "name": "TACACS+: unauthorised policy change attempt", "severity": "high", "mitre": M("TA0005", "T1556"),
     "description": "A TACACS+ policy, server or approval action was refused for lack of permission or separation of duties.", "params": {"window_minutes": 60}},
    {"key": "tacacs_emergency_use", "name": "TACACS+: emergency account used", "severity": "critical", "mitre": M("TA0004", "T1078.003"),
     "description": "A break-glass account logged in to a network device.", "params": {"window_minutes": 30}},
    {"key": "tacacs_multi_device_activity", "name": "TACACS+: one user on many devices", "severity": "medium", "mitre": M("TA0008", "T1021.004"),
     "description": "A user logged in to an unusual number of distinct devices within the window.", "params": {"window_minutes": 30, "min_devices": 8}},
    {"key": "tacacs_missing_accounting", "name": "TACACS+: device stopped sending accounting", "severity": "low", "mitre": M("TA0005", "T1562.006"),
     "description": "A client that normally sends accounting has sent none within the gap period.", "params": {"gap_hours": 24}},
]
AUTO_RESOLVE = {"tacacs_server_down", "tacacs_accounting_gap", "tacacs_missing_accounting"}


def _aware(v):
    if v is None:
        return None
    if isinstance(v, str):
        v = datetime.fromisoformat(v.replace("Z", "+00:00").replace(" ", "T", 1))
    return v if v.tzinfo else v.replace(tzinfo=timezone.utc)


def _det(key: str, rule: str, explanation: str, *, first, last, count=1, user="", device="", logic="", evidence=None, related=None, severity=None, sites=None):
    from ..alerts.engine import Detection
    ev = {"rule": rule, "user": user, "device": device, "logic": logic, "investigation": STEPS.get(rule, []), "related_events": related or [],
          "detected_at": last.isoformat(), **(evidence or {})}
    return Detection(group_key=key, count=count, first_seen=first, last_seen=last, explanation=explanation, sites=sites or [], evidence=ev,
                     event_filter={}, severity=severity)


async def _q(ch, sql: str, p: dict) -> list[dict]:
    return await ch.aquery(sql, p)


async def _per_user(ch, now, p, etype: str, key: str, rule: str, label: str):
    t0 = now - timedelta(minutes=int(p.get("window_minutes", 15)))
    rows = await _q(ch, "SELECT username, count() AS n, min(ts) AS first, max(ts) AS last, groupUniqArray(10)(device_address) AS devices, "
                        "groupUniqArray(5)(remote_addr) AS sources FROM tacacs_events FINAL WHERE ts >= {t0:DateTime64(3)} AND event_type = {e:String} "
                        "AND username != '' GROUP BY username HAVING n >= {n:UInt32}", {"t0": t0, "e": etype, "n": int(p.get(key, 5))})
    return [_det(f"{r['username']}", rule, f"{r['username']}: {r['n']} {label} in {p.get('window_minutes', 15)} min on {len(r['devices'])} device(s)",
                 first=_aware(r["first"]), last=_aware(r["last"]), count=int(r["n"]), user=r["username"], device=", ".join(r["devices"]),
                 logic=f"count({etype}) per user ≥ {p.get(key, 5)} in {p.get('window_minutes', 15)} min",
                 evidence={"devices": r["devices"], "sources": r["sources"], "observed": int(r["n"]), "threshold": int(p.get(key, 5))}) for r in rows]


async def rule_tacacs_auth_failures(ch, now, p):
    return await _per_user(ch, now, p, "auth_failure", "min_failures", "tacacs_auth_failures", "authentication failures")


async def rule_tacacs_authz_denials(ch, now, p):
    return await _per_user(ch, now, p, "authz_deny", "min_denials", "tacacs_authz_denials", "command authorization denials")


async def rule_tacacs_backend_failures(ch, now, p):
    t0 = now - timedelta(minutes=int(p.get("window_minutes", 15)))
    rows = await _q(ch, "SELECT server_id, count() AS n, min(ts) AS first, max(ts) AS last, uniqExact(username) AS users FROM tacacs_events FINAL "
                        "WHERE ts >= {t0:DateTime64(3)} AND event_type = 'auth_backend_error' GROUP BY server_id HAVING n >= {n:UInt32}",
                    {"t0": t0, "n": int(p.get("min_failures", 3))})
    return [_det(f"server{r['server_id']}", "tacacs_backend_failures", f"{r['n']} authentications failed because the identity backend did not answer "
                 f"({r['users']} user(s)); these are not wrong passwords", first=_aware(r["first"]), last=_aware(r["last"]), count=int(r["n"]),
                 logic="count(AUTHC-FAIL-BACKEND) per server", evidence={"server_id": r["server_id"]}) for r in rows]


async def rule_tacacs_protocol_errors(ch, now, p):
    t0 = now - timedelta(minutes=int(p.get("window_minutes", 30)))
    rows = await _q(ch, "SELECT device_address, any(device_name) AS name, count() AS n, min(ts) AS first, max(ts) AS last FROM tacacs_events FINAL "
                        "WHERE ts >= {t0:DateTime64(3)} AND event_type IN ('protocol_error', 'acct_unknown') GROUP BY device_address HAVING n >= {n:UInt32}",
                    {"t0": t0, "n": int(p.get("min_errors", 3))})
    return [_det(f"{r['device_address']}", "tacacs_protocol_errors", f"{r['name'] or r['device_address']}: {r['n']} protocol errors / non-compliant records",
                 first=_aware(r["first"]), last=_aware(r["last"]), count=int(r["n"]), device=r["device_address"], logic="count(protocol errors) per device")
            for r in rows]


async def rule_tacacs_success_after_failures(ch, now, p):
    t0 = now - timedelta(minutes=int(p.get("window_minutes", 30)))
    rows = await _q(ch, "SELECT username, countIf(event_type = 'auth_failure') AS fails, maxIf(ts, event_type = 'auth_success') AS ok_at, "
                        "minIf(ts, event_type = 'auth_failure') AS first_fail, maxIf(ts, event_type = 'auth_failure') AS last_fail, "
                        "anyIf(device_address, event_type = 'auth_success') AS device, anyIf(remote_addr, event_type = 'auth_success') AS source "
                        "FROM tacacs_events FINAL WHERE ts >= {t0:DateTime64(3)} AND event_type IN ('auth_failure', 'auth_success') AND username != '' "
                        "GROUP BY username HAVING fails >= {n:UInt32} AND countIf(event_type = 'auth_success') > 0 AND ok_at > last_fail",
                    {"t0": t0, "n": int(p.get("min_failures", 3))})
    return [_det(f"{r['username']}:{_aware(r['ok_at']):%Y%m%d%H%M}", "tacacs_success_after_failures",
                 f"{r['username']} logged in to {r['device']} after {r['fails']} failures", first=_aware(r["first_fail"]), last=_aware(r["ok_at"]),
                 count=int(r["fails"]), user=r["username"], device=r["device"], logic="success after ≥ N failures in the window",
                 evidence={"source": r["source"], "failures": int(r["fails"])}) for r in rows]


async def _privileged_profiles() -> set[str]:
    from .render import profile_name
    async with session_factory()() as s:
        roles = (await s.execute(select(TacRole).where(TacRole.privileged.is_(True)))).scalars().all()
    return {profile_name(r.name, v) for r in roles for v in ("cisco", "ruckus", "fortinet", "other")}


async def rule_tacacs_privileged_off_hours(ch, now, p):
    t0 = now - timedelta(minutes=int(p.get("window_minutes", 15)))
    priv = sorted(await _privileged_profiles())
    rows = await _q(ch, "SELECT ts, username, device_address, device_name, profile, priv_lvl, remote_addr FROM tacacs_events FINAL WHERE ts >= {t0:DateTime64(3)} "
                        "AND event_type = 'authz_permit' AND cmd = '' AND (profile IN {pp:Array(String)} OR (vendor = 'cisco' AND priv_lvl = 15) "
                        "OR (vendor = 'ruckus' AND priv_lvl = 0))", {"t0": t0, "pp": priv or [""]})
    out = []
    for r in rows:
        t = _aware(r["ts"])
        off = not (int(p.get("work_start_hour", 7)) <= t.hour < int(p.get("work_end_hour", 21))) or (p.get("weekend", True) and t.weekday() >= 5)
        if off:
            out.append(_det(f"{r['username']}:{r['device_address']}:{t:%Y%m%d%H}", "tacacs_privileged_off_hours",
                            f"{r['username']} received privileged access ({r['profile'] or 'priv-lvl ' + str(r['priv_lvl'])}) on {r['device_name'] or r['device_address']} "
                            f"at {t:%a %H:%M} UTC", first=t, last=t, user=r["username"], device=r["device_address"], logic="privileged exec authorization outside hours",
                            evidence={"source": r["remote_addr"]}))
    return out


async def rule_tacacs_unexpected_client(ch, now, p):
    t0 = now - timedelta(minutes=int(p.get("window_minutes", 15)))
    b0 = now - timedelta(days=int(p.get("baseline_days", 30)))
    rows = await _q(ch, "SELECT username, remote_addr, min(ts) AS first, any(device_address) AS device FROM tacacs_events FINAL WHERE ts >= {t0:DateTime64(3)} "
                        "AND event_type = 'auth_success' AND remote_addr != '' AND username != '' GROUP BY username, remote_addr", {"t0": t0})
    out = []
    for r in rows:
        base = await _q(ch, "SELECT countIf(remote_addr = {a:String}) AS same, count() AS total FROM tacacs_events FINAL WHERE ts >= {b0:DateTime64(3)} "
                            "AND ts < {t0:DateTime64(3)} AND event_type = 'auth_success' AND username = {u:String}",
                        {"a": r["remote_addr"], "b0": b0, "t0": t0, "u": r["username"]})
        if base and int(base[0]["total"]) >= 5 and int(base[0]["same"]) == 0:
            out.append(_det(f"{r['username']}:{r['remote_addr']}", "tacacs_unexpected_client", f"{r['username']} logged in from {r['remote_addr']}, "
                            f"not used in {p.get('baseline_days', 30)} days ({base[0]['total']} logins)", first=_aware(r["first"]), last=_aware(r["first"]),
                            user=r["username"], device=r["device"], logic="new rem_addr vs. baseline (≥ 5 baseline logins)"))
    return out


async def rule_tacacs_unknown_device(ch, now, p):
    t0 = now - timedelta(minutes=int(p.get("window_minutes", 30)))
    rows = await _q(ch, "SELECT device_address, count() AS n, min(ts) AS first, max(ts) AS last, groupUniqArray(3)(event_type) AS kinds FROM tacacs_events FINAL "
                        "WHERE ts >= {t0:DateTime64(3)} AND (event_type = 'conn_reject' OR (client_id = 0 AND log != 'conn')) AND device_address != '' "
                        "GROUP BY device_address", {"t0": t0})
    return [_det(f"{r['device_address']}", "tacacs_unknown_device", f"{r['n']} TACACS+ request(s) from {r['device_address']}, which is not a registered client",
                 first=_aware(r["first"]), last=_aware(r["last"]), count=int(r["n"]), device=r["device_address"], logic="connection rejected / unregistered device",
                 evidence={"kinds": r["kinds"]}) for r in rows]


async def rule_tacacs_disabled_user(ch, now, p):
    async with session_factory()() as s:
        disabled = [u.username for u in (await s.execute(select(TacUser).where(TacUser.enabled.is_(False)))).scalars()]
    if not disabled:
        return []
    t0 = now - timedelta(minutes=int(p.get("window_minutes", 30)))
    rows = await _q(ch, "SELECT username, count() AS n, min(ts) AS first, max(ts) AS last, groupUniqArray(5)(device_address) AS devices FROM tacacs_events FINAL "
                        "WHERE ts >= {t0:DateTime64(3)} AND log = 'authc' AND username IN {u:Array(String)} GROUP BY username", {"t0": t0, "u": disabled})
    return [_det(f"{r['username']}", "tacacs_disabled_user", f"disabled account {r['username']} attempted {r['n']} login(s)", first=_aware(r["first"]),
                 last=_aware(r["last"]), count=int(r["n"]), user=r["username"], device=", ".join(r["devices"]), logic="authentication by a disabled account")
            for r in rows]


async def rule_tacacs_emergency_use(ch, now, p):
    async with session_factory()() as s:
        em = [u.username for u in (await s.execute(select(TacUser).where(TacUser.emergency.is_(True)))).scalars()]
    if not em:
        return []
    t0 = now - timedelta(minutes=int(p.get("window_minutes", 30)))
    rows = await _q(ch, "SELECT ts, username, device_address, device_name, remote_addr FROM tacacs_events FINAL WHERE ts >= {t0:DateTime64(3)} "
                        "AND event_type = 'auth_success' AND username IN {u:Array(String)}", {"t0": t0, "u": em})
    return [_det(f"{r['username']}:{r['device_address']}:{_aware(r['ts']):%Y%m%d%H%M%S}", "tacacs_emergency_use",
                 f"emergency account {r['username']} logged in to {r['device_name'] or r['device_address']} from {r['remote_addr'] or '?'}",
                 first=_aware(r["ts"]), last=_aware(r["ts"]), user=r["username"], device=r["device_address"], logic="any successful login of an emergency account")
            for r in rows]


async def rule_tacacs_multi_device_activity(ch, now, p):
    t0 = now - timedelta(minutes=int(p.get("window_minutes", 30)))
    rows = await _q(ch, "SELECT username, uniqExact(device_address) AS n, min(ts) AS first, max(ts) AS last, groupUniqArray(20)(device_address) AS devices "
                        "FROM tacacs_events FINAL WHERE ts >= {t0:DateTime64(3)} AND event_type = 'auth_success' AND username != '' GROUP BY username "
                        "HAVING n >= {n:UInt32}", {"t0": t0, "n": int(p.get("min_devices", 8))})
    return [_det(f"{r['username']}", "tacacs_multi_device_activity", f"{r['username']} logged in to {r['n']} devices in {p.get('window_minutes', 30)} min",
                 first=_aware(r["first"]), last=_aware(r["last"]), count=int(r["n"]), user=r["username"], device=", ".join(r["devices"]),
                 logic="distinct devices per user ≥ N") for r in rows]


async def rule_tacacs_server_down(ch, now, p):
    async with session_factory()() as s:
        rows = (await s.execute(select(TacServer).where(TacServer.monitoring.is_(True), TacServer.status == "down"))).scalars().all()
    out = []
    for x in rows:
        since = _aware(x.status_since) or now
        if (now - since).total_seconds() >= 60 * float(p.get("min_down_minutes", 2)):
            out.append(_det(f"{x.id}:{since:%Y%m%d%H%M%S}", "tacacs_server_down", f"TACACS+ server {x.name} ({x.management_address}:{x.port}) down since "
                            f"{since:%H:%M} UTC: {x.last_error}", first=since, last=now, device=x.management_address, logic="health check failed twice",
                            evidence={"last_ok_at": x.last_ok_at.isoformat() if x.last_ok_at else None}, sites=[x.site] if x.site else []))
    return out


async def rule_tacacs_accounting_gap(ch, now, p):
    async with session_factory()() as s:
        rows = (await s.execute(select(TacServer).where(TacServer.kind == "managed", TacServer.monitoring.is_(True)))).scalars().all()
    out = []
    for x in rows:
        last = _aware(x.last_accounting_at)
        if last and (now - last).total_seconds() > 3600 * float(p.get("gap_hours", 6)):
            out.append(_det(f"{x.id}:gap", "tacacs_accounting_gap", f"no accounting on {x.name} since {last:%Y-%m-%d %H:%M} UTC", first=last, last=now,
                            device=x.management_address, logic=f"no accounting for > {p.get('gap_hours', 6)} h after earlier accounting"))
    return out


async def rule_tacacs_missing_accounting(ch, now, p):
    async with session_factory()() as s:
        rows = (await s.execute(select(TacClient).where(TacClient.enabled.is_(True), TacClient.last_accounting_at.is_not(None)))).scalars().all()
    out = []
    for c in rows:
        last = _aware(c.last_accounting_at)
        if (now - last).total_seconds() > 3600 * float(p.get("gap_hours", 24)):
            out.append(_det(f"client{c.id}", "tacacs_missing_accounting", f"{c.name} ({c.address}) has sent no accounting since {last:%Y-%m-%d %H:%M} UTC",
                            first=last, last=now, device=c.address, logic=f"normally active client silent > {p.get('gap_hours', 24)} h",
                            sites=[c.site] if c.site else []))
    return out


async def rule_tacacs_config_change(ch, now, p):
    t0 = now - timedelta(minutes=int(p.get("window_minutes", 30)))
    async with session_factory()() as s:
        jobs = (await s.execute(select(TacDeployJob).where(TacDeployJob.action == "deploy", TacDeployJob.status == "succeeded",
                                                           TacDeployJob.finished_at >= t0))).scalars().all()
    return [_det(f"job{j.id}", "tacacs_config_change", f"configuration version {j.version_id} deployed to server {j.server_id} "
                 f"(requested by {j.requested_by}, approved by {j.approved_by or 'n/a'})", first=_aware(j.finished_at), last=_aware(j.finished_at),
                 user=j.requested_by, logic="successful deployment job", evidence={"job": j.id}) for j in jobs]


async def rule_tacacs_privileged_role_assigned(ch, now, p):
    t0 = now - timedelta(minutes=int(p.get("window_minutes", 60)))
    async with session_factory()() as s:
        priv = {r.id: r.name for r in (await s.execute(select(TacRole).where(TacRole.privileged.is_(True)))).scalars()}
        maps = (await s.execute(select(TacRoleMapping).where(TacRoleMapping.created_at >= t0, TacRoleMapping.role_id.in_(list(priv) or [0])))).scalars().all()
    return [_det(f"mapping{m.id}", "tacacs_privileged_role_assigned", f"{m.principal_type} {m.principal} mapped to privileged role {priv[m.role_id]} by {m.created_by}",
                 first=_aware(m.created_at), last=_aware(m.created_at), user=m.principal, logic="new mapping to a privileged role",
                 evidence={"scope_sites": m.scope_sites, "scope_clients": m.scope_clients, "expires_at": m.expires_at.isoformat() if m.expires_at else None})
            for m in maps]


async def rule_tacacs_unauthorized_policy_change(ch, now, p):
    t0 = now - timedelta(minutes=int(p.get("window_minutes", 60)))
    async with session_factory()() as s:
        rows = (await s.execute(select(AuditLog).where(AuditLog.action.like("tacacs_%"), AuditLog.success.is_(False), AuditLog.ts >= t0))).scalars().all()
    by: dict[str, list] = {}
    for a in rows:
        by.setdefault(a.username, []).append(a)
    return [_det(f"{u}:{t0:%Y%m%d%H}", "tacacs_unauthorized_policy_change", f"{u}: {len(xs)} refused TACACS+ change(s): " + ", ".join(sorted({x.action for x in xs})),
                 first=_aware(xs[0].ts), last=_aware(xs[-1].ts), count=len(xs), user=u, logic="refused TACACS+ administrative actions",
                 related=[{"action": x.action, "target": x.target, "detail": x.detail} for x in xs[:10]]) for u, xs in by.items()]


RULES = {d["key"]: globals()[f"rule_{d['key']}"] for d in DEFAULT_RULES}
