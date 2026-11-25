"""Response actions with approvals (the SOAR half that touches other systems).

Two kinds of action:
  * read-only (enrich_ip, collect_evidence, notify): run when requested; nothing outside Sentinel changes.
  * containment (block_ip, disable_account, isolate_host): change another system, so
      1. the request is planned as a dry run: the exact commands for the target system, the commands that undo them, and
         the checks Sentinel will use to verify the effect;
      2. a second person approves (an administrator or a user with the `responder` role; never the requester);
      3. an operator applies the commands on the target system and records it here. Sentinel does not hold credentials
         that can change firewalls or directories, and no model output is ever executed;
      4. Sentinel verifies the effect from the logs it already collects (for a block: denies from the address and no
         accepted session after the change);
      5. rollback produces the undo commands the same way, also recorded; temporary blocks list their expiry.
Every step is written to the action's log and to the audit log. One open action per (kind, target): a second request
returns the existing one (idempotency).
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .db.models import Asset, Firewall, ResponseAction, User

CONTAINMENT = ("block_ip", "disable_account", "isolate_host")
READ_ONLY = ("enrich_ip", "collect_evidence", "notify")
ACTIONS = CONTAINMENT + READ_ONLY
OPEN = ("pending", "approved", "applied")
_ACCOUNT = re.compile(r"^[A-Za-z0-9._@\\-]{1,128}$")
_NAME = re.compile(r"[^A-Za-z0-9_.-]")


class ResponseError(ValueError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _log(a: ResponseAction, who: str, event: str, detail: str = "") -> None:
    a.log = [*(a.log or []), {"at": _now().isoformat(), "who": who, "event": event, "detail": detail[:1000]}]


def can_approve(user: User, a: ResponseAction) -> bool:
    roles = set(getattr(user, "iac_roles", None) or [])        # IaC approvers approve firewall changes there; reuse the same trust here
    return user.username != a.requested_by and (user.role == "admin" or "approver" in roles or "responder" in roles)


def validate_target(kind: str, target: str) -> str:
    t = target.strip()
    is_addr = bool(re.fullmatch(r"[0-9a-fA-F:./]+", t)) and any(c in t for c in ".:")
    if kind in ("block_ip", "enrich_ip") or (kind == "isolate_host" and is_addr):
        try:
            net = ipaddress.ip_network(t, strict=False)
        except ValueError:
            raise ResponseError("target must be an IP address or network")
        if kind == "block_ip":
            if net.prefixlen < (24 if net.version == 4 else 64):
                raise ResponseError("refusing to block a network larger than /24 (IPv4) or /64 (IPv6)")
            if not net.is_global:
                raise ResponseError("internal / reserved addresses are contained with isolate_host, not blocked at the perimeter")
        return str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)
    if kind == "disable_account":
        if not _ACCOUNT.fullmatch(t):
            raise ResponseError("account names are letters, digits and . _ @ \\ -")
        return t
    if kind == "isolate_host":
        if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", t):
            raise ResponseError("host must be an IP address or a host name")
        return t.lower()
    if not t or len(t) > 255:
        raise ResponseError("target is required")
    return t


# ------------------------------------------------------------------ command generation (dry run)
def _fortigate(addr: str, name: str, comment: str) -> tuple[str, str]:
    v6 = ":" in addr
    obj, grp, field = ("address6", "addrgrp6", "ip6") if v6 else ("address", "addrgrp", "subnet")
    value = addr if "/" in addr else (f"{addr}/128" if v6 else f"{addr}/32")
    apply = (f"config firewall {obj}\n    edit \"{name}\"\n        set {field} {value}\n        set comment \"{comment}\"\n    next\nend\n"
             f"config firewall {grp}\n    edit \"SENTINEL-BLOCK{'6' if v6 else ''}\"\n        append member \"{name}\"\n    next\nend")
    undo = (f"config firewall {grp}\n    edit \"SENTINEL-BLOCK{'6' if v6 else ''}\"\n        unselect member \"{name}\"\n    next\nend\n"
            f"config firewall {obj}\n    delete \"{name}\"\nend")
    return apply, undo


def _panos(addr: str, name: str, comment: str) -> tuple[str, str]:
    kind = "ip-netmask"
    value = addr if "/" in addr else (f"{addr}/128" if ":" in addr else f"{addr}/32")
    apply = (f"set address {name} {kind} {value} description \"{comment}\"\nset address-group SENTINEL-BLOCK static {name}\ncommit")
    undo = f"delete address-group SENTINEL-BLOCK static {name}\ndelete address {name}\ncommit"
    return apply, undo


def plan(a: ResponseAction, fw_names: dict[int, tuple[str, str]], asset: Asset | None = None) -> dict:
    """The dry run: what would be done, how to undo it, how Sentinel will check it worked, and the caveats."""
    k, t, p = a.kind, a.target, a.params or {}
    ref = f"Sentinel response #{a.id or 'new'}" + (f" incident {a.incident_id}" if a.incident_id else "")
    if k == "block_ip":
        name = "SENTINEL-" + _NAME.sub("_", t)[:50]
        fws = [fid for fid in (p.get("firewall_ids") or list(fw_names))]
        steps = []
        for fid in fws:
            fname, vendor = fw_names.get(int(fid), (f"firewall #{fid}", "fortinet"))
            apply, undo = (_panos if vendor == "paloalto" else _fortigate)(t, name, ref)
            steps.append({"system": fname, "firewall_id": int(fid), "vendor": vendor, "apply": apply, "rollback": undo})
        return {"summary": f"Block {t} at {len(steps)} firewall(s) by adding it to the SENTINEL-BLOCK address group",
                "steps": steps, "checks": [f"denied sessions from or to {t} after the change", f"no accepted session with {t} after the change"],
                "prerequisites": ["A deny policy (inbound and outbound) must reference the SENTINEL-BLOCK group: created once by a firewall administrator",
                                  "Apply through your change process (IaC page or the firewall console)"],
                "warnings": [w for w in [f"{t} is a CIDR: every address in it is blocked" if "/" in t else "",
                                         "no firewall selected: the plan covers every enabled firewall" if not p.get("firewall_ids") else ""] if w]}
    if k == "disable_account":
        sam = t.split("\\")[-1].split("@")[0]
        return {"summary": f"Disable account {t}", "steps": [
                {"system": "Active Directory", "vendor": "windows", "apply": f"Disable-ADAccount -Identity '{sam}'\n# optional: end sessions\nRevoke-ADAccount... (see your runbook)",
                 "rollback": f"Enable-ADAccount -Identity '{sam}'"},
                {"system": "LDAP (OpenLDAP / 389-ds)", "vendor": "ldap",
                 "apply": f"# add the account to your locked-accounts policy, e.g.\nldapmodify <<'LDIF'\ndn: uid={sam},ou=people,<base-dn>\nchangetype: modify\nreplace: pwdAccountLockedTime\npwdAccountLockedTime: 000001010000Z\nLDIF",
                 "rollback": f"ldapmodify <<'LDIF'\ndn: uid={sam},ou=people,<base-dn>\nchangetype: modify\ndelete: pwdAccountLockedTime\nLDIF"}],
                "checks": [f"failed logins for {t} after the change (the account is refused)", f"no successful login for {t} after the change"],
                "prerequisites": ["Confirm the account owner and business impact (service accounts can stop applications)"], "warnings": []}
    if k == "isolate_host":
        mac = (asset.mac if asset else "") or p.get("mac", "")
        return {"summary": f"Isolate host {t}" + (f" ({asset.hostname})" if asset and asset.hostname else ""), "steps": [
                {"system": "access switch (Cisco IOS)", "vendor": "cisco", "apply": "interface <access-port of the host>\n shutdown\n! or move it to a quarantine VLAN:\n! switchport access vlan <quarantine-vlan>",
                 "rollback": "interface <access-port of the host>\n no shutdown\n! or: switchport access vlan <original-vlan>"},
                {"system": "firewall (FortiGate)", "vendor": "fortinet", "apply": _fortigate(t, "SENTINEL-ISOLATE-" + _NAME.sub("_", t)[:40], ref)[0].replace("SENTINEL-BLOCK", "SENTINEL-ISOLATE"),
                 "rollback": _fortigate(t, "SENTINEL-ISOLATE-" + _NAME.sub("_", t)[:40], ref)[1].replace("SENTINEL-BLOCK", "SENTINEL-ISOLATE")}],
                "checks": [f"no traffic from {t} after the change"],
                "prerequisites": ["Find the access port from the switch MAC table" + (f" (MAC {mac})" if mac else ""), "Tell the owner before isolating"],
                "warnings": ["Isolation interrupts the user's work; the EDR's own isolation, when available, is preferable"]}
    if k == "enrich_ip":
        return {"summary": f"Look up {t} in threat intelligence, GeoIP, assets and recent events", "steps": [], "checks": [], "prerequisites": [], "warnings": []}
    if k == "collect_evidence":
        return {"summary": f"Attach the last 24 hours of events about {t} to the incident as evidence", "steps": [], "checks": [], "prerequisites": [], "warnings": []}
    return {"summary": f"Notify the configured channels about {t}", "steps": [], "checks": [], "prerequisites": [], "warnings": []}


async def request(s: AsyncSession, user: User, kind: str, target: str, *, reason: str, params: dict | None = None,
                  incident_id: int | None = None, alert_id: int | None = None, hours: int | None = None) -> tuple[ResponseAction, bool]:
    """Create (or return the open) action. Returns (action, created)."""
    if kind not in ACTIONS:
        raise ResponseError(f"unknown action {kind!r}")
    target = validate_target(kind, target)
    key = f"{kind}:{target}"
    existing = (await s.execute(select(ResponseAction).where(ResponseAction.idempotency_key == key, ResponseAction.status.in_(OPEN)))).scalars().first()
    if existing:
        return existing, False
    fws = {f.id: (f.name, f.vendor or "fortinet") for f in (await s.execute(select(Firewall).where(Firewall.enabled.is_(True), Firewall.is_demo.is_(False)))).scalars()}
    p = dict(params or {})
    if p.get("firewall_ids"):
        bad = [x for x in p["firewall_ids"] if int(x) not in fws]
        if bad:
            raise ResponseError(f"unknown or disabled firewall(s): {bad}")
    a = ResponseAction(kind=kind, target=target, params=p, reason=reason.strip()[:2000], incident_id=incident_id, alert_id=alert_id,
                       requires_approval=kind in CONTAINMENT, idempotency_key=key, requested_by=user.username, status="pending",
                       expires_at=_now() + timedelta(hours=hours) if hours else None, log=[], result={})
    s.add(a)
    await s.flush()
    asset = (await s.execute(select(Asset).where(Asset.ip == target))).scalar_one_or_none() if kind == "isolate_host" else None
    a.plan = plan(a, fws, asset)
    _log(a, user.username, "requested", reason)
    return a, True


async def decide(s: AsyncSession, a: ResponseAction, user: User, approve: bool, comment: str) -> None:
    if a.status != "pending":
        raise ResponseError(f"action is {a.status}, not pending")
    if not a.requires_approval:
        raise ResponseError("read-only actions need no approval")
    if not can_approve(user, a):
        raise ResponseError("needs a second person: an administrator or a user with the responder / approver role, not the requester")
    a.status, a.decided_by, a.decided_at, a.decision_comment = ("approved" if approve else "rejected"), user.username, _now(), comment.strip()[:2000]
    _log(a, user.username, a.status, comment)


async def record_applied(s: AsyncSession, a: ResponseAction, user: User, note: str) -> None:
    if a.status != "approved":
        raise ResponseError("only an approved action can be recorded as applied")
    a.status, a.applied_by, a.applied_at = "applied", user.username, _now()
    _log(a, user.username, "applied", note)


async def verify(ch, a: ResponseAction) -> dict:
    """Check the effect in the logs since it was applied. For a block: did the firewalls deny the address, and did any
    session still get through? Inconclusive (no traffic yet) is reported as such, never as success."""
    if a.status not in ("applied", "verified", "not_verified") or not a.applied_at:
        raise ResponseError("record the action as applied first")
    since = a.applied_at
    if a.kind in ("block_ip", "isolate_host") and re.fullmatch(r"[0-9a-fA-F:./]+", a.target):
        cond = "(src_ip = {t:String} OR dst_ip = {t:String})" if "/" not in a.target else \
            "(isIPAddressInRange(if(isIPv4String(src_ip) OR isIPv6String(src_ip), src_ip, '::'), {t:String}) OR isIPAddressInRange(if(isIPv4String(dst_ip) OR isIPv6String(dst_ip), dst_ip, '::'), {t:String}))"
        r = (await ch.aquery(f"SELECT countIf(action IN ('deny', 'block')) AS denied, countIf(action IN ('accept', 'close', 'timeout')) AS allowed, "
                             f"max(event_time) AS last FROM events WHERE category = 'traffic' AND event_time >= {{s:DateTime64(3)}} AND {cond}",
                             {"s": since, "t": a.target}))[0]
        denied, allowed = int(r["denied"] or 0), int(r["allowed"] or 0)
        outcome = "not_verified" if allowed else "verified" if denied else "inconclusive"
        detail = f"since the change: {denied} denied, {allowed} allowed session(s)"
    elif a.kind == "disable_account":
        r = (await ch.aquery("SELECT countIf(action = 'logon') AS ok, countIf(action IN ('logon-fail', 'lockout')) AS refused FROM events "
                             "WHERE category = 'system' AND event_time >= {s:DateTime64(3)} AND lower(user) = lower({t:String})", {"s": since, "t": a.target}))[0]
        ok, refused = int(r["ok"] or 0), int(r["refused"] or 0)
        outcome = "not_verified" if ok else "verified" if refused else "inconclusive"
        detail = f"since the change: {refused} refused, {ok} successful login(s)"
    else:
        outcome, detail = "inconclusive", "this action has no log-based check"
    a.result = {**(a.result or {}), "verification": {"outcome": outcome, "detail": detail, "at": _now().isoformat()}}
    if outcome in ("verified", "not_verified"):
        a.status = outcome
    _log(a, "system", f"verification: {outcome}", detail)
    return a.result["verification"]


async def record_rollback(s: AsyncSession, a: ResponseAction, user: User, note: str) -> None:
    if a.status not in ("applied", "verified", "not_verified"):
        raise ResponseError("only an applied action can be rolled back")
    a.status = "rolled_back"
    _log(a, user.username, "rolled_back", note)


async def run_read_only(s: AsyncSession, ch, a: ResponseAction) -> dict:
    """enrich_ip / collect_evidence / notify: nothing outside Sentinel changes, so they run at once."""
    from .db.models import Incident
    if a.kind == "enrich_ip":
        from .enrich.enricher import Enricher
        e = Enricher()
        await e.refresh_ti()
        hit = e.ti.match_ip(a.target)
        geo = e.geo.lookup(a.target) if e.geo.available else {}
        asset = (await s.execute(select(Asset).where(Asset.ip == a.target))).scalar_one_or_none()
        recent = (await ch.aquery("SELECT category, count() AS n, max(event_time) AS last FROM events WHERE event_time >= now() - INTERVAL 7 DAY "
                                  "AND (src_ip = {t:String} OR dst_ip = {t:String}) GROUP BY category", {"t": a.target})) if ch is not None else []
        res = {"threat_intel": {"indicator": hit.indicator, "source": hit.source, "category": hit.category} if hit else None,
               "geo": {k: geo.get(k) for k in ("country", "asn", "as_org")} if geo else None,
               "asset": {"hostname": asset.hostname, "owner": asset.owner, "criticality": asset.criticality} if asset else None,
               "events_7d": {r["category"]: int(r["n"]) for r in recent}}
    elif a.kind == "collect_evidence":
        rows = await ch.aquery("SELECT event_id, event_time, category, action, src_ip, dst_ip, dst_port, user, substring(msg, 1, 200) AS msg FROM events "
                               "WHERE event_time >= now() - INTERVAL 1 DAY AND (src_ip = {t:String} OR dst_ip = {t:String} OR user = {t:String}) "
                               "ORDER BY event_time DESC LIMIT 50", {"t": a.target})
        res = {"events": len(rows), "first": str(rows[-1]["event_time"]) if rows else None, "last": str(rows[0]["event_time"]) if rows else None}
        if a.incident_id:
            inc = await s.get(Incident, a.incident_id)
            if inc:
                inc.evidence = [*(inc.evidence or []), {"type": "events", "ref": f"response:{a.id}", "label": f"{len(rows)} events about {a.target} (last 24 h)",
                                                        "added_by": a.requested_by, "at": _now().isoformat(), "rows": [str(r["event_id"]) for r in rows]}]
    else:
        from .notify import enqueue
        n = await enqueue(s, "response.notify", {"title": f"Response notification: {a.target}", "text": a.reason or f"Analyst notification about {a.target}",
                                                 "fields": {"Target": a.target, "Requested by": a.requested_by, "Incident": str(a.incident_id or "—")}},
                          severity=str((a.params or {}).get("severity") or "high"), dedupe_key=f"response:{a.id}")
        res = {"queued": n, "note": "delivered to every notification rule that subscribes to response.notify" if n else
               "no notification rule subscribes to response.notify (Notifications page)"}
    a.status, a.result = "done", res
    _log(a, a.requested_by, "done")
    return res
