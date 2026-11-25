"""Controlled configuration changes on one device.

  1. request      a user with nms.device.access.configuration submits lines (+ rollback lines, window, reason)
  2. validate     the device exists, is in scope, has an SSH credential and a platform with a change procedure
  3. classify     every line (configuration context); DESTRUCTIVE lines are refused outright
  4. authorise    approval by a different user holding nms.configuration.approve (always: four eyes)
  5. backup       a fresh configuration backup before anything is sent; no backup, no change
  6. preview      the lines in order; Junos: the device's own "show | compare" of the candidate (dry run, no commit)
  7. execute      only when NMS_CONFIG_CHANGES_ENABLED is set; inside the approved window; stops at the first error
  8. verify       a new SSH login and a read-only command succeed (Junos: before the confirmed commit is confirmed,
                  so a change that cuts management access rolls back by itself)
  9. compare      a backup after the change and the diff between the two
 10. audit        every step in the change log and the hash-chained access audit
 11. rollback     Junos: "rollback 1" + commit; other platforms: the approved rollback lines

Nothing here runs from an alert or a schedule: every execution is an explicit user action on an approved request.
"""
from __future__ import annotations

import difflib
import re
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..configs.backup import backup_switch, fetch, mask
from ..db.models import DeviceConfigSnapshot, NmsChangeRequest, Switch, User
from . import audit, rbac, vault
from .commands import D, H, M, RANK, classify, worst
from .gateway import ERRORS, AccessError, Shell, connect, resolve, run_read_only

# platform → how a change is entered and left
PROCEDURES = {
    "cisco_ios": {"enter": ["terminal length 0", "configure terminal"], "leave": ["end"], "save": "write memory", "verify": "show version"},
    "cisco_nxos": {"enter": ["terminal length 0", "configure terminal"], "leave": ["end"], "save": "copy running-config startup-config", "verify": "show version"},
    "arista_eos": {"enter": ["terminal length 0", "configure terminal"], "leave": ["end"], "save": "write memory", "verify": "show version"},
    "ruckus_icx": {"enter": ["skip-page-display", "configure terminal"], "leave": ["end"], "save": "write memory", "verify": "show version"},
    "fortios": {"enter": [], "leave": [], "save": "", "verify": "get system status"},        # FortiOS saves on "end" of each block
    "junos": {"enter": ["set cli screen-length 0", "configure private"], "leave": [], "save": "", "verify": "show version"},
}
MAX_LINES, MAX_LINE = 500, 512
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(v):
    return v if v is None or v.tzinfo else v.replace(tzinfo=timezone.utc)


def log_event(cr: NmsChangeRequest, who: str, event: str, detail: str = "") -> None:
    cr.log = [*(cr.log or []), {"at": now().isoformat(), "who": who, "event": event, "detail": detail[:500]}]


def clean_lines(lines: list[str]) -> list[str]:
    out = [ln.rstrip() for ln in lines if ln.strip()]
    if not out:
        raise AccessError(422, "a change needs at least one configuration line")
    if len(out) > MAX_LINES:
        raise AccessError(422, f"at most {MAX_LINES} lines per change")
    for ln in out:
        if len(ln) > MAX_LINE or _CTRL.search(ln):
            raise AccessError(422, "lines must be printable text of at most 512 characters")
    return out


def assess(lines: list[str]) -> tuple[str, list[dict]]:
    per = []
    for ln in lines:
        r, why = classify(ln, config_context=True)
        per.append({"line": mask(ln), "risk": r, "reason": why})
    risk = worst(M, *(p["risk"] for p in per))
    return risk, per


async def create(s: AsyncSession, user: User, switch_id: int, *, title: str, reason: str, lines: list[str], rollback_lines: list[str],
                 save_config: bool, window_start: datetime | None, window_end: datetime | None) -> NmsChangeRequest:
    t = await resolve(s, user, switch_id, "ssh")
    lines = clean_lines(lines)
    rb = [ln.rstrip() for ln in rollback_lines if ln.strip()]
    if rb:
        rb = clean_lines(rb)
    risk, per = assess(lines)
    destructive = [p["line"] for p in per if p["risk"] == D]
    if destructive:
        raise AccessError(422, f"destructive commands cannot be part of a change request: {destructive[0]}")
    if t.platform not in PROCEDURES:
        raise AccessError(409, f"no change procedure for this device's platform ({t.platform or 'unknown'}); supported: {', '.join(PROCEDURES)}")
    if RANK[risk] >= RANK[H] and t.platform != "junos" and not rb:
        raise AccessError(422, "a high-risk change needs rollback lines (Junos changes roll back with 'rollback 1')")
    rb_risk, rb_per = assess(rb) if rb else (M, [])
    if any(p["risk"] == D for p in rb_per):
        raise AccessError(422, "rollback lines cannot contain destructive commands")
    if window_start and window_end and _aware(window_end) <= _aware(window_start):
        raise AccessError(422, "the change window must end after it starts")
    cred, _ = await vault.resolve(s, t.switch, "ssh")
    if cred is None:
        raise AccessError(409, "the device has no SSH credential; a change needs one (and a backup before it)")
    cr = NmsChangeRequest(switch_id=t.switch.id, device_name=t.switch.name, title=title[:200], reason=reason, lines=lines, rollback_lines=rb,
                          save_config=save_config, risk=worst(risk, rb_risk) if rb else risk, status="pending_approval",
                          window_start=window_start, window_end=window_end, requested_by=user.username,
                          result={"line_risks": per, "rollback_risks": rb_per, "platform": t.platform})
    cr.preview = preview_text(cr, t.platform)
    log_event(cr, user.username, "requested", f"{len(lines)} lines, risk {cr.risk}")
    s.add(cr)
    await s.commit()
    return cr


def preview_text(cr: NmsChangeRequest, platform: str | None) -> str:
    p = PROCEDURES.get(platform or "", {})
    body = [*(f"  {x}" for x in p.get("enter", [])), *(f"+ {mask(x)}" for x in cr.lines), *(f"  {x}" for x in p.get("leave", []))]
    if platform == "junos":
        body += ["  show | compare", f"  commit confirmed {get_settings().nms_change_confirm_minutes}  (confirmed after verification)"]
    if cr.save_config and p.get("save"):
        body.append(f"  {p['save']}  (after verification)")
    return "\n".join(body)


async def decide(s: AsyncSession, user: User, cr: NmsChangeRequest, approve: bool, comment: str) -> NmsChangeRequest:
    if cr.status != "pending_approval":
        raise AccessError(409, f"the request is {cr.status}, not pending approval")
    if not rbac.has(user, "nms.configuration.approve"):
        raise AccessError(403, "permission nms.configuration.approve required")
    if user.username == cr.requested_by:
        raise AccessError(403, "the requester cannot approve their own change (a second person must)")
    sw = await s.get(Switch, cr.switch_id) if cr.switch_id else None
    from ..products import site_allowed
    if sw is None or not site_allowed(user, sw.site):
        raise AccessError(403, "this device is outside your site scope")
    cr.status = "approved" if approve else "rejected"
    cr.approved_by, cr.approved_at, cr.decision_comment = user.username, now(), comment[:2000]
    log_event(cr, user.username, cr.status, comment)
    await s.commit()
    return cr


def _check_executable(cr: NmsChangeRequest, user: User, *, rollback: bool = False) -> None:
    st = get_settings()
    if not st.nms_config_changes_enabled:
        raise AccessError(409, "configuration changes are disabled on this installation (NMS_CONFIG_CHANGES_ENABLED)", "disabled")
    need = "nms.configuration.approve" if rollback else "nms.device.access.configuration"
    if not rbac.has(user, need):
        raise AccessError(403, f"permission {need} required")
    if rollback:
        if cr.status not in ("completed", "failed", "verify_failed"):
            raise AccessError(409, f"a {cr.status} change cannot be rolled back")
        return
    if cr.status != "approved":
        raise AccessError(409, f"the request is {cr.status}; only an approved change can run")
    t = now()
    if cr.window_start and t < _aware(cr.window_start):
        raise AccessError(409, "the approved change window has not started")
    if cr.window_end and t > _aware(cr.window_end):
        raise AccessError(409, "the approved change window has ended")


async def _backup(s: AsyncSession, sw: Switch, fetcher) -> int:
    r = await backup_switch(s, sw, trigger="change", fetcher=fetcher or fetch)
    if not r.get("ok"):
        raise AccessError(502, f"configuration backup failed: {r.get('error', '')}", "backup_failed")
    return r["snapshot_id"]


async def _apply(sh: Shell, platform: str, lines: list[str], out: list[str]) -> str | None:
    """Send the procedure; returns the first error text, or None."""
    p = PROCEDURES[platform]
    for ln in [*p["enter"], *lines]:
        text = await sh.send(ln)
        out.append(f"> {mask(ln)}\n{mask(text)}")
        if ERRORS.search(text):
            return f"'{mask(ln)}' failed: {mask(text).strip()[:300]}"
    return None


async def _leave(sh: Shell, platform: str, out: list[str]) -> None:
    for ln in PROCEDURES[platform]["leave"]:
        out.append(f"> {ln}\n{mask(await sh.send(ln))}")


async def _verify(t, cred, platform: str) -> tuple[bool, str]:
    try:
        conn, _, _ = await connect(t, cred)
    except AccessError as e:
        return False, e.message
    try:
        r = await run_read_only(conn, platform, [PROCEDURES[platform]["verify"]], float(get_settings().access_command_timeout_seconds))
        return r[0]["status"] == "ok", r[0]["output"][:200] if r[0]["status"] != "ok" else ""
    finally:
        conn.close()


def _snap_diff(a: DeviceConfigSnapshot | None, b: DeviceConfigSnapshot | None, name: str) -> tuple[str, int, int]:
    if a is None or b is None or a.id == b.id:
        return "", 0, 0
    d = list(difflib.unified_diff(a.text.splitlines(), b.text.splitlines(), f"{name} (before)", f"{name} (after)", lineterm="", n=3))
    return "\n".join(d), sum(1 for x in d if x.startswith("+") and not x.startswith("+++")), sum(1 for x in d if x.startswith("-") and not x.startswith("---"))


async def execute(s: AsyncSession, user: User, cr: NmsChangeRequest, *, client_ip: str = "", backup_fetcher=None) -> NmsChangeRequest:
    _check_executable(cr, user)
    t = await resolve(s, user, cr.switch_id, "ssh")
    platform = t.platform
    if platform not in PROCEDURES:
        raise AccessError(409, f"no change procedure for {platform}")
    cred, _ = await vault.resolve(s, t.switch, "ssh")
    cr.status, cr.executed_by, cr.executed_at = "executing", user.username, now()
    log_event(cr, user.username, "executing")
    await s.commit()
    out: list[str] = []
    try:
        cr.pre_snapshot_id = await _backup(s, t.switch, backup_fetcher)
        log_event(cr, user.username, "backup_before", f"snapshot {cr.pre_snapshot_id}")
        conn, _, _ = await connect(t, cred)
        try:
            sh = await Shell.open(conn, float(get_settings().access_command_timeout_seconds))
            err = await _apply(sh, platform, cr.lines, out)
            if platform == "junos":
                if err:
                    out.append(f"> rollback 0\n{await sh.send('rollback 0')}")
                    out.append(f"> exit configuration-mode\n{await sh.send('exit configuration-mode')}")
                else:
                    cmp_ = await sh.send("show | compare")
                    out.append(f"> show | compare\n{mask(cmp_)}")
                    text = await sh.send(f"commit confirmed {get_settings().nms_change_confirm_minutes} comment \"sentinel change {cr.id}\"")
                    out.append(f"> commit confirmed\n{mask(text)}")
                    if ERRORS.search(text) or "commit complete" not in text.lower():
                        err = f"commit failed: {mask(text).strip()[:300]}"
                    out.append(f"> exit configuration-mode\n{await sh.send('exit configuration-mode')}")
            else:
                await _leave(sh, platform, out)
            sh.close()
        finally:
            conn.close()
        if err:
            cr.status, cr.result = "failed", {**cr.result, "error": err}
            log_event(cr, user.username, "failed", err)
        else:
            ok, why = await _verify(t, cred, platform)
            if not ok:
                cr.status, cr.result = "verify_failed", {**cr.result, "error": f"verification failed: {why}"}
                log_event(cr, user.username, "verify_failed",
                          why + (" — the confirmed commit was not confirmed and rolls back by itself" if platform == "junos" else ""))
            else:
                conn, _, _ = await connect(t, cred)
                try:
                    sh = await Shell.open(conn, float(get_settings().access_command_timeout_seconds))
                    if platform == "junos":
                        for ln in ("configure", "commit comment \"sentinel change confirmed\"", "exit configuration-mode"):
                            out.append(f"> {ln}\n{mask(await sh.send(ln))}")
                    elif cr.save_config and PROCEDURES[platform]["save"]:
                        ln = PROCEDURES[platform]["save"]
                        out.append(f"> {ln}\n{mask(await sh.send(ln))}")
                    sh.close()
                finally:
                    conn.close()
                cr.status = "completed"
                log_event(cr, user.username, "completed", "verified")
        try:
            cr.post_snapshot_id = await _backup(s, t.switch, backup_fetcher)
            pre = await s.get(DeviceConfigSnapshot, cr.pre_snapshot_id)
            post = await s.get(DeviceConfigSnapshot, cr.post_snapshot_id)
            d, added, removed = _snap_diff(pre, post, t.switch.name)
            cr.result = {**cr.result, "diff": d, "added": added, "removed": removed}
            log_event(cr, user.username, "backup_after", f"snapshot {cr.post_snapshot_id}: +{added} -{removed}")
        except AccessError as e:
            log_event(cr, user.username, "backup_after_failed", e.message)
    except AccessError as e:
        cr.status, cr.result = "failed", {**cr.result, "error": e.message}
        log_event(cr, user.username, "failed", e.message)
    cr.output = "\n".join(out)[:500_000]
    await s.commit()
    await audit.record(s, user.username, "change_execute", switch_id=cr.switch_id, target=cr.device_name,
                       detail={"change_id": cr.id, "status": cr.status, "risk": cr.risk, "approved_by": cr.approved_by, "lines": len(cr.lines),
                               "error": (cr.result or {}).get("error", "")[:300]}, client_ip=client_ip, success=cr.status == "completed")
    return cr


async def rollback(s: AsyncSession, user: User, cr: NmsChangeRequest, *, client_ip: str = "", backup_fetcher=None) -> NmsChangeRequest:
    _check_executable(cr, user, rollback=True)
    t = await resolve(s, user, cr.switch_id, "ssh")
    platform = t.platform
    if platform != "junos" and not cr.rollback_lines:
        raise AccessError(409, "this change has no rollback lines; restore from the configuration backup by a new change request")
    cred, _ = await vault.resolve(s, t.switch, "ssh")
    out: list[str] = []
    err = None
    conn, _, _ = await connect(t, cred)
    try:
        sh = await Shell.open(conn, float(get_settings().access_command_timeout_seconds))
        if platform == "junos":
            for ln in ("configure private", "rollback 1", "show | compare", f"commit comment \"sentinel rollback of change {cr.id}\"", "exit configuration-mode"):
                text = await sh.send(ln)
                out.append(f"> {ln}\n{mask(text)}")
                if ERRORS.search(text):
                    err = f"'{ln}' failed"
                    break
        else:
            err = await _apply(sh, platform, cr.rollback_lines, out)
            await _leave(sh, platform, out)
        sh.close()
    finally:
        conn.close()
    cr.output = (cr.output + "\n\n--- rollback ---\n" + "\n".join(out))[:500_000]
    if err:
        cr.result = {**cr.result, "rollback_error": err}
        log_event(cr, user.username, "rollback_failed", err)
    else:
        cr.status = "rolled_back"
        log_event(cr, user.username, "rolled_back")
        try:
            snap = await _backup(s, t.switch, backup_fetcher)
            cr.result = {**cr.result, "rollback_snapshot_id": snap}
        except AccessError as e:
            log_event(cr, user.username, "backup_after_failed", e.message)
    await s.commit()
    await audit.record(s, user.username, "change_rollback", switch_id=cr.switch_id, target=cr.device_name,
                       detail={"change_id": cr.id, "error": err or ""}, client_ip=client_ip, success=err is None)
    return cr
