"""Configuration backup alert rules (same Detection pipeline as the other NMS rules; maintenance windows apply)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from ..db.models import DeviceConfigSnapshot
from ..db.pg import session_factory

TROUBLE = {
    "switch_config_changed": ["Review the diff (Config Changes) and confirm it matches an approved change",
                              "Check TACACS+ accounting for who was logged in at that time"],
    "switch_ssh_hostkey_changed": ["Confirm the device was replaced or its SSH key regenerated (crypto key generate)",
                                   "If expected, accept the new key on the Config Changes → Devices page; otherwise treat it as a possible interception"],
}
DEFAULT_RULES = [
    {"key": "switch_config_changed", "name": "Network device configuration changed", "severity": "low", "mitre": {},
     "description": "A device's running configuration differs from its previous backup (read-only SSH backup, secrets masked).",
     "params": {"window_minutes": 120}},
    {"key": "switch_ssh_hostkey_changed", "name": "Network device SSH host key changed", "severity": "high", "mitre": {},
     "description": "The device presented a different SSH host key than the one trusted on first use; configuration backups stop "
                    "before any credential is sent.", "params": {}},
]
AUTO_RESOLVE = {"switch_ssh_hostkey_changed"}


async def rule_switch_config_changed(ch, now, p):
    from ..switches.alerts import _context, _det
    since = now - timedelta(minutes=int(p.get("window_minutes", 120)))
    async with session_factory()() as s:
        snaps = (await s.execute(select(DeviceConfigSnapshot.id, DeviceConfigSnapshot.switch_id, DeviceConfigSnapshot.taken_at,
                                        DeviceConfigSnapshot.added, DeviceConfigSnapshot.removed, DeviceConfigSnapshot.trigger)
                                 .where(DeviceConfigSnapshot.taken_at >= since, DeviceConfigSnapshot.trigger != "first"))).all()
    if not snaps:
        return []
    sws, bs = await _context()
    by = {x.id: x for x in sws}
    out = []
    for r in snaps:
        sw = by.get(r.switch_id)
        if sw is None:
            continue
        at = r.taken_at if r.taken_at.tzinfo else r.taken_at.replace(tzinfo=timezone.utc)
        out.append(_det(sw, bs, f"{sw.id}:cfg:{r.id}", "switch_config_changed",
                        f"{sw.name}: running configuration changed (+{r.added} / -{r.removed} lines), found by the {r.trigger} backup at "
                        f"{at:%Y-%m-%d %H:%M} UTC", first=at, last=at, component="running-config", metric="config_lines_changed",
                        value=r.added + r.removed, extra={"snapshot_id": r.id, "added": r.added, "removed": r.removed,
                                                          "link": f"/nms/configs?switch={sw.id}&snapshot={r.id}"}))
    return out


async def rule_switch_ssh_hostkey_changed(ch, now, p):
    from ..switches.alerts import _context, _det
    sws, bs = await _context()
    return [_det(sw, bs, f"{sw.id}:hostkey", "switch_ssh_hostkey_changed", f"{sw.name} ({sw.address}): {sw.config_backup_error.split(': ', 1)[-1]}",
                 first=now, last=now, component="SSH", metric="ssh_host_key", severity="high")
            for sw in sws if (sw.config_backup_error or "").startswith("host_key_changed")]


RULES = {d["key"]: globals()[f"rule_{d['key']}"] for d in DEFAULT_RULES}


async def housekeeping(s, now: datetime, retention_days: int) -> int:
    """Delete snapshots older than the retention, always keeping each device's newest one."""
    from sqlalchemy import delete, func
    from sqlalchemy.orm import aliased
    later = aliased(DeviceConfigSnapshot)
    newest_at = (select(func.max(later.taken_at)).where(later.switch_id == DeviceConfigSnapshot.switch_id).scalar_subquery())
    res = await s.execute(delete(DeviceConfigSnapshot).where(DeviceConfigSnapshot.taken_at < now - timedelta(days=retention_days),
                                                             DeviceConfigSnapshot.taken_at < newest_at))
    return res.rowcount or 0


async def loop_body(ch, s) -> dict:
    """Worker loop: due backups, then retention."""
    from ..config import get_settings
    from .backup import run_due
    now = datetime.now(timezone.utc)
    res = await run_due(ch, s, now)
    res["deleted"] = await housekeeping(s, now, get_settings().config_backup_retention_days)
    from ..access.gateway import expire_pending
    from ..access.terminal import purge_recordings
    res["recordings_deleted"] = await purge_recordings(s, now)       # device-access recordings (app/access)
    await s.commit()
    res["tickets_expired"] = await expire_pending(s)
    return res
