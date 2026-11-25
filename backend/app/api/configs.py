"""APIs: Sentinel NMS → Config Changes (read-only SSH configuration backup, app/configs/backup.py).

Everyone with NMS access sees which devices changed and when; the configuration text and diffs (secrets already
masked) are for administrators. Nothing here connects to a device: the API container has no route to the network.
"Back up now" marks the device due, and the worker takes it within 10 minutes.
"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..configs.backup import COMMANDS, seal, vendor_of
from ..db.models import DeviceConfigSnapshot, DeviceSshCredential, Switch, User
from ..db.pg import get_session
from .deps import audit, current_user, require_admin

router = APIRouter(prefix="/api/nms/config", tags=["nms-config"])


class CredIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    username: str = Field(min_length=1, max_length=64)
    password: str = Field("", max_length=256)
    private_key: str = Field("", max_length=16384)
    description: str = Field("", max_length=1000)


class AssignIn(BaseModel):
    ssh_credential_id: int | None = None


def _iso(v):
    return (v if v.tzinfo else v.replace(tzinfo=timezone.utc)).isoformat() if v else None


def _cred_out(c: DeviceSshCredential, used: int) -> dict:
    return {"id": c.id, "name": c.name, "username": c.username, "description": c.description, "has_secret": bool(c.secret_ciphertext),
            "devices": used, "created_by": c.created_by, "updated_at": _iso(c.updated_at)}


@router.get("/credentials")
async def credentials(_: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    used = dict((await s.execute(select(Switch.ssh_credential_id, func.count()).where(Switch.ssh_credential_id.is_not(None))
                                 .group_by(Switch.ssh_credential_id))).all())
    return {"items": [_cred_out(c, used.get(c.id, 0)) for c in (await s.execute(select(DeviceSshCredential).where(DeviceSshCredential.kind == "ssh")
                                                                                  .order_by(DeviceSshCredential.name))).scalars()]}


@router.post("/credentials")
async def create_credential(body: CredIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    if not body.password and not body.private_key:
        raise HTTPException(422, "a password or a private key is required")
    if (await s.execute(select(DeviceSshCredential).where(DeviceSshCredential.name == body.name))).scalar_one_or_none():
        raise HTTPException(409, "a credential with this name exists")
    if body.private_key:
        import asyncssh
        try:
            asyncssh.import_private_key(body.private_key)
        except Exception:
            raise HTTPException(422, "the private key could not be read (OpenSSH or PEM, without a passphrase)")
    c = DeviceSshCredential(name=body.name, username=body.username, secret_ciphertext=seal(body.password, body.private_key),
                            description=body.description, created_by=user.username)
    s.add(c)
    await s.commit()
    await audit(s, request, user.username, "config_credential_create", c.name)
    await s.commit()
    return _cred_out(c, 0)


@router.put("/credentials/{cid}")
async def update_credential(cid: int, body: CredIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    c = await s.get(DeviceSshCredential, cid)
    if c is None or (c.kind or "ssh") != "ssh":          # other kinds belong to the credential vault (Device Access)
        raise HTTPException(404, "credential not found")
    c.name, c.username, c.description = body.name, body.username, body.description
    if body.password or body.private_key:                    # empty secret fields keep the stored secret
        c.secret_ciphertext = seal(body.password, body.private_key)
    await s.commit()
    await audit(s, request, user.username, "config_credential_update", c.name, {"secret_changed": bool(body.password or body.private_key)})
    await s.commit()
    return {"id": c.id}


@router.delete("/credentials/{cid}")
async def delete_credential(cid: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    c = await s.get(DeviceSshCredential, cid)
    if c is None or (c.kind or "ssh") != "ssh":          # other kinds belong to the credential vault (Device Access)
        raise HTTPException(404, "credential not found")
    await s.delete(c)
    await s.commit()
    await audit(s, request, user.username, "config_credential_delete", c.name)
    await s.commit()
    return {"ok": True}


@router.get("/devices")
async def devices(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    counts = dict((await s.execute(select(DeviceConfigSnapshot.switch_id, func.count()).group_by(DeviceConfigSnapshot.switch_id))).all())
    creds = {c.id: c.name for c in (await s.execute(select(DeviceSshCredential))).scalars()}
    out = []
    for sw in (await s.execute(select(Switch).order_by(Switch.name))).scalars():
        out.append({"id": sw.id, "name": sw.name, "address": sw.address, "site": sw.site, "vendor": sw.vendor, "role": sw.role,
                    "supported": vendor_of(sw) is not None, "commands": list(COMMANDS[vendor_of(sw)][1]) if vendor_of(sw) else [],
                    "ssh_credential_id": sw.ssh_credential_id, "ssh_credential": creds.get(sw.ssh_credential_id),
                    "host_key": (sw.ssh_host_key or "").split(" ")[0] + (" (trusted)" if sw.ssh_host_key else ""),
                    "last_backup": _iso(sw.config_backup_at), "error": sw.config_backup_error, "snapshots": counts.get(sw.id, 0)})
    return {"items": out, "supported_vendors": sorted(COMMANDS)}


@router.put("/devices/{sid}")
async def assign(sid: int, body: AssignIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    sw = await s.get(Switch, sid)
    if sw is None:
        raise HTTPException(404, "device not found")
    if body.ssh_credential_id is not None and ((c := await s.get(DeviceSshCredential, body.ssh_credential_id)) is None or (c.kind or "ssh") != "ssh"):
        raise HTTPException(422, "credential not found")
    old = sw.ssh_credential_id
    sw.ssh_credential_id = body.ssh_credential_id
    sw.config_backup_at = None                                # due at the next worker pass
    await s.commit()
    await audit(s, request, user.username, "config_device_credential", sw.name, {"before": old, "after": body.ssh_credential_id})
    await s.commit()
    return {"id": sw.id, "ssh_credential_id": sw.ssh_credential_id}


@router.post("/devices/{sid}/backup")
async def backup_now(sid: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    sw = await s.get(Switch, sid)
    if sw is None:
        raise HTTPException(404, "device not found")
    if not sw.ssh_credential_id:
        raise HTTPException(422, "assign an SSH credential first")
    sw.config_backup_at = None
    await s.commit()
    await audit(s, request, user.username, "config_backup_request", sw.name)
    await s.commit()
    return {"queued": True, "note": "The worker backs the device up within 10 minutes."}


@router.post("/devices/{sid}/accept-host-key")
async def accept_host_key(sid: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    """Forget the stored host key: the next backup trusts the key the device presents (use after a replacement or a
    key regeneration you have confirmed)."""
    sw = await s.get(Switch, sid)
    if sw is None:
        raise HTTPException(404, "device not found")
    old = (sw.ssh_host_key or "").split(" ")[0]
    sw.ssh_host_key, sw.config_backup_error, sw.config_backup_at = "", "", None
    await s.commit()
    await audit(s, request, user.username, "config_host_key_reset", sw.name, {"previous_key_type": old})
    await s.commit()
    return {"ok": True}


@router.get("/changes")
async def changes(switch_id: int | None = None, days: int = Query(30, ge=1, le=400), _: User = Depends(current_user),
                  s: AsyncSession = Depends(get_session)):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    q = select(DeviceConfigSnapshot.id, DeviceConfigSnapshot.switch_id, DeviceConfigSnapshot.taken_at, DeviceConfigSnapshot.added,
               DeviceConfigSnapshot.removed, DeviceConfigSnapshot.trigger, DeviceConfigSnapshot.size).where(DeviceConfigSnapshot.taken_at >= since)
    if switch_id:
        q = q.where(DeviceConfigSnapshot.switch_id == switch_id)
    rows = (await s.execute(q.order_by(DeviceConfigSnapshot.taken_at.desc()).limit(500))).all()
    names = {x.id: x.name for x in (await s.execute(select(Switch).where(Switch.id.in_({r.switch_id for r in rows} or {0})))).scalars()}
    return {"items": [{"id": r.id, "switch_id": r.switch_id, "switch": names.get(r.switch_id), "taken_at": _iso(r.taken_at), "added": r.added,
                       "removed": r.removed, "trigger": r.trigger, "size": r.size} for r in rows]}


@router.get("/snapshots/{snap_id}")
async def snapshot(snap_id: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    x = await s.get(DeviceConfigSnapshot, snap_id)
    if x is None:
        raise HTTPException(404, "snapshot not found")
    sw = await s.get(Switch, x.switch_id)
    await audit(s, request, user.username, "config_snapshot_view", sw.name if sw else str(x.switch_id), {"snapshot": snap_id})
    await s.commit()
    return {"id": x.id, "switch_id": x.switch_id, "switch": sw.name if sw else None, "taken_at": _iso(x.taken_at), "trigger": x.trigger,
            "added": x.added, "removed": x.removed, "text": x.text, "diff": x.diff,
            "note": "Secrets (passwords, keys, SNMP communities, PSKs) are masked before storage."}


@router.get("/snapshots/{snap_id}/download", response_class=PlainTextResponse)
async def download(snap_id: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    x = await s.get(DeviceConfigSnapshot, snap_id)
    if x is None:
        raise HTTPException(404, "snapshot not found")
    sw = await s.get(Switch, x.switch_id)
    await audit(s, request, user.username, "config_snapshot_download", sw.name if sw else str(x.switch_id), {"snapshot": snap_id})
    await s.commit()
    name = f"{(sw.name if sw else x.switch_id)}-{x.taken_at:%Y%m%d-%H%M%S}.cfg".replace("/", "_")
    return PlainTextResponse(x.text, headers={"Content-Disposition": f'attachment; filename="{name}"'})
