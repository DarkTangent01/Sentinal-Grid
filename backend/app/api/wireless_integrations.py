"""APIs: Sentinel NMS → Wireless → Integrations (Ruckus SmartZone / vSZ, Ruckus One, Juniper Mist, Aruba Central).
Administrators manage them; everyone with NMS access sees their status. Credentials live in the vault (never here)."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import DeviceSshCredential, SwitchNetwork, User, WirelessIntegration
from ..db.pg import get_session
from ..wireless import integrations as W
from .deps import audit, current_user, iso, require_admin

router = APIRouter(prefix="/api/wireless/integrations", tags=["wireless-integrations"])


class IntegrationIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    kind: str = Field(pattern=r"^(smartzone|ruckus_one|mist|aruba_central)$")
    base_url: str = Field(min_length=8, max_length=255)
    org_id: str = Field("", max_length=128)
    site_filter: list[str] = Field(default_factory=list, max_length=200)
    api_version: str = Field("", max_length=16, pattern=r"^(v\d+_\d+)?$")
    credential_id: int | None = None
    verify_tls: bool = True
    interval_seconds: int = Field(300, ge=60, le=86400)
    enabled: bool = True


def _out(i: WirelessIntegration) -> dict:
    return {"id": i.id, "name": i.name, "kind": i.kind, "kind_label": W.KINDS[i.kind], "base_url": i.base_url, "org_id": i.org_id,
            "site_filter": i.site_filter or [], "api_version": i.api_version, "credential_id": i.credential_id, "verify_tls": i.verify_tls,
            "switch_id": i.switch_id, "interval_seconds": i.interval_seconds, "enabled": i.enabled, "last_sync_at": iso(i.last_sync_at),
            "last_ok_at": iso(i.last_ok_at), "last_error": i.last_error, "stats": i.stats or {}}


async def _check(s: AsyncSession, body: IntegrationIn) -> str:
    try:
        url = W.validate_base_url(body.kind, body.base_url, (await s.execute(select(SwitchNetwork))).scalars().all())
    except W.IntegrationError as e:
        raise HTTPException(422, str(e))
    if body.kind in ("mist", "ruckus_one") and not body.org_id:
        raise HTTPException(422, "the organisation / tenant id is required")
    if body.credential_id is not None:
        c = await s.get(DeviceSshCredential, body.credential_id)
        want = "https" if body.kind == "smartzone" else "api_token"
        if c is None or (c.kind or "ssh") != want:
            raise HTTPException(422, f"{W.KINDS[body.kind]} needs a vault credential of kind {want}")
    return url


@router.get("")
async def list_integrations(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    return {"kinds": W.KINDS, "items": [_out(i) for i in (await s.execute(select(WirelessIntegration).order_by(WirelessIntegration.name))).scalars()]}


@router.post("", status_code=201)
async def create(body: IntegrationIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    url = await _check(s, body)
    if (await s.execute(select(WirelessIntegration).where(WirelessIntegration.name == body.name))).scalar_one_or_none():
        raise HTTPException(409, "an integration with this name exists")
    i = WirelessIntegration(**{**body.model_dump(), "base_url": url}, created_by=user.username)
    s.add(i)
    await s.commit()
    await audit(s, request, user.username, "wireless_integration_create", i.name, {"kind": i.kind, "base_url": url})
    return _out(i)


@router.put("/{iid}")
async def update_integration(iid: int, body: IntegrationIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    i = await s.get(WirelessIntegration, iid)
    if i is None:
        raise HTTPException(404, "integration not found")
    if body.kind != i.kind:
        raise HTTPException(422, "the kind of an integration cannot change")
    url = await _check(s, body)
    for k, v in {**body.model_dump(), "base_url": url}.items():
        setattr(i, k, v)
    await s.commit()
    await audit(s, request, user.username, "wireless_integration_update", i.name, {"kind": i.kind, "base_url": url, "enabled": i.enabled})
    return _out(i)


@router.delete("/{iid}")
async def delete_integration(iid: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    """Removes the integration; its virtual controller (and the wireless data under it) stays until deleted in Switch Monitoring."""
    i = await s.get(WirelessIntegration, iid)
    if i is None:
        raise HTTPException(404, "integration not found")
    await s.delete(i)
    await s.commit()
    await audit(s, request, user.username, "wireless_integration_delete", i.name, {"kind": i.kind})
    return {"ok": True}


@router.post("/{iid}/sync")
async def sync_now(iid: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    """Synchronise now (also the connection test). Read-only calls to the vendor API."""
    from ..db.ch import get_ch
    i = await s.get(WirelessIntegration, iid)
    if i is None:
        raise HTTPException(404, "integration not found")
    res = await W.sync(s, get_ch(), i, transport=_TRANSPORT.get("t"), now=datetime.now(timezone.utc))
    await audit(s, request, user.username, "wireless_integration_sync", i.name, {"ok": res.get("ok"), "error": res.get("error", "")[:300]}, success=bool(res.get("ok")))
    return res


_TRANSPORT: dict = {}   # tests only: an httpx transport standing in for the vendor API
