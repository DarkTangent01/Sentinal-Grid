"""Notification channels, rules and delivery log (shared service: each product app mounts it)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import NotificationChannel, NotificationOutbox, NotificationRule, User
from ..db.pg import get_session
from ..netguard import DestinationError, check_host_static, check_url_static
from ..notify import EVENT_TYPES, deliver, seal, secrets_of
from .deps import audit, iso, require_admin

router = APIRouter(prefix="/api", tags=["notifications"])


def ch_out(c: NotificationChannel) -> dict:
    sec = secrets_of(c)
    return {"id": c.id, "name": c.name, "type": c.type, "config": c.config, "enabled": c.enabled,
            "has_secret": bool(sec), "secret_fields": sorted(sec)}  # secret values are never returned


class ChannelIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    type: str = Field(pattern=r"^(email|slack|teams|webhook)$")
    config: dict = Field(default_factory=dict)  # email: host, port, security, username, from_addr, to[]
    url: str | None = Field(None, max_length=2048)  # slack/teams/webhook (stored encrypted)
    password: str | None = Field(None, max_length=512)  # SMTP (stored encrypted)
    hmac_secret: str | None = Field(None, max_length=512)  # webhook signing (stored encrypted)
    enabled: bool = True


def _validate_channel(body: ChannelIn, existing_secret: dict) -> dict:
    secret = {**existing_secret, **{k: v for k, v in (("url", body.url), ("password", body.password), ("hmac_secret", body.hmac_secret)) if v}}
    if body.type in ("slack", "teams", "webhook") and not str(secret.get("url", "")).lower().startswith(("https://", "http://")):
        raise HTTPException(422, "a webhook URL (https://...) is required")
    try:
        if body.type in ("slack", "teams", "webhook"):
            check_url_static(str(secret["url"]), ("https", "http"))
        elif body.type == "email" and body.config.get("host"):
            check_host_static(str(body.config["host"]))
    except DestinationError as e:
        raise HTTPException(422, str(e))
    if body.type == "email":
        cfg = body.config
        if not cfg.get("host") or not cfg.get("to"):
            raise HTTPException(422, "SMTP host and at least one recipient are required")
        if cfg.get("security", "starttls") not in ("starttls", "ssl", "none"):
            raise HTTPException(422, "security must be starttls, ssl or none")
    return secret


@router.get("/notifications/channels")
async def list_channels(_: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    return [ch_out(c) for c in (await s.execute(select(NotificationChannel).order_by(NotificationChannel.name))).scalars()]


@router.post("/notifications/channels", status_code=201)
async def create_channel(body: ChannelIn, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    secret = _validate_channel(body, {})
    c = NotificationChannel(name=body.name, type=body.type, config=body.config, secret_ciphertext=seal(secret), enabled=body.enabled)
    s.add(c)
    await s.commit()
    await audit(s, request, admin.username, "notify_channel_create", body.name, {"type": body.type})
    return ch_out(c)


@router.put("/notifications/channels/{cid}")
async def update_channel(cid: int, body: ChannelIn, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    c = await s.get(NotificationChannel, cid)
    if not c:
        raise HTTPException(404, "not found")
    secret = _validate_channel(body, secrets_of(c))
    c.name, c.type, c.config, c.enabled, c.secret_ciphertext = body.name, body.type, body.config, body.enabled, seal(secret)
    await s.commit()
    await audit(s, request, admin.username, "notify_channel_update", body.name)
    return ch_out(c)


@router.delete("/notifications/channels/{cid}")
async def delete_channel(cid: int, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    c = await s.get(NotificationChannel, cid)
    if not c:
        raise HTTPException(404, "not found")
    await s.delete(c)
    await s.commit()
    await audit(s, request, admin.username, "notify_channel_delete", c.name)
    return {"ok": True}


@router.post("/notifications/channels/{cid}/test")
async def test_channel(cid: int, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    c = await s.get(NotificationChannel, cid)
    if not c:
        raise HTTPException(404, "not found")
    payload = {"title": "Sentinel Grid test notification", "text": f"Test message sent by {admin.username}.",
               "severity": "informational", "fields": {"Channel": c.name}, "event_type": "test"}
    try:
        await deliver(c, payload)
        ok, err = True, None
    except Exception as e:
        ok, err = False, f"{type(e).__name__}: {e}"[:300]
    await audit(s, request, admin.username, "notify_channel_test", c.name, {"ok": ok}, success=ok)
    return {"ok": ok, "error": err}


class RuleIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    channel_id: int
    event_types: list[str] = Field(min_length=1)
    min_severity: str = Field("high", pattern=r"^(informational|low|medium|high|critical)$")
    rule_keys: list[str] = Field(default_factory=list)
    quiet_start: str | None = Field(None, pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    quiet_end: str | None = Field(None, pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    quiet_tz: str = Field("UTC", max_length=64)
    dedupe_minutes: int = Field(30, ge=0, le=1440)
    enabled: bool = True


def nr_out(r: NotificationRule) -> dict:
    return {k: getattr(r, k) for k in ("id", "name", "channel_id", "event_types", "min_severity", "rule_keys", "quiet_start", "quiet_end",
                                       "quiet_tz", "dedupe_minutes", "enabled")}


@router.get("/notifications/rules")
async def list_nrules(_: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    return {"rules": [nr_out(r) for r in (await s.execute(select(NotificationRule).order_by(NotificationRule.id))).scalars()],
            "event_types": list(EVENT_TYPES)}


async def _save_rule(s, r: NotificationRule, body: RuleIn):
    bad = set(body.event_types) - set(EVENT_TYPES)
    if bad:
        raise HTTPException(422, f"unknown event types {sorted(bad)}")
    if not await s.get(NotificationChannel, body.channel_id):
        raise HTTPException(422, "channel not found")
    for k, v in body.model_dump().items():
        setattr(r, k, v)


@router.post("/notifications/rules", status_code=201)
async def create_nrule(body: RuleIn, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    r = NotificationRule()
    await _save_rule(s, r, body)
    s.add(r)
    await s.commit()
    await audit(s, request, admin.username, "notify_rule_create", body.name)
    return nr_out(r)


@router.put("/notifications/rules/{rid}")
async def update_nrule(rid: int, body: RuleIn, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    r = await s.get(NotificationRule, rid)
    if not r:
        raise HTTPException(404, "not found")
    await _save_rule(s, r, body)
    await s.commit()
    await audit(s, request, admin.username, "notify_rule_update", body.name)
    return nr_out(r)


@router.delete("/notifications/rules/{rid}")
async def delete_nrule(rid: int, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    r = await s.get(NotificationRule, rid)
    if not r:
        raise HTTPException(404, "not found")
    await s.delete(r)
    await s.commit()
    await audit(s, request, admin.username, "notify_rule_delete", r.name)
    return {"ok": True}


@router.get("/notifications/log")
async def notify_log(_: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    rows = (await s.execute(select(NotificationOutbox).order_by(NotificationOutbox.id.desc()).limit(200))).scalars()
    return [{"id": o.id, "created_at": iso(o.created_at), "channel_id": o.channel_id, "rule_id": o.rule_id, "event_type": o.event_type,
             "title": (o.payload or {}).get("title"), "severity": (o.payload or {}).get("severity"), "status": o.status,
             "attempts": o.attempts, "sent_at": iso(o.sent_at), "error": o.error} for o in rows]


