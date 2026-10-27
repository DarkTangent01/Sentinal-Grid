import ipaddress
import os
import re

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db.ch import ClickHouse
from ..db.models import Firewall, IngestStat, User
from ..db.pg import get_session
from ..fortigate.client import FortiGateError
from ..fortigate.versions import support_level
from ..netguard import DestinationError, check_host_static
from ..security import TokenCipher
from .deps import iso, audit, ch_dep, current_user, require_admin

router = APIRouter(prefix="/api/firewalls", tags=["firewalls"])
VDOM_RE = re.compile(r"^[A-Za-z0-9_.\-]{0,31}$")
HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$|^[0-9a-fA-F:.]+$")


class FirewallIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    host: str = Field(min_length=1, max_length=255)
    vendor: str = Field("fortinet", pattern=r"^(fortinet|paloalto)$")
    log_tz: str = Field("UTC", max_length=64)  # IANA zone; PAN-OS syslog carries local time without an offset
    https_port: int = Field(443, ge=1, le=65535)
    fortios_version: str | None = Field(None, max_length=32)
    api_method: str = Field("token", pattern=r"^token$")
    api_token: str | None = Field(None, min_length=10, max_length=512)
    vdom: str = Field("root", max_length=64)
    site: str = Field("", max_length=128)
    tags: list[str] = Field(default_factory=list, max_length=20)
    poll_interval_seconds: int = Field(60, ge=15, le=3600)
    ca_bundle_path: str | None = Field(None, max_length=512)
    syslog_source_ips: list[str] = Field(default_factory=list, max_length=16)
    api_log_pull: bool = False
    api_log_device: str = Field("disk", pattern=r"^(memory|disk|fortianalyzer|forticloud)$")
    enabled: bool = True

    @field_validator("host")
    @classmethod
    def _host(cls, v):
        if v is None:
            return v
        if not HOST_RE.match(v):
            raise ValueError("invalid hostname or IP")
        try:
            check_host_static(v)  # loopback, link-local/metadata and this stack's own services are never FortiGates
        except DestinationError as e:
            raise ValueError(str(e))
        return v

    @field_validator("log_tz")
    @classmethod
    def _tz(cls, v):
        from zoneinfo import ZoneInfo
        try:
            ZoneInfo(v)
        except (KeyError, ValueError):
            raise ValueError("log_tz must be an IANA time zone such as Asia/Kolkata or UTC")
        return v

    @field_validator("vdom")
    @classmethod
    def _vdom(cls, v):
        if not VDOM_RE.match(v):
            raise ValueError("invalid VDOM name")
        return v

    @field_validator("tags")
    @classmethod
    def _tags(cls, v):
        if any(len(t) > 64 for t in v):
            raise ValueError("tags are limited to 64 characters")
        return v

    @field_validator("syslog_source_ips")
    @classmethod
    def _ips(cls, v):
        try:
            return [str(ipaddress.ip_address(x.strip())) for x in v]
        except ValueError:
            raise ValueError("syslog_source_ips must be IP addresses")

    @field_validator("ca_bundle_path")
    @classmethod
    def _ca(cls, v):
        if not v:
            return v
        base = os.path.realpath(get_settings().fortigate_ca_dir)
        real = os.path.realpath(v)
        if os.path.commonpath([base, real]) != base:
            raise ValueError(f"ca_bundle_path must be a file inside {base}")
        return real


class FirewallPatch(FirewallIn):
    name: str | None = Field(None, min_length=1, max_length=128)
    vendor: str | None = Field(None, pattern=r"^(fortinet|paloalto)$")
    host: str | None = Field(None, min_length=1, max_length=255)


def fw_out(fw: Firewall, stats: list[IngestStat] | None = None) -> dict:
    """Never includes the API token or its ciphertext."""
    ingest = [{"source": s.source, "last_event_time": iso(s.last_event_time),
               "last_ingest_time": iso(s.last_ingest_time),
               "lag_seconds": s.lag_seconds, "events_total": s.events_total, "parse_errors": s.parse_errors,
               "last_error": s.last_error} for s in (stats or [])]
    return {
        "id": fw.id, "name": fw.name, "vendor": fw.vendor, "log_tz": fw.log_tz, "host": fw.host, "https_port": fw.https_port, "api_method": fw.api_method,
        "has_token": bool(fw.token_ciphertext), "vdom": fw.vdom, "site": fw.site, "tags": fw.tags or [],
        "poll_interval_seconds": fw.poll_interval_seconds, "enabled": fw.enabled, "is_demo": fw.is_demo,
        "serial": fw.serial, "hostname": fw.hostname, "model": fw.model,
        "fortios_version_declared": fw.fortios_version_declared, "fortios_version_detected": fw.fortios_version_detected,
        "version_support": support_level(fw.fortios_version_detected or fw.fortios_version_declared) if fw.vendor == "fortinet"
        else (fw.capabilities or {}).get("version_support"),
        "ca_bundle_path": fw.ca_bundle_path, "syslog_source_ips": fw.syslog_source_ips or [],
        "api_log_pull": fw.api_log_pull, "api_log_device": fw.api_log_device,
        "api_status": fw.api_status, "api_last_success": iso(fw.api_last_success),
        "api_last_error": fw.api_last_error, "api_last_error_at": iso(fw.api_last_error_at),
        "capabilities": fw.capabilities or {}, "health": fw.health or {}, "ingest": ingest,
    }


async def _stats(s: AsyncSession) -> dict[int, list[IngestStat]]:
    out: dict[int, list[IngestStat]] = {}
    for st in (await s.execute(select(IngestStat))).scalars():
        out.setdefault(st.firewall_id, []).append(st)
    return out


@router.get("")
async def list_firewalls(_: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    stats = await _stats(s)
    return [fw_out(f, stats.get(f.id)) for f in (await s.execute(select(Firewall).order_by(Firewall.name))).scalars()]


@router.get("/{fw_id}")
async def get_firewall(fw_id: int, _: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    fw = await s.get(Firewall, fw_id)
    if not fw:
        raise HTTPException(404, "not found")
    return fw_out(fw, (await _stats(s)).get(fw.id))


def _apply(fw: Firewall, body: BaseModel) -> dict:
    data = body.model_dump(exclude_unset=True)
    token = data.pop("api_token", None)
    if "fortios_version" in data:
        fw.fortios_version_declared = data.pop("fortios_version")
    for k, v in data.items():
        setattr(fw, k, v)
    if token:
        fw.token_ciphertext = TokenCipher().encrypt(token)
    return {k: v for k, v in data.items()} | ({"api_token": "rotated"} if token else {})


@router.post("", status_code=201)
async def create_firewall(body: FirewallIn, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    if (await s.execute(select(Firewall).where(Firewall.name == body.name))).scalar_one_or_none():
        raise HTTPException(409, "firewall name exists")
    fw = Firewall(tags=[], syslog_source_ips=[], capabilities={}, health={}, api_log_cursor={})
    changes = _apply(fw, body)
    if fw.vendor == "paloalto":
        fw.api_log_pull = False  # PAN-OS logs come from syslog
        if fw.vdom in ("", "root"):
            fw.vdom = "vsys1"
    s.add(fw)
    await s.commit()
    await audit(s, request, admin.username, "firewall_create", fw.name, changes)
    return fw_out(fw)


@router.put("/{fw_id}")
async def update_firewall(fw_id: int, body: FirewallPatch, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    fw = await s.get(Firewall, fw_id)
    if not fw:
        raise HTTPException(404, "not found")
    moved = (body.host is not None and body.host != fw.host) or ("https_port" in body.model_fields_set and body.https_port != fw.https_port)
    if moved and fw.token_ciphertext and not body.api_token:
        # the stored token is never shown to anyone; pointing it at a new address would hand it to that address
        raise HTTPException(422, "re-enter the API token when changing the firewall host or port")
    changes = _apply(fw, body)
    await s.commit()
    await audit(s, request, admin.username, "firewall_update", fw.name, changes)
    return fw_out(fw)


@router.delete("/{fw_id}")
async def delete_firewall(fw_id: int, request: Request, admin: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    fw = await s.get(Firewall, fw_id)
    if not fw:
        raise HTTPException(404, "not found")
    name = fw.name
    await s.delete(fw)
    await s.commit()
    await audit(s, request, admin.username, "firewall_delete", name, {"note": "stored events are retained"})
    return {"ok": True}


class TestIn(BaseModel):
    api_token: str | None = Field(None, min_length=10, max_length=512)


@router.post("/{fw_id}/test")
async def test_firewall(fw_id: int, request: Request, body: TestIn | None = None, admin: User = Depends(require_admin),
                        s: AsyncSession = Depends(get_session)):
    fw = await s.get(Firewall, fw_id)
    if not fw:
        raise HTTPException(404, "not found")
    if fw.vendor == "paloalto":
        from .. import paloalto as vendor_api
    else:
        from ..fortigate import service as vendor_api
    try:
        report = await vendor_api.run_connection_test(fw, body.api_token if body else None)
    except FortiGateError as e:
        report = {"ok": False, "auth": "unknown", "error": str(e), "endpoints": {}, "warnings": []}
    vendor_api.apply_test_report(fw, report)
    await s.commit()
    await audit(s, request, admin.username, "firewall_test", fw.name, {"ok": report.get("ok"), "auth": report.get("auth")},
                success=bool(report.get("ok")))
    return report


@router.get("/{fw_id}/metrics")
async def metrics(fw_id: int, hours: int = 24, _: User = Depends(current_user), ch: ClickHouse = Depends(ch_dep)):
    hours = max(1, min(hours, 24 * 30))
    rows = await ch.aquery(
        "SELECT ts, cpu, mem, sessions FROM device_metrics WHERE firewall_id = {id:UInt32} "
        "AND ts >= now() - toIntervalHour({h:UInt32}) ORDER BY ts", {"id": fw_id, "h": hours})
    return [{**r, "ts": str(r["ts"]).replace(" ", "T") + ("Z" if "Z" not in str(r["ts"]) else "")} for r in rows]
