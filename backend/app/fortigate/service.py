"""Device operations shared by the API (Test Connection) and the worker (polling, log pull)."""
import logging
from datetime import datetime, timezone

from ..config import get_settings
from ..db.ch import ClickHouse
from ..db.models import Firewall
from ..security import TokenCipher
from .client import (ClientConfig, FortiGateAuthError, FortiGateClient, FortiGateError, FortiGateNotSupported,
                     FortiGateUnreachable, test_connection)
from .versions import support_level

log = logging.getLogger("fortigate.service")

# (capability key, log type, subtype) used for optional API log pulls
LOG_STREAMS = [
    ("log_traffic_forward", "traffic", "forward"),
    ("log_event_system", "event", "system"),
    ("log_event_vpn", "event", "vpn"),
    ("log_webfilter", "webfilter", None),
    ("log_dns", "dns", None),
    ("log_ips", "ips", None),
    ("log_virus", "virus", None),
    ("log_app_ctrl", "app-ctrl", None),
]


def build_client(fw: Firewall, token: str | None = None) -> FortiGateClient:
    s = get_settings()
    if token is None:
        if not fw.token_ciphertext:
            raise FortiGateError("no API token configured")
        token = TokenCipher().decrypt(fw.token_ciphertext)
    return FortiGateClient(ClientConfig(
        host=fw.host, port=fw.https_port, token=token, vdom=fw.vdom or None, verify_tls=True,
        ca_bundle=fw.ca_bundle_path or s.fortigate_ca_bundle or None, timeout=s.fortigate_timeout_seconds,
        max_retries=s.fortigate_max_retries, rps=s.fortigate_requests_per_second,
    ))


def _now():
    return datetime.now(timezone.utc)


def record_error(fw: Firewall, e: Exception) -> None:
    if isinstance(e, FortiGateAuthError):
        fw.api_status = "auth_error"
    elif isinstance(e, FortiGateUnreachable):
        fw.api_status = "unreachable"
    else:
        fw.api_status = "error"
    fw.api_last_error = str(e)[:1000]
    fw.api_last_error_at = _now()


async def run_connection_test(fw: Firewall, token: str | None = None) -> dict:
    client = build_client(fw, token)
    client.cfg.max_retries = 1  # interactive: fail fast instead of the polling retry budget
    try:
        report = await test_connection(client, fw.api_log_device or "disk")
    finally:
        await client.close()
    ident = report.get("identity") or {}
    if report.get("ok"):
        report["version_support"] = support_level(ident.get("version"))
        if fw.fortios_version_declared and ident.get("version") and fw.fortios_version_declared.lstrip("v") not in ident["version"]:
            report["warnings"].append(f"Declared FortiOS {fw.fortios_version_declared} differs from detected {ident['version']}.")
    return report


def apply_test_report(fw: Firewall, report: dict) -> None:
    if report.get("ok"):
        ident = report["identity"]
        fw.serial = ident.get("serial") or fw.serial
        fw.hostname = ident.get("hostname") or fw.hostname
        fw.model = ident.get("model") or fw.model
        fw.fortios_version_detected = ident.get("version")
        fw.capabilities = {"endpoints": report["endpoints"], "tested_at": _now().isoformat(),
                           "version_support": report.get("version_support")}
        fw.api_status = "ok"
        fw.api_last_success = _now()
        fw.api_last_error = None
    else:
        fw.api_status = "auth_error" if report.get("auth") == "failed" else "unreachable"
        fw.api_last_error = report.get("error")
        fw.api_last_error_at = _now()


async def poll_health(fw: Firewall, ch: ClickHouse | None = None) -> None:
    """Polls supported monitor endpoints. Unsupported endpoints are recorded, never fabricated."""
    client = build_client(fw)
    caps = (fw.capabilities or {}).get("endpoints", {})
    health = dict(fw.health or {})
    try:
        status = await client.system_status()
        fw.fortios_version_detected = status.get("version") or fw.fortios_version_detected
        fw.serial = status.get("serial") or fw.serial
        fw.hostname = status.get("hostname") or fw.hostname
        for key, fn in (("resources", client.resource_usage), ("interfaces", client.interfaces)):
            cap = "resource_usage" if key == "resources" else "interfaces"
            if caps.get(cap) not in (None, "supported"):
                health[key] = {"unsupported": caps.get(cap)}
                continue
            try:
                health[key] = await fn()
            except FortiGateNotSupported:
                health[key] = {"unsupported": "not_found"}
            except FortiGateAuthError as e:
                if e.status == 401:
                    raise
                health[key] = {"unsupported": "forbidden"}
        if caps.get("policies") == "supported":
            try:
                pols = await client.policies()
                health["policies"] = {str(p.get("policyid")): p.get("name", "") for p in pols if p.get("policyid") is not None}
            except FortiGateError:
                pass
        health["polled_at"] = _now().isoformat()
        fw.health = health
        fw.api_status = "ok"
        fw.api_last_success = _now()
        res = health.get("resources") or {}
        if ch is not None and "unsupported" not in res:
            await ch.ainsert("device_metrics", [{"ts": _now().replace(microsecond=0), "firewall_id": fw.id, **{k: res.get(k) for k in ("cpu", "mem", "sessions", "disk")}}],
                             ["ts", "firewall_id", "cpu", "mem", "sessions", "disk"])
    except FortiGateError as e:
        record_error(fw, e)
        log.warning("poll failed for firewall %s: %s", fw.name, e)
    finally:
        await client.close()


async def pull_logs(fw: Firewall, sink, rows: int | None = None) -> int:
    """Best-effort API log retrieval. Reads newest-first pages until reaching the stored high-water mark.

    The FortiGate log API serves stored logs (memory/disk/FortiAnalyzer) in pages; it is not a stream and
    may miss logs that roll over between polls. Syslog remains the recommended primary source.
    """
    rows = rows or get_settings().fortigate_log_page_rows
    caps = (fw.capabilities or {}).get("endpoints", {})
    cursor = dict(fw.api_log_cursor or {})
    client = build_client(fw)
    total = 0
    fwd = {"id": fw.id, "name": fw.name, "site": fw.site}
    try:
        for cap, t, st in LOG_STREAMS:
            if caps.get(cap) != "supported":
                continue
            hwm = cursor.get(cap)
            newest = hwm
            stop = False
            async for page in client.iter_logs(fw.api_log_device or "disk", t, st, rows=rows):
                for rec in page:
                    if not isinstance(rec, dict):
                        continue
                    et = str(rec.get("eventtime") or "")
                    if hwm and et.isdigit() and int(et) < int(hwm):
                        stop = True
                        break
                    rec.setdefault("type", t if t not in ("webfilter", "dns", "ips", "virus", "app-ctrl") else "utm")
                    if t in ("webfilter", "dns", "ips", "virus", "app-ctrl"):
                        rec.setdefault("subtype", t)
                    if sink.add_fields(rec, source="api_log", raw=None, firewall=fwd):
                        total += 1
                    if et.isdigit() and (newest is None or int(et) > int(newest)):
                        newest = et
                if stop:
                    break
            if newest:
                cursor[cap] = newest
        fw.api_log_cursor = cursor
    except FortiGateError as e:
        record_error(fw, e)
        log.warning("log pull failed for firewall %s: %s", fw.name, e)
    finally:
        await client.close()
    return total
