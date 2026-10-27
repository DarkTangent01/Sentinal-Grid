"""Read-only Palo Alto Networks PAN-OS XML API client and the polling / connection-test glue.

Read-only by construction: `PanClient.op()` only sends operational commands that start with <show>, and
`PanClient.config_get()` only uses action=get. Nothing here can commit, set, edit or delete. The API key travels in
the X-PAN-KEY header (never the URL) and TLS is always verified against the configured CA bundle, exactly like the
FortiGate client. Create the key for an admin with a read-only role (Device > Admin Roles: XML API → Operational
Requests and Configuration read only; everything else disabled).

Errors reuse the FortiGate exception types so the rest of the SIEM (status, alerts, UI) treats both vendors alike.
"""
from __future__ import annotations

import re
import ssl
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import httpx

from .config import get_settings
from .fortigate.client import FortiGateAuthError, FortiGateError, FortiGateNotSupported, FortiGateUnreachable
from .netguard import DestinationError, request_guard
from .security import TokenCipher

SYSTEM_INFO = "<show><system><info></info></system></show>"
RESOURCES = "<show><system><resources></resources></system></show>"
SESSION_INFO = "<show><session><info></info></session></show>"
HA_STATE = "<show><high-availability><state></state></high-availability></show>"
INTERFACES = "<show><interface>all</interface></show>"


class PanClient:
    def __init__(self, host: str, port: int, key: str, ca_bundle: str | None, timeout: float = 15.0,
                 transport: httpx.AsyncBaseTransport | None = None):
        self.host = host
        verify = ssl.create_default_context(cafile=ca_bundle) if ca_bundle else True
        h = f"[{host}]" if ":" in host and not host.startswith("[") else host
        self._http = httpx.AsyncClient(
            base_url=f"https://{h}:{port}", headers={"X-PAN-KEY": key, "Accept": "application/xml"},
            timeout=httpx.Timeout(timeout, connect=min(timeout, 10.0)), verify=verify, transport=transport,
            follow_redirects=False, limits=httpx.Limits(max_connections=2, max_keepalive_connections=1),
            event_hooks={"request": [request_guard(("https",))]})

    async def close(self) -> None:
        await self._http.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.close()

    async def _call(self, params: dict) -> ET.Element:
        try:
            resp = await self._http.get("/api/", params=params)
        except DestinationError as e:
            raise FortiGateError(str(e)) from e
        except httpx.ConnectError as e:
            if "CERTIFICATE_VERIFY_FAILED" in str(e) or "certificate" in str(e).lower():
                raise FortiGateUnreachable(f"TLS certificate verification failed for {self.host}: install the firewall's CA "
                                           "or a certificate signed by a trusted CA") from e
            raise FortiGateUnreachable(f"{self.host}: {e}") from e
        except (httpx.TimeoutException, httpx.NetworkError) as e:
            raise FortiGateUnreachable(f"{self.host}: {type(e).__name__}") from e
        if resp.status_code in (401, 403):
            raise FortiGateAuthError(resp.status_code, "PAN-OS API key rejected or not allowed for this request")
        if resp.status_code != 200:
            raise FortiGateError(f"PAN-OS API HTTP {resp.status_code}")
        text = resp.text
        if "<!DOCTYPE" in text or "<!ENTITY" in text:  # never expand entities from a remote document
            raise FortiGateError("PAN-OS API returned a document type declaration; refused")
        try:
            root = ET.fromstring(text)
        except ET.ParseError as e:
            raise FortiGateError(f"PAN-OS API returned invalid XML: {e}") from e
        if root.get("status") != "success":
            code = root.get("code", "")
            msg = " ".join(t.strip() for t in root.itertext() if t.strip())[:300]
            if code in ("403", "16") or "invalid credential" in msg.lower() or "unauthorized" in msg.lower():
                raise FortiGateAuthError(403, f"PAN-OS API: {msg or 'unauthorized'}")
            if code in ("7", "12") or "not available" in msg.lower():
                raise FortiGateNotSupported(f"PAN-OS API: {msg}")
            raise FortiGateError(f"PAN-OS API error {code}: {msg}")
        return root

    async def op(self, cmd: str) -> ET.Element:
        if not cmd.startswith("<show>"):
            raise ValueError("only <show> operational commands are allowed (read-only)")
        return await self._call({"type": "op", "cmd": cmd})

    async def config_get(self, xpath: str) -> ET.Element:
        return await self._call({"type": "config", "action": "get", "xpath": xpath})


def _t(el: ET.Element | None, path: str) -> str:
    x = el.find(path) if el is not None else None
    return (x.text or "").strip() if x is not None and x.text else ""


def parse_uptime(v: str) -> int | None:
    m = re.match(r"(?:(\d+) days?, )?(\d+):(\d+):(\d+)", v or "")
    if not m:
        return None
    d, h, mi, s = (int(x or 0) for x in m.groups())
    return d * 86400 + h * 3600 + mi * 60 + s


def parse_resources(text: str) -> dict:
    """CPU and memory from the `top` snapshot that `show system resources` returns."""
    out: dict = {}
    m = re.search(r"Cpu\(s\):.*?([\d.]+)\s*id", text)
    if m:
        out["cpu"] = round(100 - float(m.group(1)), 1)
    m = re.search(r"(?:MiB|KiB)\s+Mem\s*:\s*([\d.]+)\s+total,\s*([\d.]+)\s+free,\s*([\d.]+)\s+used", text)
    if m:
        total, _free, used = (float(x) for x in m.groups())
        out["mem"] = round(100 * used / total, 1) if total else None
    return out


async def system_info(c: PanClient) -> dict:
    s = (await c.op(SYSTEM_INFO)).find("./result/system")
    return {"hostname": _t(s, "hostname"), "serial": _t(s, "serial"), "model": _t(s, "model"),
            "version": _t(s, "sw-version"), "uptime_s": parse_uptime(_t(s, "uptime")), "multi_vsys": _t(s, "multi-vsys"),
            "app_version": _t(s, "app-version"), "threat_version": _t(s, "threat-version")}


async def health(c: PanClient) -> dict:
    """Resources, sessions, HA and interfaces; each part is optional (recorded as unsupported, never invented)."""
    out: dict = {}
    try:
        res = parse_resources(" ".join((await c.op(RESOURCES)).itertext()))
        si = (await c.op(SESSION_INFO)).find("./result")
        res["sessions"] = int(_t(si, "num-active") or 0)
        res["cps"] = int(_t(si, "cps") or 0)
        res["throughput_kbps"] = int(_t(si, "kbps") or 0)
        out["resources"] = res
    except FortiGateNotSupported:
        out["resources"] = {"unsupported": "not_found"}
    except FortiGateAuthError:
        out["resources"] = {"unsupported": "forbidden"}
    try:
        ha = (await c.op(HA_STATE)).find("./result")
        out["ha"] = {"enabled": _t(ha, "enabled") == "yes", "local_state": _t(ha, "group/local-info/state"),
                     "peer_state": _t(ha, "group/peer-info/state"), "mode": _t(ha, "group/mode")}
    except (FortiGateNotSupported, FortiGateAuthError):
        out["ha"] = {"unsupported": True}
    try:
        r = await c.op(INTERFACES)
        out["interfaces"] = [{"name": _t(e, "name"), "link": _t(e, "state"), "speed": _t(e, "speed"), "duplex": _t(e, "duplex"),
                              "mac": _t(e, "mac")} for e in r.findall("./result/hw/entry")]
    except (FortiGateNotSupported, FortiGateAuthError):
        out["interfaces"] = {"unsupported": "forbidden"}
    return out


async def security_rules(c: PanClient, vsys: str) -> list[dict]:
    root = await c.config_get(f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{vsys}']/rulebase/security/rules")
    return [{"name": e.get("name"), "action": _t(e, "action"), "disabled": _t(e, "disabled") == "yes"}
            for e in root.findall(".//rules/entry")]


# ------------------------------------------------------------------ SIEM glue (same contract as fortigate.service)
def client_for(fw, key: str | None = None) -> PanClient:
    s = get_settings()
    if key is None:
        if not fw.token_ciphertext:
            raise FortiGateError("no API key configured")
        key = TokenCipher().decrypt(fw.token_ciphertext)
    return PanClient(fw.host, fw.https_port, key, fw.ca_bundle_path or s.fortigate_ca_bundle or None, s.fortigate_timeout_seconds)


def _vsys(fw) -> str:
    return fw.vdom if fw.vdom and fw.vdom != "root" else "vsys1"


async def run_connection_test(fw, key: str | None = None) -> dict:
    report: dict = {"ok": False, "auth": "unknown", "identity": None, "endpoints": {}, "warnings": []}
    async with client_for(fw, key) as c:
        try:
            ident = await system_info(c)
            report["identity"] = ident
            report["auth"] = "ok"
        except FortiGateAuthError as e:
            report.update(auth="failed", error=str(e))
            return report
        except FortiGateError as e:
            report.update(auth="unreachable", error=str(e))
            return report
        report["endpoints"]["system_status"] = "supported"
        for name, cmd in (("resource_usage", RESOURCES), ("sessions", SESSION_INFO), ("ha_state", HA_STATE), ("interfaces", INTERFACES)):
            try:
                await c.op(cmd)
                report["endpoints"][name] = "supported"
            except FortiGateAuthError:
                report["endpoints"][name] = "forbidden"
            except FortiGateNotSupported:
                report["endpoints"][name] = "not_found"
            except FortiGateError as e:
                report["endpoints"][name] = f"error: {e}"
        try:
            rules = await security_rules(c, _vsys(fw))
            report["endpoints"]["policies"] = "supported"
            report["warnings"].append(f"{len(rules)} security rules readable in {_vsys(fw)}.")
        except FortiGateAuthError:
            report["endpoints"]["policies"] = "forbidden"
        except FortiGateError as e:
            report["endpoints"]["policies"] = f"error: {e}"
    report["warnings"].append("Logs come from syslog (PAN-OS default CSV format); set the device log time zone so local times convert correctly.")
    report["version_support"] = "supported" if (ident.get("version") or "")[:2] in ("9.", "10", "11", "12") else "untested"
    report["ok"] = True
    return report


def apply_test_report(fw, report: dict) -> None:
    now = datetime.now(timezone.utc)
    if report.get("ok"):
        ident = report["identity"]
        fw.serial = ident.get("serial") or fw.serial
        fw.hostname = ident.get("hostname") or fw.hostname
        fw.model = ident.get("model") or fw.model
        fw.fortios_version_detected = ident.get("version")  # column holds the OS version for every vendor
        fw.capabilities = {"endpoints": report["endpoints"], "tested_at": now.isoformat(), "version_support": report.get("version_support")}
        fw.api_status, fw.api_last_success, fw.api_last_error = "ok", now, None
    else:
        fw.api_status = "auth_error" if report.get("auth") == "failed" else "unreachable"
        fw.api_last_error, fw.api_last_error_at = report.get("error"), now


async def poll_health(fw, ch=None) -> None:
    from .fortigate.service import record_error
    now = datetime.now(timezone.utc)
    try:
        async with client_for(fw) as c:
            ident = await system_info(c)
            h = await health(c)
            try:
                rules = await security_rules(c, _vsys(fw))
                h["policies"] = {r["name"]: r["name"] for r in rules if r.get("name")}
            except FortiGateError:
                pass
        fw.serial = ident.get("serial") or fw.serial
        fw.hostname = ident.get("hostname") or fw.hostname
        fw.model = ident.get("model") or fw.model
        fw.fortios_version_detected = ident.get("version") or fw.fortios_version_detected
        h.update({"polled_at": now.isoformat(), "uptime_s": ident.get("uptime_s"),
                  "content": {"app": ident.get("app_version"), "threat": ident.get("threat_version")}})
        fw.health = h
        fw.api_status, fw.api_last_success = "ok", now
        res = h.get("resources") or {}
        if ch is not None and "unsupported" not in res:
            await ch.ainsert("device_metrics", [{"ts": now.replace(microsecond=0), "firewall_id": fw.id, "cpu": res.get("cpu"),
                                                 "mem": res.get("mem"), "sessions": res.get("sessions"), "disk": None}],
                             ["ts", "firewall_id", "cpu", "mem", "sessions", "disk"])
    except FortiGateError as e:
        record_error(fw, e)
