"""Async FortiGate REST API client (read-only).

Only HTTP GET is implemented: the SIEM never changes firewall configuration.
Authentication uses an API token sent in the `Authorization: Bearer` header (never in the URL, so it
cannot leak into proxy or access logs).

Endpoint paths follow the FortiOS 7.x REST API (monitor, cmdb and log namespaces). Availability varies by
FortiOS version, VDOM, logging device and the API administrator's access profile, so every endpoint is
probed by `test_connection()` and recorded as supported / forbidden / not_found rather than assumed.
"""
import asyncio
import logging
import random
import ssl
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from ..netguard import DestinationError, request_guard

log = logging.getLogger("fortigate")


class FortiGateError(Exception):
    pass


class FortiGateAuthError(FortiGateError):
    """401: bad/expired token, or source IP not in trusted hosts. 403: insufficient access profile."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class FortiGateNotSupported(FortiGateError):
    """404 / 405 / 424: endpoint not available on this FortiOS version, VDOM or log device."""


class FortiGateUnreachable(FortiGateError):
    pass


class TokenBucket:
    def __init__(self, rate: float, burst: int | None = None):
        self.rate = max(rate, 0.1)
        self.capacity = burst or max(1, int(rate))
        self.tokens = float(self.capacity)
        self.updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
                self.updated = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                await asyncio.sleep((1 - self.tokens) / self.rate)


@dataclass
class ClientConfig:
    host: str
    token: str
    port: int = 443
    vdom: str | None = "root"
    verify_tls: bool = True
    ca_bundle: str | None = None
    timeout: float = 15.0
    max_retries: int = 4
    rps: float = 5.0
    backoff_base: float = 0.5
    backoff_max: float = 20.0
    extra_headers: dict = field(default_factory=dict)


RETRY_STATUS = {429, 500, 502, 503, 504}


class FortiGateClient:
    def __init__(self, cfg: ClientConfig, transport: httpx.AsyncBaseTransport | None = None):
        self.cfg = cfg
        if cfg.verify_tls:
            verify: Any = ssl.create_default_context(cafile=cfg.ca_bundle) if cfg.ca_bundle else True
        else:
            verify = False  # only reachable via an explicit, audited per-device admin override
        host = f"[{cfg.host}]" if ":" in cfg.host and not cfg.host.startswith("[") else cfg.host
        self._http = httpx.AsyncClient(
            base_url=f"https://{host}:{cfg.port}",
            headers={"Authorization": f"Bearer {cfg.token}", "Accept": "application/json", **cfg.extra_headers},
            timeout=httpx.Timeout(cfg.timeout, connect=min(cfg.timeout, 10.0)),
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
            verify=verify,
            transport=transport,
            follow_redirects=False,
            event_hooks={"request": [request_guard(("https",))]},
        )
        self._bucket = TokenBucket(cfg.rps)
        self.request_count = 0

    async def close(self) -> None:
        await self._http.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.close()

    async def get(self, path: str, params: dict | None = None, *, vdom: bool = True) -> dict:
        params = dict(params or {})
        if vdom and self.cfg.vdom:
            params.setdefault("vdom", self.cfg.vdom)
        attempt = 0
        while True:
            await self._bucket.acquire()
            self.request_count += 1
            try:
                resp = await self._http.get(path, params=params)
            except DestinationError as e:
                raise FortiGateError(str(e)) from e
            except httpx.ConnectError as e:
                if "CERTIFICATE_VERIFY_FAILED" in str(e) or "certificate" in str(e).lower():
                    raise FortiGateUnreachable(f"TLS certificate verification failed for {self.cfg.host}: "
                                               "install the FortiGate CA or a trusted certificate") from e
                err: Exception = e
            except (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError) as e:
                err = e
            else:
                if resp.status_code == 200:
                    try:
                        body = resp.json()
                    except ValueError as e:
                        raise FortiGateError(f"{path}: non-JSON response") from e
                    if isinstance(body, dict) and body.get("status") == "error":
                        code = body.get("http_status") or body.get("error")
                        if code in (403, -37):
                            raise FortiGateAuthError(403, f"{path}: permission denied by access profile")
                        if code in (404, -3, 424):
                            raise FortiGateNotSupported(f"{path}: not supported ({code})")
                        raise FortiGateError(f"{path}: API error {code}")
                    return body
                if resp.status_code == 401:
                    raise FortiGateAuthError(401, "authentication failed: token invalid/expired or source IP not a trusted host")
                if resp.status_code == 403:
                    raise FortiGateAuthError(403, f"{path}: permission denied by access profile")
                if resp.status_code in (404, 405, 424):
                    raise FortiGateNotSupported(f"{path}: HTTP {resp.status_code}")
                if resp.status_code not in RETRY_STATUS:
                    raise FortiGateError(f"{path}: HTTP {resp.status_code}")
                err = FortiGateError(f"{path}: HTTP {resp.status_code}")
                retry_after = resp.headers.get("Retry-After")
                if retry_after and retry_after.isdigit() and attempt < self.cfg.max_retries:
                    attempt += 1
                    await asyncio.sleep(min(float(retry_after), self.cfg.backoff_max))
                    continue
            if attempt >= self.cfg.max_retries:
                if isinstance(err, FortiGateError):
                    raise err
                raise FortiGateUnreachable(f"{self.cfg.host}: {type(err).__name__}: {err}") from err
            delay = min(self.cfg.backoff_max, self.cfg.backoff_base * (2 ** attempt)) * (0.5 + random.random() / 2)
            attempt += 1
            log.warning("fortigate %s %s failed (%s), retry %d in %.1fs", self.cfg.host, path, err, attempt, delay)
            await asyncio.sleep(delay)

    # ----- monitor / cmdb ------------------------------------------------
    async def system_status(self) -> dict:
        body = await self.get("/api/v2/monitor/system/status")
        res = body.get("results") or {}
        return {
            "serial": body.get("serial") or res.get("serial"),
            "version": body.get("version") or res.get("version"),
            "build": body.get("build") or res.get("build"),
            "hostname": res.get("hostname"),
            "model": res.get("model_name") or res.get("model"),
            "model_number": res.get("model_number"),
            "vdom": body.get("vdom"),
        }

    async def resource_usage(self) -> dict:
        body = await self.get("/api/v2/monitor/system/resource/usage", {"interval": "1-min"})
        res = body.get("results") or {}

        def current(key):
            v = res.get(key)
            if isinstance(v, list) and v:
                v = v[0]
            return v.get("current") if isinstance(v, dict) else None

        return {"cpu": current("cpu"), "mem": current("mem"), "sessions": current("session"), "disk": current("disk")}

    async def interfaces(self) -> list[dict]:
        body = await self.get("/api/v2/monitor/system/interface")
        res = body.get("results") or {}
        items = res.values() if isinstance(res, dict) else res
        out = []
        for it in items:
            if not isinstance(it, dict):
                continue
            out.append({k: it.get(k) for k in ("name", "alias", "link", "speed", "duplex", "ip", "mask",
                                               "tx_bytes", "rx_bytes", "tx_errors", "rx_errors")})
        return out

    async def policies(self) -> list[dict]:
        body = await self.get("/api/v2/cmdb/firewall/policy", {"format": "policyid|name|action|status"})
        return [p for p in body.get("results") or [] if isinstance(p, dict)]

    # ----- log API (best effort; not a continuous stream) ----------------
    async def log_page(self, device: str, log_type: str, subtype: str | None, start: int, rows: int,
                       session_id: int | None = None) -> dict:
        path = f"/api/v2/log/{device}/{log_type}" + (f"/{subtype}" if subtype else "")
        params: dict[str, Any] = {"start": start, "rows": rows}
        if session_id is not None:
            params["session_id"] = session_id
        return await self.get(path, params)

    async def iter_logs(self, device: str, log_type: str, subtype: str | None, *, rows: int = 500,
                        max_pages: int = 20, not_ready_retries: int = 5):
        """Yields pages of log records (newest first). Handles FortiOS search sessions that report
        ready=false / completed<100 by re-polling with the returned session_id."""
        start, session_id = 0, None
        for _ in range(max_pages):
            body, tries = None, 0
            while True:
                body = await self.log_page(device, log_type, subtype, start, rows, session_id)
                session_id = body.get("session_id", session_id)
                ready = body.get("ready", True)
                if ready is not False or body.get("results"):
                    break
                tries += 1
                if tries > not_ready_retries:
                    return
                await asyncio.sleep(0.5 * tries)
            results = body.get("results") or []
            if not results:
                return
            yield results
            if len(results) < rows:
                return
            start += len(results)


PROBE_ENDPOINTS: list[tuple[str, str, dict]] = [
    ("system_status", "/api/v2/monitor/system/status", {}),
    ("resource_usage", "/api/v2/monitor/system/resource/usage", {"interval": "1-min"}),
    ("interfaces", "/api/v2/monitor/system/interface", {}),
    ("policies", "/api/v2/cmdb/firewall/policy", {"format": "policyid|name"}),
    ("sessions_current", "/api/v2/monitor/firewall/session", {"count": 1}),
]
LOG_PROBES: list[tuple[str, str, str | None]] = [
    ("log_traffic_forward", "traffic", "forward"),
    ("log_event_system", "event", "system"),
    ("log_event_vpn", "event", "vpn"),
    ("log_webfilter", "webfilter", None),
    ("log_dns", "dns", None),
    ("log_ips", "ips", None),
    ("log_virus", "virus", None),
    ("log_app_ctrl", "app-ctrl", None),
]


async def test_connection(client: FortiGateClient, log_device: str = "disk") -> dict:
    """Checks authentication, identity, version, endpoint availability and permissions."""
    report: dict[str, Any] = {"ok": False, "auth": "unknown", "identity": None, "endpoints": {}, "warnings": []}
    try:
        report["identity"] = await client.system_status()
        report["auth"] = "ok"
    except FortiGateAuthError as e:
        report["auth"] = "failed"
        report["error"] = str(e)
        return report
    except FortiGateError as e:
        report["auth"] = "unreachable"
        report["error"] = str(e)
        return report

    async def probe(name, path, params):
        try:
            await client.get(path, params)
            report["endpoints"][name] = "supported"
        except FortiGateAuthError as e:
            report["endpoints"][name] = "forbidden" if e.status == 403 else "auth_failed"
        except FortiGateNotSupported:
            report["endpoints"][name] = "not_found"
        except FortiGateError as e:
            report["endpoints"][name] = f"error: {e}"

    for name, path, params in PROBE_ENDPOINTS[1:]:
        await probe(name, path, params)
    for name, t, st in LOG_PROBES:
        path = f"/api/v2/log/{log_device}/{t}" + (f"/{st}" if st else "")
        await probe(name, path, {"rows": 1, "start": 0})
    report["endpoints"]["system_status"] = "supported"

    if report["endpoints"].get("sessions_current") == "supported":
        report["warnings"].append("Current-session data is a point-in-time snapshot and is not used as historical traffic.")
    if not any(report["endpoints"].get(n) == "supported" for n, _, _ in LOG_PROBES):
        report["warnings"].append("No log API endpoints available; configure syslog forwarding for traffic/DNS/URL logs.")
    else:
        report["warnings"].append("The log API returns stored log pages, not a continuous stream; syslog is the recommended primary source.")
    report["ok"] = True
    return report
