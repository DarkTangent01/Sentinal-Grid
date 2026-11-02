"""Device integration boundary for IaC.

FortiGateAdapter is the only code in the SIEM that can send a configuration change to a firewall. It is constructed
with `writes_allowed=False` everywhere except the deployment executor, which passes True only after the global switch
(IAC_DEVICE_WRITES + the IaC admin setting), plan approval and stale checks have passed. Writes are limited to the
cmdb paths in the resource registry, object keys are URL-encoded (no path injection), TLS verification and the SSRF
guard of the read client stay on, and nothing user-supplied is ever executed.

FortiManagerAdapter is an explicit boundary: devices managed by FortiManager are detected and their deployments are
blocked (a direct change would be overwritten by the next FortiManager install). Reading still uses the FortiGate API.
"""
from __future__ import annotations

import logging
from urllib.parse import quote

import httpx

from ..fortigate.client import FortiGateAuthError, FortiGateError, FortiGateNotSupported
from ..netguard import DestinationError
from .resources import REFERENCE_ONLY, SINGLETONS, TYPES, from_cmdb, redact, to_cmdb

log = logging.getLogger("iac.adapter")
MAX_BACKUP_BYTES = 30_000_000


class WriteBlocked(RuntimeError):
    pass


class DeviceAdapter:
    vendor = "generic"

    async def read_state(self, types: list[str]) -> dict:
        raise NotImplementedError

    async def capabilities(self) -> dict:
        raise NotImplementedError

    async def backup_full(self) -> tuple[str | None, str]:
        raise NotImplementedError

    async def apply(self, change: dict) -> dict:
        raise NotImplementedError

    async def health(self) -> dict:
        raise NotImplementedError

    async def close(self) -> None:
        pass


class FortiManagerAdapter(DeviceAdapter):
    """Not implemented: deployments to FortiManager-managed devices must go through FortiManager."""
    vendor = "fortimanager"

    async def apply(self, change: dict) -> dict:
        raise WriteBlocked("device is managed by FortiManager: deploy through FortiManager (adapter not implemented)")


class FortiGateAdapter(DeviceAdapter):
    vendor = "fortinet"

    def __init__(self, fw, *, writes_allowed: bool = False, transport: httpx.AsyncBaseTransport | None = None):
        from ..fortigate.client import FortiGateClient
        from ..fortigate.service import build_client
        self.fw = fw
        self.writes_allowed = writes_allowed
        base = build_client(fw)
        if transport is not None:  # tests: same configuration, mocked device
            cfg = base.cfg
            self._close_base = base
            self.client = FortiGateClient(cfg, transport=transport)
        else:
            self._close_base = None
            self.client = base
        # interactive IaC reads (plans, imports) must fail fast on an unreachable device instead of retrying for a minute
        self.client.cfg.max_retries = min(self.client.cfg.max_retries, 1)

    async def close(self) -> None:
        await self.client.close()
        if self._close_base is not None:
            await self._close_base.close()

    # ---------------- reads (GET only)
    async def read_state(self, types: list[str]) -> dict:
        state: dict[str, dict] = {t: {} for t in types}
        order: list[str] = []
        errors: dict[str, str] = {}
        for t in types:
            d = TYPES[t]
            try:
                res = (await self.client.get(d["path"])).get("results")
            except FortiGateNotSupported:
                errors[t] = "not supported on this device / version"
                continue
            except FortiGateAuthError as e:
                if e.status == 401:
                    raise
                errors[t] = "the API token's profile cannot read this table"
                continue
            if t in SINGLETONS:
                obj = res[0] if isinstance(res, list) and res else (res or {})
                _, c = from_cmdb(t, obj)
                state[t] = {"": c}
                continue
            for o in res or []:
                if not isinstance(o, dict):
                    continue
                k, c = from_cmdb(t, o)
                state[t][k] = c
                if t == "policy":
                    order.append(k)
        refs: dict[str, list[str]] = {}
        for name, path in REFERENCE_ONLY.items():
            try:
                res = (await self.client.get(path, {"format": "name"})).get("results") or []
                key = "schedule" if name.startswith("schedule") else name
                refs.setdefault(key, []).extend(str(o.get("name")) for o in res if isinstance(o, dict) and o.get("name"))
            except FortiGateError:
                continue
        return {"state": state, "order": order, "refs": refs, "errors": errors}

    async def capabilities(self) -> dict:
        caps = {"vendor": "fortinet", "integration": "fortigate_api", "fortimanager": False, "readable": [], "unreadable": {},
                "writable": False, "reason": ""}
        try:
            cm = (await self.client.get("/api/v2/cmdb/system/central-management")).get("results") or {}
            cm = cm[0] if isinstance(cm, list) and cm else cm
            caps["fortimanager"] = cm.get("type") == "fortimanager" and bool(cm.get("fmg"))
        except FortiGateError:
            caps["unreadable"]["central-management"] = "unknown (cannot read system central-management)"
        st = await self.read_state(list(TYPES))
        caps["readable"] = [t for t in TYPES if t not in st["errors"]]
        caps["unreadable"].update(st["errors"])
        if caps["fortimanager"]:
            caps["integration"] = "fortimanager"
            caps["reason"] = "managed by FortiManager: direct deployment is blocked"
        else:
            caps["writable"] = True
            caps["reason"] = "writes still require IAC_DEVICE_WRITES, the IaC setting and an approved plan"
        return caps

    async def backup_full(self) -> tuple[str | None, str]:
        """Full configuration file via the monitor backup endpoint (read-only). Not every version/profile allows it."""
        try:
            params = {"scope": "global"}
            if self.client.cfg.vdom:
                params["vdom"] = self.client.cfg.vdom
            resp = await self.client._http.get("/api/v2/monitor/system/config/backup", params=params)
        except (httpx.HTTPError, DestinationError) as e:
            return None, f"full backup unavailable: {type(e).__name__}"
        if resp.status_code != 200:
            return None, f"full backup unavailable: HTTP {resp.status_code} (needs a profile with read access to system configuration)"
        if len(resp.content) > MAX_BACKUP_BYTES:
            return None, "full backup larger than the 30 MB limit"
        text = resp.text
        if "config system global" not in text and "#config-version" not in text:
            return None, "full backup response did not look like a FortiOS configuration"
        return text, "full configuration captured"

    async def health(self) -> dict:
        try:
            st = await self.client.system_status()
            usage = await self.client.resource_usage()
            return {"reachable": True, "version": st.get("version"), "serial": st.get("serial"), "cpu": usage.get("cpu"), "mem": usage.get("mem"),
                    "ok": (usage.get("cpu") or 0) < 95 and (usage.get("mem") or 0) < 95}
        except FortiGateError as e:
            return {"reachable": False, "ok": False, "error": redact(str(e))[:300]}

    # ---------------- writes (deployment executor only)
    def _request_for(self, change: dict) -> tuple[str, str, dict | None, dict]:
        t, key, action = change["type"], change["key"], change["action"]
        if t not in TYPES:
            raise WriteBlocked(f"resource type {t} is not deployable")
        path = TYPES[t]["path"]
        params: dict = {}
        if self.client.cfg.vdom:
            params["vdom"] = self.client.cfg.vdom
        mkey = quote(str(key), safe="")
        if t in SINGLETONS:
            if action != "update":
                raise WriteBlocked(f"{t} supports update only")
            return "PUT", path, to_cmdb(t, key, change["desired"]), params
        if action == "create":
            return "POST", path, to_cmdb(t, key, change["desired"]), params
        if action == "update":
            return "PUT", f"{path}/{mkey}", to_cmdb(t, key, change["desired"]), params
        if action == "delete":
            return "DELETE", f"{path}/{mkey}", None, params
        if action == "move" and t == "policy":
            d = change["desired"]
            if d.get("after"):
                params.update({"action": "move", "after": str(int(d["after"]))})
            elif d.get("before"):
                params.update({"action": "move", "before": str(int(d["before"]))})
            else:
                raise WriteBlocked("move without a reference policy")
            return "PUT", f"{path}/{mkey}", None, params
        raise WriteBlocked(f"action {action} is not supported for {t}")

    def describe(self, change: dict) -> dict:
        """The exact request a change would send (dry runs and logs; bodies redacted)."""
        method, path, body, params = self._request_for(change)
        return {"method": method, "path": path, "params": params, "body": redact(body)}

    async def apply(self, change: dict) -> dict:
        method, path, body, params = self._request_for(change)
        if not self.writes_allowed:
            raise WriteBlocked("device writes are not enabled for this operation")
        try:
            resp = await self.client._http.request(method, path, params=params, json=body)
        except DestinationError as e:
            raise FortiGateError(str(e)) from e
        except httpx.HTTPError as e:
            raise FortiGateError(f"{method} {path}: {type(e).__name__}") from e
        try:
            data = resp.json()
        except ValueError:
            data = {}
        ok = resp.status_code == 200 and (not isinstance(data, dict) or data.get("status", "success") == "success")
        result = {"method": method, "path": path, "params": params, "http_status": resp.status_code, "ok": ok,
                  "device_error": redact(str((data or {}).get("cli_error") or (data or {}).get("error") or ""))[:500] if not ok else ""}
        if resp.status_code == 401:
            raise FortiGateAuthError(401, "authentication failed during deployment")
        return result


def make_adapter(fw, *, integration: str = "fortigate_api", writes_allowed: bool = False) -> DeviceAdapter:
    """Factory (tests replace it to inject a mocked FortiGate)."""
    if getattr(fw, "vendor", "fortinet") != "fortinet":
        raise FortiGateNotSupported("IaC currently supports FortiGate only")
    return FortiGateAdapter(fw, writes_allowed=writes_allowed and integration == "fortigate_api")
