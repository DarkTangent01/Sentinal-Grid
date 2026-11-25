"""Read-only NETCONF (RFC 6241 over SSH, RFC 6242) and RESTCONF (RFC 8040) operations through the access gateway.

Only the operations in OPS run: fixed RPCs or GET paths, no edit-config, no commit, no arbitrary XML or URL from the API.
NETCONF connects to the device's management address on TCP 830 with the vault's netconf credential (else its ssh
credential) and the same pinned SSH host key as the terminal. RESTCONF connects to TCP 443 with the https credential;
the server certificate is pinned on first use (switches.https_cert_sha256) and checked, on an unauthenticated request,
before the credentials are sent.

Our NETCONF hello advertises base:1.0 only, so the session uses end-of-message framing (]]>]]>).
"""
from __future__ import annotations

import asyncio
import hashlib
import re
import time

from .gateway import AccessError, Target

EOM = "]]>]]>"
NS = "urn:ietf:params:xml:ns:netconf:base:1.0"
_XML_SECRET = re.compile(r"<((?:[\w-]+:)?[\w-]*(?:password|secret|community|pre-shared-key|psk|auth-key|key-string|passphrase)[\w-]*)(\s[^>]*)?>[^<]*</\1>", re.I)

NETCONF_OPS: dict[str, dict] = {
    "capabilities": {"title": "Capabilities (hello)", "rpc": None},
    "running_config": {"title": "Running configuration (masked)", "rpc": "<get-config><source><running/></source></get-config>"},
    "interfaces_state": {"title": "Interfaces (ietf-interfaces)", "rpc": '<get><filter type="subtree"><interfaces-state xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces"/></filter></get>'},
    "yang_library": {"title": "YANG modules (ietf-yang-library)", "rpc": '<get><filter type="subtree"><modules-state xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-library"/></filter></get>'},
    "junos_interfaces": {"title": "Junos: interfaces terse", "rpc": "<get-interface-information><terse/></get-interface-information>", "platform": "junos"},
    "junos_chassis": {"title": "Junos: chassis inventory", "rpc": "<get-chassis-inventory/>", "platform": "junos"},
    "junos_bgp": {"title": "Junos: BGP summary", "rpc": "<get-bgp-summary-information/>", "platform": "junos"},
}
RESTCONF_OPS: dict[str, dict] = {
    "yang_library": {"title": "YANG library", "path": "/restconf/data/ietf-yang-library:modules-state"},
    "interfaces": {"title": "Interfaces (ietf-interfaces)", "path": "/restconf/data/ietf-interfaces:interfaces"},
    "interfaces_state": {"title": "Interface state (ietf-interfaces, deprecated tree)", "path": "/restconf/data/ietf-interfaces:interfaces-state"},
    "iosxe_version": {"title": "IOS-XE: version", "path": "/restconf/data/Cisco-IOS-XE-native:native/version", "platform": "cisco_ios"},
    "iosxe_hostname": {"title": "IOS-XE: hostname", "path": "/restconf/data/Cisco-IOS-XE-native:native/hostname", "platform": "cisco_ios"},
    "openconfig_interfaces": {"title": "OpenConfig interfaces", "path": "/restconf/data/openconfig-interfaces:interfaces"},
}
# every RPC above is a read (get / get-config / get-*-information): checked at import, like the CLI templates
for _k, _o in NETCONF_OPS.items():
    if _o["rpc"] and not re.match(r"^<(get|get-config|get-[\w-]+-information|get-chassis-inventory)\b", _o["rpc"]):
        raise RuntimeError(f"NETCONF operation {_k} is not a read")


def mask_xml(text: str) -> str:
    return _XML_SECRET.sub(lambda m: f"<{m.group(1)}{m.group(2) or ''}>&lt;masked&gt;</{m.group(1)}>", text)


def hello() -> str:
    return (f'<?xml version="1.0" encoding="UTF-8"?><hello xmlns="{NS}"><capabilities>'
            f"<capability>urn:ietf:params:netconf:base:1.0</capability></capabilities></hello>{EOM}")


def rpc(msg_id: int, body: str) -> str:
    return f'<?xml version="1.0" encoding="UTF-8"?><rpc message-id="{msg_id}" xmlns="{NS}">{body}</rpc>{EOM}'


async def _read_msg(stdout, timeout: float, limit: int = 8 << 20) -> str:
    buf = ""
    deadline = time.monotonic() + timeout
    while EOM not in buf:
        left = deadline - time.monotonic()
        if left <= 0:
            raise AccessError(504, "NETCONF: no complete reply in time", "timeout")
        chunk = await asyncio.wait_for(stdout.read(65536), left)
        if not chunk:
            raise AccessError(502, "NETCONF: the device closed the session", "connect_failed")
        buf += chunk
        if len(buf) > limit:
            raise AccessError(502, "NETCONF: reply larger than 8 MB", "too_large")
    return buf.split(EOM, 1)[0]


def capabilities(server_hello: str) -> list[str]:
    return re.findall(r"<(?:\w+:)?capability>\s*([^<]+?)\s*</(?:\w+:)?capability>", server_hello)


async def netconf(conn, op: str, timeout: float = 60) -> dict:
    """Run one read operation on an open asyncssh connection to port 830."""
    o = NETCONF_OPS[op]
    t0 = time.perf_counter()
    try:
        proc = await conn.create_process(subsystem="netconf", encoding="utf-8")
    except Exception as e:
        raise AccessError(502, f"NETCONF subsystem refused: {type(e).__name__}", "unsupported")
    try:
        proc.stdin.write(hello())
        server = await _read_msg(proc.stdout, timeout)
        caps = capabilities(server)
        out = "\n".join(caps) if o["rpc"] is None else ""
        status = "ok"
        if o["rpc"] is not None:
            proc.stdin.write(rpc(101, o["rpc"]))
            reply = await _read_msg(proc.stdout, timeout)
            out = mask_xml(reply)
            status = "error" if "<rpc-error" in reply else "ok"
        proc.stdin.write(rpc(102, "<close-session/>"))
        return {"operation": op, "status": status, "output": out, "capabilities": len(caps), "ms": round((time.perf_counter() - t0) * 1000)}
    finally:
        proc.close()


def cert_fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


async def restconf(t: Target, cred_values: dict, username: str, op: str, *, pinned: str, timeout: float = 30, transport=None) -> tuple[dict, str]:
    """GET one fixed RESTCONF path. Returns (result, server certificate SHA-256). The certificate is checked on an
    unauthenticated request first; a different certificate than the pinned one refuses before credentials are sent."""
    import httpx
    o = RESTCONF_OPS[op]
    host = f"[{t.host}]" if ":" in t.host else t.host
    base = f"https://{host}:{t.port}"
    t0 = time.perf_counter()

    def peer_fp(resp) -> str:
        ns = resp.extensions.get("network_stream")
        sslobj = ns.get_extra_info("ssl_object") if ns is not None else None
        der = sslobj.getpeercert(binary_form=True) if sslobj is not None else None
        return cert_fingerprint(der) if der else ""
    async with httpx.AsyncClient(verify=False, timeout=timeout, transport=transport, follow_redirects=False,
                                 limits=httpx.Limits(max_connections=1, max_keepalive_connections=1)) as c:
        try:
            probe = await c.get(f"{base}/.well-known/host-meta", headers={"Accept": "application/xrd+xml"})
        except httpx.HTTPError as e:
            raise AccessError(502, f"RESTCONF connection failed: {type(e).__name__}", "connect_failed")
        fp = peer_fp(probe)
        if pinned and fp and fp != pinned:
            raise AccessError(409, "the device's HTTPS certificate changed since it was pinned; an administrator must accept the new one", "host_key_changed")
        try:
            r = await c.get(f"{base}{o['path']}", auth=(username, cred_values.get("password", "")), headers={"Accept": "application/yang-data+json"})
        except httpx.HTTPError as e:
            raise AccessError(502, f"RESTCONF request failed: {type(e).__name__}", "connect_failed")
        fp2 = peer_fp(r) or fp
        body = r.text[: 8 << 20]
        status = "ok" if r.status_code == 200 else ("unsupported" if r.status_code in (400, 404) else "auth_failed" if r.status_code in (401, 403) else "error")
        return ({"operation": op, "path": o["path"], "status": status, "http_status": r.status_code, "output": mask_xml(body) if "<" in body[:1] else _mask_json(body),
                 "ms": round((time.perf_counter() - t0) * 1000)}, fp2)


_JSON_SECRET = re.compile(r'("[\w:-]*(?:password|secret|community|pre-shared-key|psk|auth-key|key-string|passphrase)[\w-]*"\s*:\s*)"[^"]*"', re.I)


def _mask_json(text: str) -> str:
    return _JSON_SECRET.sub(r'\1"<masked>"', text)
