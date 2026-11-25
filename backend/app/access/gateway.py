"""Device Access Gateway core: which device, which address, which port, which credential, how many sessions.

Callers pass a device id. The host is the device's management address from the inventory, accepted only when
switches.poller.validate_address passes: an IP literal, no loopback / link-local / reserved address, inside an
authorised management network. The port comes from PORTS. There is no parameter for either, so the gateway cannot be
used to reach anything that is not a registered device's management service (no general proxy, no port scanning).
"""
from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db.models import NmsAccessSession, Switch, SwitchNetwork, User
from ..products import site_allowed
from . import vault
from .commands import PLATFORMS, platform_of

PORTS = {"ssh": 22, "https": 443, "netconf": 830, "telnet": 23}
ACTIVE_STATES = ("pending", "active")


class AccessError(Exception):
    def __init__(self, status: int, message: str, kind: str = "refused"):
        super().__init__(message)
        self.status, self.message, self.kind = status, message, kind


@dataclass
class Target:
    switch: Switch
    host: str
    port: int
    protocol: str
    platform: str | None


async def resolve(s: AsyncSession, user: User, switch_id: int, protocol: str = "ssh") -> Target:
    if protocol not in PORTS:
        raise AccessError(422, f"unsupported protocol '{protocol}'")
    sw = await s.get(Switch, switch_id)
    if sw is None:
        raise AccessError(404, "device not found")
    if not site_allowed(user, sw.site):
        raise AccessError(403, "this device is outside your site scope")
    from ..switches.poller import validate_address
    nets = (await s.execute(select(SwitchNetwork))).scalars().all()
    try:
        host = validate_address(sw.address, nets)
    except ValueError as e:
        raise AccessError(403, str(e))
    return Target(sw, host, PORTS[protocol], protocol, platform_of(sw))


async def expire_pending(s: AsyncSession) -> int:
    """Sessions whose one-time ticket was never used expire with it (they must not hold a session slot)."""
    from datetime import datetime, timezone
    from sqlalchemy import update
    now = datetime.now(timezone.utc)
    r = await s.execute(update(NmsAccessSession).where(NmsAccessSession.state == "pending", NmsAccessSession.ticket_expires_at < now)
                        .values(state="expired", ended_at=now, ticket_hash="", result="refused", termination_reason="ticket not used"))
    await s.commit()
    return r.rowcount or 0


async def check_limits(s: AsyncSession, user: User, switch_id: int) -> None:
    await expire_pending(s)
    st = get_settings()
    q = select(func.count()).select_from(NmsAccessSession).where(NmsAccessSession.state.in_(ACTIVE_STATES))
    total = (await s.execute(q)).scalar() or 0
    mine = (await s.execute(q.where(NmsAccessSession.user_id == user.id))).scalar() or 0
    dev = (await s.execute(q.where(NmsAccessSession.switch_id == switch_id))).scalar() or 0
    if total >= st.access_max_sessions:
        raise AccessError(429, f"the gateway already has {total} open sessions (limit {st.access_max_sessions})")
    if mine >= st.access_max_sessions_per_user:
        raise AccessError(429, f"you already have {mine} open sessions (limit {st.access_max_sessions_per_user})")
    if dev >= st.access_max_sessions_per_device:
        raise AccessError(429, f"this device already has {dev} open sessions (limit {st.access_max_sessions_per_device})")


async def tcp_probe(host: str, port: int, timeout: float = 3.0) -> dict:
    t0 = time.perf_counter()
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        return {"ok": True, "latency_ms": round((time.perf_counter() - t0) * 1000, 1), "error": ""}
    except asyncio.TimeoutError:
        return {"ok": False, "latency_ms": None, "error": f"no answer on TCP {port} within {timeout:g} s"}
    except OSError as e:
        return {"ok": False, "latency_ms": None, "error": f"TCP {port}: {e.strerror or type(e).__name__}"}


async def _dial(host: str, port: int, host_key: str, **kw):
    """The only place that opens an SSH connection to a device (tests replace it to reach a local server)."""
    import asyncssh
    known = asyncssh.import_known_hosts(f"{host} {host_key}\n") if host_key else None   # validated before authentication
    return await asyncssh.connect(host, port=port, known_hosts=known, **kw)


async def connect(t: Target, cred, timeout: float | None = None):
    """SSH connection to the target with the stored host key pinned (trust on first use).
    Returns (connection, server host key in OpenSSH format, latency ms). The password is sent only after the host key
    check passes."""
    import asyncssh
    st = get_settings()
    timeout = timeout or float(st.access_connect_timeout_seconds)
    if cred is None:
        raise AccessError(409, "no SSH credential is assigned to this device (Credential Vault)", "config")
    secret = vault.unseal(cred)
    host_key = t.switch.ssh_host_key or ""
    kw: dict = {"username": cred.username, "connect_timeout": timeout, "login_timeout": timeout, "agent_path": None,
                "client_keys": [asyncssh.import_private_key(secret["private_key"])] if secret.get("private_key") else None,
                "password": secret.get("password") or None, "preferred_auth": "publickey,keyboard-interactive,password",
                "keepalive_interval": 30}
    t0 = time.perf_counter()
    try:
        conn = await _dial(t.host, t.port, host_key, **kw)
    except asyncssh.HostKeyNotVerifiable as e:
        raise AccessError(409, f"the device's SSH host key changed ({e.reason}); an administrator must accept the new key "
                               "(Config Changes → device) before anyone can connect", "host_key_changed")
    except asyncssh.PermissionDenied:
        raise AccessError(502, "the device rejected the SSH login (check the credential)", "auth_failed")
    except (OSError, asyncio.TimeoutError, asyncssh.Error) as e:
        raise AccessError(502, f"SSH connection failed: {type(e).__name__}: {str(e)[:200]}", "connect_failed")
    key = conn.get_server_host_key()
    server_key = key.export_public_key("openssh").decode().strip() if key else ""
    return conn, server_key, round((time.perf_counter() - t0) * 1000, 1)


# ------------------------------------------------------------------ running commands
PROMPT = re.compile(r"(?:^|\n)[^\n]{0,80}?[\w\-.()@/:~\]\[]+\s?[#>$%]\s?$")
ERRORS = re.compile(r"^\s*(%\s*(Invalid|Incomplete|Ambiguous|Unknown|Unrecognized|Error)|syntax error|unknown command|error:|"
                    r"Command fail|command parse error|Unknown action|Invalid input)", re.I | re.M)


class Shell:
    """An interactive shell on the device for CLIs without exec channels: send one line, read until the prompt."""

    def __init__(self, proc, timeout: float):
        self.proc, self.timeout, self.transcript = proc, timeout, []

    @classmethod
    async def open(cls, conn, timeout: float):
        proc = await conn.create_process(term_type="vt100", term_size=(200, 50))
        sh = cls(proc, timeout)
        await sh.read_prompt()
        return sh

    async def read_prompt(self, timeout: float | None = None) -> str:
        buf, deadline = "", time.monotonic() + (timeout or self.timeout)
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise AccessError(504, "the device did not return a prompt in time", "timeout")
            try:
                chunk = await asyncio.wait_for(self.proc.stdout.read(65536), min(left, 0.5 if buf else left))
            except asyncio.TimeoutError:
                if buf and PROMPT.search(buf.replace("\r", "")):
                    break
                continue
            if not chunk:
                break
            buf += chunk
            if PROMPT.search(buf.replace("\r", "")):
                # a prompt-shaped line can be part of the output: wait briefly for more before accepting it
                try:
                    more = await asyncio.wait_for(self.proc.stdout.read(65536), 0.3)
                    if more:
                        buf += more
                        continue
                except asyncio.TimeoutError:
                    pass
                break
        self.transcript.append(buf)
        return buf

    async def send(self, line: str) -> str:
        self.proc.stdin.write(line + "\n")
        out = await self.read_prompt()
        return strip_echo(out, line)

    def close(self):
        try:
            self.proc.stdin.write("exit\n")
            self.proc.close()
        except Exception:
            pass


def strip_echo(out: str, line: str) -> str:
    lines = out.replace("\r", "").split("\n")
    if lines and lines[0].strip().endswith(line.strip()):
        lines = lines[1:]
    if lines and PROMPT.search("\n" + lines[-1]):
        lines = lines[:-1]
    return "\n".join(lines)


async def run_read_only(conn, platform: str, commands: list[str], timeout: float) -> list[dict]:
    """Run already-validated read-only commands. Returns [{command, output, status, ms}] (status ok | unsupported |
    timeout | error); one failing command does not stop the others."""
    mode = PLATFORMS[platform]["mode"]
    pager = PLATFORMS[platform]["pager"]
    out: list[dict] = []
    if mode == "exec":
        for c in commands:
            t0 = time.perf_counter()
            try:
                r = await asyncio.wait_for(conn.run(c, check=False), timeout)
                text = str(r.stdout or "") + (("\n" + str(r.stderr)) if r.stderr else "")
                status = "unsupported" if ERRORS.search(text) else ("ok" if r.exit_status in (0, None) else "error")
            except asyncio.TimeoutError:
                text, status = f"no output within {timeout:g} s", "timeout"
            out.append({"command": c, "output": text, "status": status, "ms": round((time.perf_counter() - t0) * 1000)})
        return out
    sh = await Shell.open(conn, timeout)
    try:
        if pager:
            await sh.send(pager)
        for c in commands:
            t0 = time.perf_counter()
            try:
                text = await sh.send(c)
                status = "unsupported" if ERRORS.search(text) else "ok"
            except AccessError as e:
                text, status = e.message, "timeout"
            out.append({"command": c, "output": text, "status": status, "ms": round((time.perf_counter() - t0) * 1000)})
    finally:
        sh.close()
    return out
