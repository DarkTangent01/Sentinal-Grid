"""Interactive channels for the browser terminal: SSH (default), Telnet (legacy, opt-in) and serial console through a
console server (Opengear or Cisco terminal server). All three present the same interface to terminal.py, so the
line guard, recording, timeouts and audit are identical whatever the transport.

Console connection forms:
  Opengear, ssh     ssh <user>:port<NN>@<console server>          (port NN of the console server, two digits)
  Cisco, ssh        ssh -l <user>:<line> <terminal server>         (reverse SSH to async line <line>)
  either, telnet    telnet <console server> 2000+<port / line>     (clear text; needs ACCESS_TELNET_ENABLED)
The console server's address must pass the same management-network allowlist as any device, and its SSH host key is
pinned on first use like a device's.
"""
from __future__ import annotations

import asyncio
import time

from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db.models import ConsolePort, ConsoleServer, NmsAccessSession, SwitchNetwork, User
from . import vault
from .gateway import AccessError, _dial, connect, resolve
from .telnet import TelnetChannel, TelnetError


class SshChannel:
    def __init__(self, conn, proc):
        self.conn, self.proc = conn, proc

    async def read(self) -> str:
        return await self.proc.stdout.read(32768)

    def write(self, text: str) -> None:
        self.proc.stdin.write(text)

    def resize(self, cols: int, rows: int) -> None:
        self.proc.change_terminal_size(cols, rows)

    def close(self) -> None:
        try:
            self.proc.close()
        except Exception:
            pass
        self.conn.close()


async def _pty(conn, cols: int, rows: int) -> SshChannel:
    try:
        proc = await conn.create_process(term_type="xterm-256color", term_size=(cols, rows), encoding="utf-8", errors="replace")
    except Exception as e:
        conn.close()
        raise AccessError(502, f"the device refused an interactive shell ({type(e).__name__})", "shell_refused")
    return SshChannel(conn, proc)


def console_login(kind: str, method: str, username: str, port: int) -> tuple[str, int]:
    """(SSH user name or "", TCP port) to reach serial port / line `port` of a console server."""
    if method == "telnet":
        return "", 2000 + port
    if kind == "opengear":
        return f"{username}:port{port:02d}", 22
    if kind == "cisco":
        return f"{username}:{port}", 22
    raise AccessError(422, f"unknown console server kind '{kind}'")


async def open_channel(s: AsyncSession, user: User, row: NmsAccessSession, cols: int, rows: int):
    """Returns (channel, latency ms, how the credential was chosen, banner text already read, detail for the audit)."""
    st = get_settings()
    proto = row.protocol or "ssh"
    if proto == "ssh":
        t = await resolve(s, user, row.switch_id, "ssh")
        cred, how = await vault.resolve(s, t.switch, "ssh")
        row.credential_id = cred.id if cred else None
        conn, server_key, latency = await connect(t, cred)
        if not t.switch.ssh_host_key and server_key:
            t.switch.ssh_host_key = server_key        # trust on first use, shared with configuration backup
        return await _pty(conn, cols, rows), latency, how, "", {"protocol": "ssh"}
    if proto == "telnet":
        if not st.access_telnet_enabled:
            raise AccessError(409, "Telnet is disabled on this installation (ACCESS_TELNET_ENABLED)", "disabled")
        t = await resolve(s, user, row.switch_id, "telnet")
        if not t.switch.access_telnet:
            raise AccessError(409, "Telnet is not enabled for this device", "disabled")
        cred, how = await vault.resolve(s, t.switch, "ssh")
        if cred is None:
            raise AccessError(409, "no credential is assigned to this device (Credential Vault)", "config")
        row.credential_id = cred.id
        t0 = time.perf_counter()
        try:
            ch = await TelnetChannel.open(t.host, t.port, float(st.access_connect_timeout_seconds), cols, rows)
            banner = await ch.login(cred.username, vault.unseal(cred).get("password", ""), float(st.access_connect_timeout_seconds))
        except TelnetError as e:
            raise AccessError(502, e.message, e.kind)
        return ch, round((time.perf_counter() - t0) * 1000, 1), how, banner, {"protocol": "telnet", "cleartext": True}
    if proto == "console":
        cp = await s.get(ConsolePort, row.console_port_id) if row.console_port_id else None
        srv = await s.get(ConsoleServer, cp.server_id) if cp else None
        if cp is None or srv is None or cp.switch_id != row.switch_id:
            raise AccessError(404, "console port not found for this device")
        await resolve(s, user, row.switch_id, "ssh")      # the user may access this device (inventory, site scope)
        from sqlalchemy import select
        from ..switches.poller import validate_address
        nets = (await s.execute(select(SwitchNetwork))).scalars().all()
        try:
            host = validate_address(srv.address, nets)
        except ValueError as e:
            raise AccessError(403, f"console server: {e}")
        cred = await s.get(vault.DeviceSshCredential, srv.credential_id) if srv.credential_id else None
        if cred is None:
            raise AccessError(409, "the console server has no credential (Device Access → Console servers)", "config")
        row.credential_id = cred.id
        secret = vault.unseal(cred)
        login, port = console_login(srv.kind, srv.method, cred.username, cp.port)
        detail = {"protocol": "console", "console_server": srv.name, "console_port": cp.port, "method": srv.method}
        timeout = float(st.access_connect_timeout_seconds)
        if srv.method == "telnet":
            if not st.access_telnet_enabled:
                raise AccessError(409, "Telnet is disabled on this installation (ACCESS_TELNET_ENABLED)", "disabled")
            t0 = time.perf_counter()
            try:
                ch = await TelnetChannel.open(host, port, timeout, cols, rows)
                banner = await ch.login(cred.username, secret.get("password", ""), timeout, wake=True)
            except TelnetError as e:
                raise AccessError(502, e.message, e.kind)
            return ch, round((time.perf_counter() - t0) * 1000, 1), "console server", banner, {**detail, "cleartext": True}
        import asyncssh
        kw = {"username": login, "connect_timeout": timeout, "login_timeout": timeout, "agent_path": None, "password": secret.get("password") or None,
              "client_keys": [asyncssh.import_private_key(secret["private_key"])] if secret.get("private_key") else None,
              "preferred_auth": "publickey,keyboard-interactive,password"}
        t0 = time.perf_counter()
        try:
            conn = await _dial(host, port, srv.ssh_host_key or "", **kw)
        except asyncssh.HostKeyNotVerifiable:
            raise AccessError(409, "the console server's SSH host key changed; an administrator must accept the new key", "host_key_changed")
        except asyncssh.PermissionDenied:
            raise AccessError(502, "the console server rejected the login (credential, or the port is in use / not permitted)", "auth_failed")
        except (OSError, asyncio.TimeoutError, asyncssh.Error) as e:
            raise AccessError(502, f"console server connection failed: {type(e).__name__}", "connect_failed")
        key = conn.get_server_host_key()
        if not srv.ssh_host_key and key:
            srv.ssh_host_key = key.export_public_key("openssh").decode().strip()
        ch = await _pty(conn, cols, rows)
        ch.write("\r")                                    # wake the console line
        return ch, round((time.perf_counter() - t0) * 1000, 1), "console server", "", detail
    raise AccessError(422, f"unknown protocol {proto}")
