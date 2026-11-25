"""Read-only configuration backup over SSH for switches and wireless controllers.

What this module will do on a device, and nothing else:
  * connect over SSH to the device's management address, only if it passes the same checks as SNMP polling
    (switches.poller.validate_address: an IP literal inside an authorised management network, not loopback / reserved);
  * run the fixed, read-only show commands of its vendor (COMMANDS). There is no path for any other command: no
    configuration mode, no write / copy / reload, no free text from the API or the UI;
  * check the server's host key: the first successful connection stores it (trust on first use); afterwards a different
    key stops the backup before any password is sent, and raises an alert.

The text is stored with secrets masked (passwords, secrets, keys, SNMP communities, PSKs) and volatile lines removed
(timestamps the device writes into the configuration), so the hash changes only when the configuration does. A new
snapshot row is written only when the hash changes, with a unified diff against the previous one.
"""
from __future__ import annotations

import asyncio
import difflib
import hashlib
import json
import logging
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db.models import DeviceConfigSnapshot, DeviceSshCredential, Switch, SwitchNetwork
from ..security import TokenCipher

log = logging.getLogger("configs")

# vendor → (mode, commands). "exec": one SSH exec channel per command (no pager on exec channels); "shell": an
# interactive shell fed the commands then "exit" (devices without exec support).
COMMANDS: dict[str, tuple[str, tuple[str, ...]]] = {
    "cisco": ("exec", ("show running-config",)),
    "juniper": ("exec", ("show configuration | display set | no-more",)),
    "ruckus": ("shell", ("skip-page-display", "show running-config")),
}
ALLOWED = {c for _, cmds in COMMANDS.values() for c in cmds}

_MASK = [
    # Cisco / Ruckus / generic: keep the keyword and the encryption type, mask the value
    (re.compile(r"^(\s*(?:enable\s+)?(?:secret|password)\s+(?:\d+\s+)?)\S.*$", re.I), r"\1<masked>"),
    (re.compile(r"^(\s*username\s+\S+.*?\s(?:secret|password)\s+(?:\d+\s+)?)\S.*$", re.I), r"\1<masked>"),
    (re.compile(r"^(\s*snmp-server\s+community\s+)\S+(.*)$", re.I), r"\1<masked>\2"),
    (re.compile(r"^(\s*snmp-server\s+user\s+\S+\s+\S+\s+.*?\b(?:auth|priv)\b\s+\S+\s+)\S+(.*)$", re.I), r"\1<masked>\2"),
    (re.compile(r"^(\s*(?:tacacs|radius)[\w-]*\s+.*?\bkey\s+(?:\d+\s+)?)\S+(.*)$", re.I), r"\1<masked>\2"),
    (re.compile(r"^(\s*key(?:-string)?\s+(?:\d+\s+)?)\S.*$", re.I), r"\1<masked>"),
    (re.compile(r"^(\s*(?:wpa-psk|psk|pre-shared-key|security\s+wpa\s+psk\s+set-key)\s+(?:\S+\s+){0,2})\S+\s*$", re.I), r"\1<masked>"),
    (re.compile(r"^(\s*crypto\s+isakmp\s+key\s+)\S+(.*)$", re.I), r"\1<masked>\2"),
    # Juniper "set ... encrypted-password "$6$..."", "set ... secret "..."", "authentication-key"
    (re.compile(r'^(set\s+.*?\b(?:encrypted-password|secret|authentication-key|pre-shared-key\s+ascii-text|community)\s+)"?[^"\s]+"?(.*)$', re.I),
     r"\1<masked>\2"),
]
_VOLATILE = [
    re.compile(r"^! (?:Last configuration change|NVRAM config last updated|No configuration change since).*$", re.I),
    re.compile(r"^Current configuration\s*:\s*\d+ bytes\s*$", re.I),
    re.compile(r"^Building configuration\.\.\.\s*$", re.I),
    re.compile(r"^\s*ntp clock-period\s+\d+\s*$", re.I),
    re.compile(r"^## Last commit: .*$", re.I),
    re.compile(r"^!Current configuration:\s*$", re.I),
]


class BackupError(Exception):
    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind, self.message = kind, message


def mask(text: str) -> str:
    out = []
    for line in text.splitlines():
        for rx, rep in _MASK:
            new = rx.sub(rep, line)
            if new != line:
                line = new
                break
        out.append(line)
    return "\n".join(out)


def normalise(text: str) -> str:
    lines = [ln.rstrip() for ln in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    lines = [ln for ln in lines if not any(rx.match(ln) for rx in _VOLATILE)]
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines)


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def diff(old: str, new: str, name: str = "config") -> tuple[str, int, int]:
    d = list(difflib.unified_diff(old.splitlines(), new.splitlines(), f"{name} (previous)", f"{name} (now)", lineterm="", n=3))
    added = sum(1 for x in d if x.startswith("+") and not x.startswith("+++"))
    removed = sum(1 for x in d if x.startswith("-") and not x.startswith("---"))
    return "\n".join(d), added, removed


def vendor_of(sw: Switch) -> str | None:
    v = (sw.vendor_override or sw.vendor or "").lower()
    return v if v in COMMANDS else None


def seal(password: str = "", private_key: str = "") -> str:
    data = {k: v for k, v in {"password": password, "private_key": private_key}.items() if v}
    return TokenCipher().encrypt(json.dumps(data)) if data else ""


def unseal(cred: DeviceSshCredential) -> dict:
    return json.loads(TokenCipher().decrypt(cred.secret_ciphertext)) if cred.secret_ciphertext else {}


async def fetch(host: str, port: int, username: str, secret: dict, host_key: str, vendor: str, timeout: float) -> tuple[str, str]:
    """Run the vendor's fixed commands; return (output, server host key in OpenSSH format)."""
    import asyncssh
    mode, cmds = COMMANDS[vendor]
    assert all(c in ALLOWED for c in cmds)
    kw: dict = {"username": username, "connect_timeout": timeout, "login_timeout": timeout, "agent_path": None,
                "client_keys": [asyncssh.import_private_key(secret["private_key"])] if secret.get("private_key") else None,
                "password": secret.get("password") or None, "preferred_auth": "publickey,keyboard-interactive,password"}
    # the device-access gateway's single dial function: the host key is validated by asyncssh before authentication,
    # so a changed key never receives the password
    from ..access.gateway import _dial
    try:
        async with await _dial(host, port, host_key, **kw) as conn:
            key = conn.get_server_host_key()
            server_key = key.export_public_key("openssh").decode().strip() if key else ""
            if mode == "exec":
                parts = []
                for c in cmds:
                    r = await asyncio.wait_for(conn.run(c, check=False), timeout)
                    if r.exit_status not in (0, None):
                        raise BackupError("command", f"'{c}' exited with status {r.exit_status}: {str(r.stderr or '')[:200]}")
                    parts.append(str(r.stdout or ""))
                return "\n".join(parts), server_key
            proc = await conn.create_process(term_type="vt100")
            for c in cmds:
                proc.stdin.write(c + "\n")
            proc.stdin.write("exit\n")
            out = await asyncio.wait_for(proc.stdout.read(), timeout)
            return str(out), server_key
    except asyncssh.HostKeyNotVerifiable as e:
        raise BackupError("host_key_changed", f"the device's SSH host key changed ({e.reason}); backups stop until an administrator "
                                              "accepts the new key")
    except asyncssh.PermissionDenied:
        raise BackupError("auth", "SSH login rejected (check the SSH credential)")
    except (OSError, asyncio.TimeoutError, asyncssh.Error) as e:
        raise BackupError("connect", f"SSH connection failed: {type(e).__name__}: {str(e)[:200]}")


def _shell_output(raw: str, cmds: tuple[str, ...]) -> str:
    """From an interactive session, keep what follows the last command's echo up to the next prompt."""
    lines = raw.replace("\r", "").split("\n")
    start = max((i for i, ln in enumerate(lines) if ln.rstrip().endswith(cmds[-1])), default=-1) + 1
    body = lines[start:]
    while body and re.match(r"^\S+[#>]\s*(exit)?\s*$", body[-1].strip() or "x#"):
        body.pop()
    return "\n".join(body)


async def backup_switch(s: AsyncSession, sw: Switch, *, trigger: str = "schedule", now: datetime | None = None, fetcher=fetch) -> dict:
    """Back up one device. Returns {"ok", "changed", "snapshot_id" | "error"}; the device row records the attempt."""
    now = now or datetime.now(timezone.utc)
    st = get_settings()
    vendor = vendor_of(sw)
    cred = await s.get(DeviceSshCredential, sw.ssh_credential_id) if sw.ssh_credential_id else None
    try:
        if cred is None:
            raise BackupError("config", "no SSH credential assigned")
        if vendor is None:
            raise BackupError("config", f"configuration backup is not supported for vendor '{sw.vendor}'")
        from ..switches.poller import validate_address
        nets = (await s.execute(select(SwitchNetwork))).scalars().all()
        try:
            host = validate_address(sw.address, nets)
        except ValueError as e:
            raise BackupError("config", str(e))
        raw, server_key = await fetcher(host, 22, cred.username, unseal(cred), sw.ssh_host_key or "", vendor, float(st.config_backup_timeout_seconds))
    except BackupError as e:
        sw.config_backup_error = f"{e.kind}: {e.message}"[:2000]
        await s.commit()
        return {"ok": False, "error": sw.config_backup_error, "kind": e.kind}
    if COMMANDS[vendor][0] == "shell":
        raw = _shell_output(raw, COMMANDS[vendor][1])
    text = mask(normalise(raw))
    if not text.strip():
        sw.config_backup_error = "empty: the device returned no configuration text"
        await s.commit()
        return {"ok": False, "error": sw.config_backup_error, "kind": "empty"}
    if not sw.ssh_host_key and server_key:
        sw.ssh_host_key = server_key                          # trust on first use
    h = digest(text)
    prev = (await s.execute(select(DeviceConfigSnapshot).where(DeviceConfigSnapshot.switch_id == sw.id)
                            .order_by(DeviceConfigSnapshot.taken_at.desc(), DeviceConfigSnapshot.id.desc()).limit(1))).scalar_one_or_none()
    sw.config_backup_at, sw.config_backup_error = now, ""
    if prev is not None and prev.config_hash == h:
        await s.commit()
        return {"ok": True, "changed": False, "snapshot_id": prev.id}
    d, added, removed = diff(prev.text, text, sw.name) if prev is not None else ("", 0, 0)
    snap = DeviceConfigSnapshot(switch_id=sw.id, taken_at=now, config_hash=h, size=len(text), text=text, added=added, removed=removed, diff=d,
                                trigger="first" if prev is None else trigger)
    s.add(snap)
    await s.commit()
    return {"ok": True, "changed": prev is not None, "snapshot_id": snap.id, "added": added, "removed": removed}


async def _trap_triggers(ch, since: datetime) -> dict[int, datetime]:
    """Devices that sent a configuration-change notification (ciscoConfigManEvent) since `since`."""
    try:
        rows = await ch.aquery("SELECT switch_id, max(ts) AS t FROM snmp_traps WHERE ts >= {t0:DateTime64(3)} AND trap_name = 'ciscoConfigManEvent' "
                               "GROUP BY switch_id", {"t0": since})
    except Exception:
        return {}
    out = {}
    for r in rows:
        t = r["t"] if isinstance(r["t"], datetime) else datetime.fromisoformat(str(r["t"]).replace(" ", "T"))
        out[int(r["switch_id"])] = t if t.tzinfo else t.replace(tzinfo=timezone.utc)
    return out


async def run_due(ch, s: AsyncSession, now: datetime | None = None, fetcher=fetch) -> dict:
    """Worker loop body: back up devices whose last backup is older than the interval, or that reported a configuration
    change (trap) after their last backup. At most config_backup_concurrency at a time."""
    now = now or datetime.now(timezone.utc)
    st = get_settings()
    sws = (await s.execute(select(Switch).where(Switch.ssh_credential_id.is_not(None), Switch.monitoring == "active"))).scalars().all()
    if not sws:
        return {"due": 0}
    traps = await _trap_triggers(ch, now - timedelta(days=1))
    due = []
    for sw in sws:
        last = sw.config_backup_at if sw.config_backup_at is None or sw.config_backup_at.tzinfo else sw.config_backup_at.replace(tzinfo=timezone.utc)
        if (sw.config_backup_error or "").startswith("host_key_changed"):
            continue
        if last is None or (now - last).total_seconds() >= st.config_backup_interval_hours * 3600:
            due.append((sw.id, "schedule"))
        elif sw.id in traps and traps[sw.id] > last:
            due.append((sw.id, "trap"))
    sem = asyncio.Semaphore(max(1, st.config_backup_concurrency))
    from ..db.pg import session_factory
    results = []

    async def one(sid: int, trigger: str):
        async with sem, session_factory()() as s2:
            sw = await s2.get(Switch, sid)
            results.append(await backup_switch(s2, sw, trigger=trigger, now=now, fetcher=fetcher))
    await asyncio.gather(*(one(i, t) for i, t in due))
    return {"due": len(due), "ok": sum(1 for r in results if r["ok"]), "changed": sum(1 for r in results if r.get("changed")),
            "failed": sum(1 for r in results if not r["ok"])}
