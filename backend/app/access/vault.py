"""Credential vault: device login secrets for SSH, HTTPS, vendor API tokens and NETCONF.

Secrets are encrypted with TokenCipher (Fernet, key outside the database, rotation via app.rotate_keys) in
device_ssh_credentials.secret_ciphertext. No API returns a secret, and nothing here logs one. SNMP credentials stay in
their own profiles (switch_credentials), managed in Switch Monitoring.

Resolution for a device and a kind: the device's own assignment (switches.ssh_credential_id, kind ssh) wins; otherwise
the most specific group assignment (site / role / vendor; more matching fields wins, then the oldest assignment).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import DeviceSshCredential, NmsCredentialAssignment, Switch
from ..security import TokenCipher

KINDS = ("ssh", "https", "api_token", "netconf")
# api_token: a bearer / API token; Aruba Central may also hold client_id / client_secret / refresh_token so the
# integration can refresh its access token (the rotated refresh token is stored back, encrypted)
FIELDS = {"ssh": ("password", "private_key"), "https": ("password",), "api_token": ("token", "client_id", "client_secret", "refresh_token"),
          "netconf": ("password", "private_key")}


def seal(kind: str, values: dict) -> str:
    data = {k: v for k, v in values.items() if k in FIELDS[kind] and v}
    return TokenCipher().encrypt(json.dumps(data)) if data else ""


def unseal(cred: DeviceSshCredential) -> dict:
    return json.loads(TokenCipher().decrypt(cred.secret_ciphertext)) if cred.secret_ciphertext else {}


def describe(c: DeviceSshCredential, devices: int = 0, groups: int = 0) -> dict:
    iso = lambda v: (v if v.tzinfo else v.replace(tzinfo=timezone.utc)).isoformat() if v else None  # noqa: E731
    try:
        held = sorted(unseal(c).keys())
    except Exception:
        held = ["<unreadable: key rotation needed>"]
    return {"id": c.id, "name": c.name, "kind": c.kind or "ssh", "username": c.username, "description": c.description, "owner": c.owner,
            "has_secret": bool(c.secret_ciphertext), "secret_fields": held, "devices": devices, "groups": groups,
            "rotated_at": iso(c.rotated_at), "updated_at": iso(c.updated_at), "created_by": c.created_by}


def _specificity(a: NmsCredentialAssignment) -> int:
    return sum(1 for v in (a.site, a.role, a.vendor) if v)


def _matches(a: NmsCredentialAssignment, sw: Switch) -> bool:
    vendor = (sw.vendor_override or sw.vendor or "").lower()
    return ((not a.site or a.site.lower() == (sw.site or "").lower()) and (not a.role or a.role.lower() == (sw.role or "").lower())
            and (not a.vendor or a.vendor.lower() == vendor))


async def resolve(s: AsyncSession, sw: Switch, kind: str = "ssh") -> tuple[DeviceSshCredential | None, str]:
    """(credential, how it was chosen) for a device."""
    if kind == "ssh" and sw.ssh_credential_id:
        c = await s.get(DeviceSshCredential, sw.ssh_credential_id)
        if c is not None and (c.kind or "ssh") == "ssh":
            return c, "device"
    rows = (await s.execute(select(NmsCredentialAssignment).where(NmsCredentialAssignment.kind == kind)
                            .order_by(NmsCredentialAssignment.id))).scalars().all()
    best = sorted((a for a in rows if _matches(a, sw)), key=lambda a: (-_specificity(a), a.id))
    for a in best:
        c = await s.get(DeviceSshCredential, a.credential_id)
        if c is not None and (c.kind or "ssh") == kind:
            label = ", ".join(f"{k}={v}" for k, v in (("site", a.site), ("role", a.role), ("vendor", a.vendor)) if v) or "all devices"
            return c, f"group ({label})"
    return None, ""


def rotated(c: DeviceSshCredential) -> None:
    c.rotated_at = datetime.now(timezone.utc)
