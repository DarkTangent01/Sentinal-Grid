"""NMS roles and permissions (enforced on every device-access route and on the terminal WebSocket).

Administrators (User.role == "admin") are Super Administrators. Every account with the NMS product keeps
nms.device.view and the traffic view permissions, so existing NMS users see exactly what they saw before; everything else
needs an NMS role.
Site scope (User.sites, products.site_allowed) still limits which devices a permission applies to.
"""
from __future__ import annotations

from fastapi import Depends, HTTPException

from ..db.models import User
from ..products import products_of, site_allowed

PERMISSIONS = (
    "nms.device.view",
    "nms.device.manage",
    "nms.device.access.view",
    "nms.device.access.ssh",
    "nms.device.access.https",
    "nms.device.access.diagnostics",
    "nms.device.access.command_execute",
    "nms.device.access.configuration",
    "nms.device.access.credential.manage",
    "nms.device.access.session.terminate",
    "nms.device.access.audit.view",
    "nms.automation.execute",
    "nms.configuration.approve",
    # application & protocol intelligence (app/traffic)
    "nms.traffic.view",                 # traffic analytics (every NMS account, like the Flow Analytics page before it)
    "nms.traffic.detections.view",      # traffic security detections (every NMS account, as alerts are)
    "nms.traffic.sensitive.view",       # MAC addresses, domains / DNS queries, reverse-DNS names, wireless user names
    "nms.traffic.export",               # CSV exports
    "nms.traffic.rules.manage",         # detection thresholds, custom rules, signatures, VLAN policies
    "nms.traffic.enrichment.manage",    # DNS / ASN / reverse-DNS enrichment switches
    "nms.traffic.collector.manage",     # network ranges and zones, deduplication / LAG handling, authorised services
)

_ALL = set(PERMISSIONS)
_BASE = {"nms.device.view", "nms.traffic.view", "nms.traffic.detections.view"}   # every account with the NMS product
_VIEW = _BASE | {"nms.device.access.view"}
_TRAFFIC_ENGINEER = {"nms.traffic.sensitive.view", "nms.traffic.export"}
_TRAFFIC_ADMIN = _TRAFFIC_ENGINEER | {"nms.traffic.rules.manage", "nms.traffic.enrichment.manage", "nms.traffic.collector.manage"}
ROLES: dict[str, dict] = {
    "super_admin": {"label": "Super Administrator", "permissions": _ALL},
    "nms_admin": {"label": "NMS Administrator", "permissions": _ALL},
    "network_engineer": {"label": "Network Engineer", "permissions": _VIEW | {
        "nms.device.access.ssh", "nms.device.access.https", "nms.device.access.diagnostics", "nms.device.access.command_execute",
        "nms.device.access.configuration", "nms.automation.execute"} | _TRAFFIC_ENGINEER | {"nms.traffic.rules.manage"}},
    "network_operator": {"label": "Network Operator", "permissions": _VIEW | {
        "nms.device.access.ssh", "nms.device.access.diagnostics", "nms.device.access.command_execute"}},
    "read_only": {"label": "Read-only User", "permissions": set(_VIEW)},
    # a site administrator's permissions apply only to the sites in their account's site list
    "site_admin": {"label": "Site Administrator", "permissions": _VIEW | {
        "nms.device.manage", "nms.device.access.ssh", "nms.device.access.https", "nms.device.access.diagnostics",
        "nms.device.access.command_execute", "nms.device.access.configuration", "nms.device.access.session.terminate",
        "nms.device.access.audit.view", "nms.automation.execute", "nms.configuration.approve"} | _TRAFFIC_ADMIN},
    "auditor": {"label": "Auditor", "permissions": _VIEW | {"nms.device.access.audit.view"} | _TRAFFIC_ENGINEER},
}


def roles_of(user: User) -> list[str]:
    if getattr(user, "role", "") == "admin":
        return ["super_admin"]
    return sorted(r for r in (getattr(user, "nms_roles", None) or []) if r in ROLES)


def permissions_of(user: User) -> set[str]:
    if getattr(user, "role", "") == "admin":
        return set(_ALL)
    if "nms" not in products_of(user):
        return set()
    out = set(_BASE)
    for r in roles_of(user):
        out |= ROLES[r]["permissions"]
    return out


def has(user: User, perm: str, site: str | None = None, *, check_site: bool = False) -> bool:
    if perm not in _ALL:
        raise ValueError(f"unknown permission {perm}")
    if perm not in permissions_of(user):
        return False
    return site_allowed(user, site) if check_site else True


def require(perm: str):
    """FastAPI dependency: the signed-in user holds `perm` (site checks happen where the device is known)."""
    from ..api.deps import current_user

    async def dep(user: User = Depends(current_user)) -> User:
        if not has(user, perm):
            raise HTTPException(403, f"permission {perm} required")
        return user
    return dep


def validate_roles(values: list[str]) -> list[str]:
    bad = [v for v in values if v not in ROLES]
    if bad:
        raise ValueError(f"unknown NMS role(s): {', '.join(bad)}")
    return sorted(set(values))
