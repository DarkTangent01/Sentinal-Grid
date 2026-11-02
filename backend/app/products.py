"""Product boundaries: Sentinel Grid (SIEM) and Sentinel NMS (network monitoring) share one backend, database,
authentication and set of workers; this module is the single place that says which API belongs to which product
(docs/PRODUCTS.md).

Access model
    users.products lists the products an account may use ("grid", "nms"). Administrators can use every product
    (admin.access implies grid.access and nms.access). An analyst with an empty list can sign in but reaches no
    product API. Migration 0020 gave every existing account both products, because before the split every account
    could use every page; new accounts get only what an administrator assigns.

Enforcement
    current_user() checks every authenticated API call against PATH_PRODUCT (longest prefix wins, on a path-segment
    boundary). Shared paths (auth, users, admin, notifications, log sources, system, reports, assets, the firewall list
    used by every page's filter bar) need no product; firewall changes are NMS. Alerts are shared but filtered by
    product: an account only sees alerts of the products it may use.
"""
from __future__ import annotations

PRODUCTS = ("grid", "nms")
PRODUCT_LABEL = {"grid": "Sentinel Grid", "nms": "Sentinel NMS"}

# API prefix → product. Anything not listed (or listed as None) is shared.
PATH_PRODUCT: dict[str, str | None] = {
    # Sentinel Grid — security analytics, detection, investigation, security incidents, compliance evidence
    "/api/analytics": "grid", "/api/events": "grid", "/api/search": "grid", "/api/searches": "grid", "/api/hunting": "grid",
    "/api/bookmarks": "grid", "/api/detections": "grid", "/api/incidents": "grid",
    "/api/incident-analysts": "grid", "/api/ti": "grid", "/api/watchlists": "grid", "/api/workbooks": "grid",
    "/api/automation": "grid", "/api/entity": "grid", "/api/investigate": "grid", "/api/identity": "grid", "/api/vpn": "grid",
    "/api/geo": "grid", "/api/mitre": "grid", "/api/sigma": "grid", "/api/ql": "grid", "/api/tuning": "grid",
    "/api/compliance": "grid", "/api/ai": "grid",
    # Sentinel NMS — ISP / WAN, device health, routing, switches, AAA, policy and configuration management
    "/api/isp": "nms", "/api/wan": "nms", "/api/switches": "nms", "/api/tacacs": "nms", "/api/iac": "nms", "/api/bgp": "nms",
    "/api/fwhealth": "nms", "/api/vpn-tunnels": "nms", "/api/wireless": "nms", "/api/nms": "nms", "/api/snmp": "nms", "/api/hardening": "nms", "/api/drift": "nms", "/api/v1/policies": "nms",
    # shared services
    "/api/auth": None, "/api/users": None, "/api/admin": None, "/api/notifications": None, "/api/log-sources": None,
    "/api/system": None, "/api/reports": None, "/api/alert-rules": None, "/api/assets": None, "/api/alerts": None, "/api/firewalls": None,
    "/api/health": None, "/api/ready": None, "/api/metrics": None,  # metrics: administrators only (main.py)
}
# shared reads whose changes belong to one product
WRITE_PRODUCT: dict[str, str] = {"/api/firewalls": "nms"}

# alert rules that describe network operations (everything else is a security detection → Grid)
NMS_RULE_PREFIXES = ("switch_", "wan_", "bgp_", "wireless_", "nms_", "snmp_")
NMS_RULES = {"isp_outage", "icmp_down", "fw_resource_high", "fw_reboot", "log_feed_gap", "vpn_tunnel_down", "iac_drift",
             "tacacs_server_down", "tacacs_accounting_gap", "tacacs_missing_accounting", "tacacs_protocol_errors",
             "tacacs_backend_failures", "tacacs_config_change"}


def _match(path: str, table: dict) -> tuple[str, object] | None:
    best = None
    for p, v in table.items():
        if (path == p or path.startswith(p + "/")) and (best is None or len(p) > len(best[0])):
            best = (p, v)
    return best


def required_product(path: str, method: str = "GET") -> str | None:
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        w = _match(path, WRITE_PRODUCT)
        if w:
            return w[1]  # type: ignore[return-value]
    m = _match(path, PATH_PRODUCT)
    return m[1] if m else None  # type: ignore[return-value]


def products_of(user) -> list[str]:
    """Effective products of an account (administrators: all)."""
    if getattr(user, "role", "") == "admin":
        return list(PRODUCTS)
    return [p for p in PRODUCTS if p in (getattr(user, "products", None) or [])]


def alert_product(rule_key: str) -> str:
    return "nms" if rule_key in NMS_RULES or rule_key.startswith(NMS_RULE_PREFIXES) else "grid"


def rules_of(product: str, keys) -> list[str]:
    return [k for k in keys if alert_product(k) == product]


def site_allowed(user, site: str | None) -> bool:
    """NMS site scope: administrators and accounts without a site list see every site; otherwise only devices whose
    site is in the list (case-insensitive). A device without a site is visible only to unscoped accounts."""
    scope = [x.strip().lower() for x in (getattr(user, "sites", None) or []) if x and x.strip()]
    if getattr(user, "role", "") == "admin" or not scope:
        return True
    return (site or "").strip().lower() in scope


def validate_sites(values: list[str] | None) -> list[str]:
    out = sorted({x.strip()[:128] for x in (values or []) if x and x.strip()})
    if len(out) > 200:
        raise ValueError("at most 200 sites")
    return out


def validate_products(values: list[str] | None) -> list[str]:
    vals = sorted(set(values or []))
    bad = [v for v in vals if v not in PRODUCTS]
    if bad:
        raise ValueError(f"unknown product(s): {', '.join(bad)}")
    return vals


def nms_rule_clause(col):
    """SQL condition: the alert rule column belongs to Sentinel NMS."""
    from sqlalchemy import or_
    return or_(col.in_(sorted(NMS_RULES)), *[col.like(f"{p}%") for p in NMS_RULE_PREFIXES])
