"""Product boundaries: Sentinel Grid / Sentinel NMS access, backend enforcement, alert scoping, user management."""
from datetime import datetime, timezone

from sqlalchemy import select

from app.db.models import Alert, AuditLog, User
from app.products import PATH_PRODUCT, alert_product, products_of, required_product
from app.security import hash_password

from .test_api import PW, api, login  # noqa: F401
from .test_iac import As

NOW = datetime.now(timezone.utc)


async def _users(db):
    db.add_all([User(username="gridonly", password_hash=hash_password(PW), role="analyst", products=["grid"]),
                User(username="nmsonly", password_hash=hash_password(PW), role="analyst", products=["nms"]),
                User(username="noproduct", password_hash=hash_password(PW), role="analyst", products=[])])
    await db.commit()


def test_path_classification_and_segment_boundaries():
    assert required_product("/api/vpn/summary") == "grid" and required_product("/api/vpn-tunnels/overview") == "nms"
    assert required_product("/api/search") == "grid" and required_product("/api/searches/3") == "grid"
    assert required_product("/api/firewalls") is None and required_product("/api/firewalls", "POST") == "nms"
    assert required_product("/api/firewalls/2", "DELETE") == "nms" and required_product("/api/auth/me") is None
    assert required_product("/api/v1/policies/x") == "nms" and required_product("/api/wan/overview") == "nms"
    assert alert_product("wan_flapping") == "nms" and alert_product("switch_unreachable") == "nms" and alert_product("isp_outage") == "nms"
    assert alert_product("port_scan") == "grid" and alert_product("tacacs_auth_failures") == "grid"
    assert products_of(User(role="admin", products=[])) == ["grid", "nms"]
    assert products_of(User(role="analyst", products=["nms", "bogus"])) == ["nms"]


def test_every_api_route_is_classified():
    """A new router must be placed in a product (or declared shared) in app/products.py."""
    from app.main import create_app
    unclassified = sorted({"/".join(r.path.split("/")[:3]) for r in create_app().routes
                           if getattr(r, "path", "").startswith("/api/") and not r.path.startswith(("/api/docs", "/api/openapi"))
                           and not any(r.path == p or r.path.startswith(p + "/") for p in PATH_PRODUCT)})
    assert unclassified == [], unclassified


async def test_backend_enforces_product_access_and_audits(api, db):
    await _users(db)
    g = await As.login(api, "gridonly")
    n = await As.login(api, "nmsonly")
    x = await As.login(api, "noproduct")
    assert (await g.get("/api/incidents")).status_code == 200
    r = await g.get("/api/wan/meta")
    assert r.status_code == 403 and "Sentinel NMS" in r.json()["detail"]
    assert (await g.get("/api/switches/overview")).status_code == 403 and (await g.get("/api/tacacs/meta")).status_code == 403
    assert (await g.get("/api/firewalls")).status_code == 200                      # shared read (filter bar)
    assert (await g.post("/api/firewalls", json={"name": "x"})).status_code == 403  # firewall changes are NMS
    assert (await n.get("/api/wan/meta")).status_code == 200 and (await n.get("/api/analytics/kpis")).status_code == 403
    assert (await n.get("/api/incidents")).status_code == 403 and (await n.get("/api/threat-intel")).status_code in (403, 404)
    me = (await x.get("/api/auth/me")).json()
    assert me["products"] == [] and (await x.get("/api/incidents")).status_code == 403 and (await x.get("/api/wan/meta")).status_code == 403
    assert (await x.get("/api/alerts")).json()["total"] == 0
    denied = (await db.execute(select(AuditLog).where(AuditLog.action == "product_access_denied"))).scalars().all()
    assert {(d.username, d.detail["product"]) for d in denied} >= {("gridonly", "nms"), ("nmsonly", "grid"), ("noproduct", "grid")}
    assert all(d.success is False for d in denied)


async def test_alerts_are_scoped_to_the_accounts_products(api, db):
    await _users(db)
    mk = lambda key, g: Alert(rule_key=key, name=key, severity="medium", status="new", group_key=g, first_seen=NOW, last_seen=NOW,  # noqa: E731
                              event_count=1, evidence={}, created_at=NOW)
    db.add_all([mk("port_scan", "a"), mk("wan_flapping", "b"), mk("switch_unreachable", "c")])
    await db.commit()
    ids = {a.rule_key: a.id for a in (await db.execute(select(Alert))).scalars()}
    g = await As.login(api, "gridonly")
    n = await As.login(api, "nmsonly")
    assert [a["rule_key"] for a in (await g.get("/api/alerts")).json()["items"]] == ["port_scan"]
    assert sorted(a["rule_key"] for a in (await n.get("/api/alerts")).json()["items"]) == ["switch_unreachable", "wan_flapping"]
    assert (await g.get(f"/api/alerts/{ids['wan_flapping']}")).status_code == 404
    assert (await n.c.patch(f"/api/alerts/{ids['port_scan']}", json={"status": "resolved"}, headers=n.h)).status_code == 404
    h = await login(api, "admin1")
    assert (await api.get("/api/alerts", headers=h)).json()["total"] == 3
    assert (await api.get("/api/alerts", params={"product": "nms"}, headers=h)).json()["total"] == 2
    assert (await g.get("/api/alerts", params={"product": "nms"})).json()["total"] == 0   # asking does not widen access


async def test_user_management_assigns_products_explicitly(api, db):
    h = await login(api, "admin1")
    r = await api.post("/api/users", json={"username": "newbie", "password": "Str0ng!Passw0rd-x", "role": "analyst"}, headers=h)
    assert r.status_code == 201 and r.json()["products"] == []                     # nothing by default
    uid = r.json()["id"]
    assert (await api.post("/api/users", json={"username": "bad1", "password": "Str0ng!Passw0rd-x", "role": "analyst", "products": ["soc"]},
                           headers=h)).status_code == 422
    await _users(db)
    g = await As.login(api, "gridonly")
    gid = (await g.get("/api/auth/me")).json()["id"]
    assert (await g.get("/api/wan/meta")).status_code == 403
    r = await api.patch(f"/api/users/{gid}", json={"products": ["grid", "nms"]}, headers=h)
    assert r.status_code == 200 and r.json()["products"] == ["grid", "nms"]
    assert (await g.get("/api/wan/meta")).status_code == 200                       # applies immediately, same session
    assert (await api.patch(f"/api/users/{uid}", json={"products": ["grid"]}, headers=h)).json()["assigned_products"] == ["grid"]
    # default product (skip the selector) must be a product the account can use
    assert (await g.put("/api/auth/me/preferences", json={"default_product": "nms"})).json()["default_product"] == "nms"
    await api.patch(f"/api/users/{gid}", json={"products": ["grid"]}, headers=h)
    me = (await g.get("/api/auth/me")).json()
    assert me["products"] == ["grid"] and me["default_product"] is None
    assert (await g.put("/api/auth/me/preferences", json={"default_product": "nms"})).status_code == 403
    assert (await api.get("/api/auth/me", headers=h)).json()["products"] == ["grid", "nms"]   # admins: every product
