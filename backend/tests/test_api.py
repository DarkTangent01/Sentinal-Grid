"""API security: authentication, CSRF, RBAC, token secrecy, input validation."""
import httpx
import pytest_asyncio

from app.config import get_settings
from app.db.models import Firewall, User
from app.main import create_app
from app.security import hash_password

PW = "correct-horse-battery-staple"


@pytest_asyncio.fixture
async def api(db, clean_ch):
    get_settings.cache_clear()
    db.add_all([User(username="admin1", password_hash=hash_password(PW), role="admin"),
                User(username="analyst1", password_hash=hash_password(PW), role="analyst")])
    await db.commit()
    app = create_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def login(c, user):
    r = await c.post("/api/auth/login", json={"username": user, "password": PW})
    assert r.status_code == 200, r.text
    return {"X-CSRF-Token": r.json()["csrf_token"]}


FW = {"name": "fw-a", "host": "10.20.30.1", "api_token": "super-secret-token-value", "site": "Lab", "fortios_version": "7.4.4"}


async def test_requires_auth(api):
    assert (await api.get("/api/firewalls")).status_code == 401
    assert (await api.get("/api/analytics/kpis")).status_code == 401


async def test_login_failure_and_lockout(api):
    for _ in range(5):
        assert (await api.post("/api/auth/login", json={"username": "analyst1", "password": "wrong"})).status_code == 401
    # locked even with the right password
    assert (await api.post("/api/auth/login", json={"username": "analyst1", "password": PW})).status_code == 401


async def test_session_cookie_flags(api):
    r = await api.post("/api/auth/login", json={"username": "admin1", "password": PW})
    cookie = [v for k, v in r.headers.multi_items() if k == "set-cookie" and v.startswith("siem_session")][0]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie


async def test_csrf_required_for_writes(api):
    await login(api, "admin1")
    assert (await api.post("/api/firewalls", json=FW)).status_code == 403


async def test_admin_creates_firewall_token_never_returned(api, db):
    h = await login(api, "admin1")
    r = await api.post("/api/firewalls", json=FW, headers=h)
    assert r.status_code == 201
    body = r.text
    assert "super-secret-token-value" not in body and "token_ciphertext" not in body
    assert r.json()["has_token"] is True
    fw = await db.get(Firewall, r.json()["id"])
    await db.refresh(fw)
    assert fw.token_ciphertext and "super-secret" not in fw.token_ciphertext  # encrypted at rest
    listing = await api.get("/api/firewalls")
    assert "super-secret-token-value" not in listing.text
    audit = await api.get("/api/admin/audit")
    assert "super-secret-token-value" not in audit.text and "firewall_create" in audit.text


async def test_analyst_is_read_only(api):
    h = await login(api, "analyst1")
    assert (await api.post("/api/firewalls", json=FW, headers=h)).status_code == 403
    assert (await api.put("/api/alert-rules/port_scan", json={"enabled": False}, headers=h)).status_code == 403
    assert (await api.get("/api/users")).status_code == 403
    assert (await api.get("/api/firewalls")).status_code == 200
    assert (await api.get("/api/analytics/kpis?range=1h")).status_code == 200


async def test_input_validation(api):
    h = await login(api, "admin1")
    assert (await api.post("/api/firewalls", json={**FW, "host": "bad host;rm"}, headers=h)).status_code == 422
    assert (await api.get("/api/events?src_ip=not-an-ip")).status_code == 422
    assert (await api.get("/api/events?range=99y")).status_code == 422
    assert (await api.get("/api/investigate/ip/1.2.3")).status_code == 422
    assert (await api.get("/api/events/abc';drop")).status_code in (404, 422)


async def test_security_headers_and_health(api):
    r = await api.get("/api/health")
    assert r.status_code == 200 and r.headers["x-frame-options"] == "DENY" and "content-security-policy" in r.headers


async def test_events_and_export(api, clean_ch):
    from .test_storage_analytics import _load, traffic
    await _load(clean_ch, [traffic(i) for i in range(3)] + [traffic(10, src="10.0.0.9", action="deny")])
    await login(api, "analyst1")
    r = await api.get("/api/events?range=1h&verdict=denied")
    assert r.status_code == 200 and r.json()["total"] == 1
    r = await api.get("/api/events/export.csv?range=1h")
    assert r.status_code == 200 and r.text.count("\n") == 5
    k = (await api.get("/api/analytics/kpis?range=1h")).json()
    assert k["traffic_events"] == 4 and k["denied_events"] == 1
