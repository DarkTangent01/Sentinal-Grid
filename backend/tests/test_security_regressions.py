"""Regression tests for the findings in docs/SECURITY_AUDIT_REPORT.md (one test group per finding ID)."""
import httpx
import pytest
from pydantic import ValidationError

from app.config import get_settings
from app.db.models import NotificationChannel, TiFeed, User
from app.fortigate.client import ClientConfig, FortiGateClient, FortiGateError
from app.hardening.cli import q, render_apply
from app.hardening.spec import PlanSpec
from app.ingest.pipeline import DeviceRegistry, EventSink
from app.netguard import DestinationError, check_host_static, check_ip, check_url_static
from app.security import hash_password

from .conftest import fixture_lines
from .test_api import FW, PW, api, login  # noqa: F401  (api is a fixture)

REG_FW = {"id": 1, "name": "FGT-TEST-01", "site": "Lab", "serial": "FGTEST0000000001", "host": "10.1.0.1"}


# ------------------------------------------------------------------ SEC-01 syslog device attribution
def _registry():
    r = DeviceRegistry()
    r.load([REG_FW])
    return r


async def test_sec01_spoofed_devid_from_other_sender_is_rejected(clean_ch):
    sink = EventSink(clean_ch, _registry())
    line = fixture_lines()[0]  # devid=FGTEST0000000001
    assert sink.add_line(line, source="syslog", peer_ip="192.0.2.66") is None
    assert sink.counters["source_mismatch"] == 1 and sink.counters["parsed"] == 0
    assert sink.add_line(line, source="syslog", peer_ip="10.1.0.1") is not None  # the firewall itself


async def test_sec01_syslog_source_ips_and_legacy_opt_in(clean_ch, monkeypatch):
    r = DeviceRegistry()
    r.load([{**REG_FW, "syslog_source_ips": ["10.9.9.9"]}])
    sink = EventSink(clean_ch, r)
    assert sink.add_line(fixture_lines()[0], source="syslog", peer_ip="10.9.9.9") is not None
    monkeypatch.setenv("SYSLOG_TRUST_DEVICE_FIELDS", "true")
    get_settings.cache_clear()
    try:
        assert sink.add_line(fixture_lines()[1], source="syslog", peer_ip="192.0.2.66") is not None
    finally:
        monkeypatch.delenv("SYSLOG_TRUST_DEVICE_FIELDS")
        get_settings.cache_clear()


# ------------------------------------------------------------------ SEC-04 token re-pointing
async def test_sec04_host_change_requires_reentering_token(api):  # noqa: F811
    h = await login(api, "admin1")
    fw = (await api.post("/api/firewalls", json=FW, headers=h)).json()
    r = await api.put(f"/api/firewalls/{fw['id']}", json={"host": "10.66.66.66"}, headers=h)
    assert r.status_code == 422 and "re-enter the API token" in r.text
    r = await api.put(f"/api/firewalls/{fw['id']}", json={"https_port": 8443}, headers=h)
    assert r.status_code == 422
    # unchanged host (what the UI sends on every save) and a host change with a new token both work
    assert (await api.put(f"/api/firewalls/{fw['id']}", json={"host": FW["host"], "site": "B"}, headers=h)).status_code == 200
    r = await api.put(f"/api/firewalls/{fw['id']}", json={"host": "10.66.66.66", "api_token": "another-token-value"}, headers=h)
    assert r.status_code == 200 and r.json()["host"] == "10.66.66.66"


# ------------------------------------------------------------------ SEC-06 SSRF guard
@pytest.mark.parametrize("host", ["127.0.0.1", "169.254.169.254", "localhost", "postgres", "clickhouse", "::1",
                                  "0.0.0.0", "fe80::1", "::ffff:127.0.0.1", "fd00:ec2::254", "x.localhost"])
def test_sec06_blocked_destinations(host):
    with pytest.raises(DestinationError):
        check_host_static(host)


@pytest.mark.parametrize("host", ["10.20.30.1", "192.168.1.1", "172.16.0.5", "fgt01.corp.example", "203.0.113.7"])
def test_sec06_private_and_named_firewalls_allowed(host):
    check_host_static(host)


def test_sec06_url_checks():
    with pytest.raises(DestinationError):
        check_url_static("http://169.254.169.254/latest/meta-data/", ("https", "http"))
    with pytest.raises(DestinationError):
        check_url_static("https://user:pw@hooks.example.com/x")
    with pytest.raises(DestinationError):
        check_url_static("file:///etc/passwd", ("https", "http"))
    check_url_static("https://hooks.slack.com/services/x")


def test_sec06_allowlist_override(monkeypatch):
    monkeypatch.setenv("OUTBOUND_ALLOWED_HOSTS", "localhost")
    get_settings.cache_clear()
    try:
        check_host_static("localhost")
    finally:
        monkeypatch.delenv("OUTBOUND_ALLOWED_HOSTS")
        get_settings.cache_clear()
    with pytest.raises(DestinationError):
        check_ip("127.0.0.1")


async def test_sec06_firewall_registration_rejects_internal_hosts(api):  # noqa: F811
    h = await login(api, "admin1")
    for host in ("127.0.0.1", "169.254.169.254", "postgres", "localhost"):
        r = await api.post("/api/firewalls", json={**FW, "name": f"fw-{host}", "host": host}, headers=h)
        assert r.status_code == 422, host


async def test_sec06_fortigate_client_refuses_loopback_even_if_stored():
    hits = []
    transport = httpx.MockTransport(lambda req: hits.append(req) or httpx.Response(200, json={}))
    c = FortiGateClient(ClientConfig(host="127.0.0.1", token="t" * 20, max_retries=0), transport=transport)
    with pytest.raises(FortiGateError):
        await c.get("/api/v2/monitor/system/status")
    await c.close()
    assert hits == []  # the request never left the process


async def test_sec06_webhook_channel_to_metadata_rejected(api):  # noqa: F811
    h = await login(api, "admin1")
    r = await api.post("/api/notifications/channels", headers=h,
                       json={"name": "m", "type": "webhook", "url": "http://169.254.169.254/latest/meta-data/"})
    assert r.status_code == 422
    r = await api.post("/api/notifications/channels", headers=h,
                       json={"name": "s", "type": "email", "config": {"host": "127.0.0.1", "to": ["a@example.com"]}})
    assert r.status_code == 422


async def test_sec06_stored_webhook_to_loopback_not_delivered(db):
    from app.notify import deliver, seal
    ch = NotificationChannel(name="w", type="webhook", config={}, secret_ciphertext=seal({"url": "http://127.0.0.1:8123/"}),
                             enabled=True)
    hits = []
    transport = httpx.MockTransport(lambda req: hits.append(req) or httpx.Response(200))
    with pytest.raises(DestinationError):
        await deliver(ch, {"title": "t"}, transport)
    assert hits == []


async def test_sec06_feed_redirect_to_metadata_blocked(db):
    from app.enrich.feeds import fetch_feed
    f = TiFeed(name="r", url="https://feed.test/list.txt", kind="ip", category="c2", enabled=True)
    db.add(f)
    await db.commit()

    def handler(req):
        if req.url.host == "feed.test":
            return httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})
        return httpx.Response(200, text="1.0.0.7\n")  # must never be reached

    status = await fetch_feed(db, f, httpx.MockTransport(handler))
    assert status.startswith("error") and f.indicator_count in (0, None)


async def test_sec06_feed_add_rejects_internal(api):  # noqa: F811
    h = await login(api, "admin1")
    r = await api.post("/api/ti/feeds", headers=h, json={"name": "internal", "url": "https://localhost/feed", "kind": "ip"})
    assert r.status_code == 422 and "not allowed" in r.text
    r = await api.post("/api/ti/feeds", headers=h, json={"name": "public", "url": "https://feeds.example.com/ip.txt", "kind": "ip"})
    assert r.status_code == 201


# ------------------------------------------------------------------ SEC-15/16 firewall field validation
async def test_sec15_ca_bundle_and_source_ips_validated(api):  # noqa: F811
    h = await login(api, "admin1")
    r = await api.post("/api/firewalls", json={**FW, "ca_bundle_path": "/etc/passwd"}, headers=h)
    assert r.status_code == 422
    r = await api.post("/api/firewalls", json={**FW, "ca_bundle_path": "/certs/../etc/shadow"}, headers=h)
    assert r.status_code == 422
    r = await api.post("/api/firewalls", json={**FW, "syslog_source_ips": ["not-an-ip"]}, headers=h)
    assert r.status_code == 422
    r = await api.post("/api/firewalls", json={**FW, "vdom": 'root" injected'}, headers=h)
    assert r.status_code == 422


# ------------------------------------------------------------------ SEC-05 FortiOS CLI injection
INJECT = 'x"\nend\nconfig system admin\n    edit "backdoor"\n        set accprofile "super_admin"\nnext\nend\n#'


@pytest.mark.parametrize("spec", [
    {"addresses": [{"name": "a", "subnet": "10.0.0.1/32", "comment": INJECT}]},
    {"services": [{"name": "svc", "tcp": ["443"], "comment": INJECT}]},
    {"address_groups": [{"name": "g", "members": ["all"], "comment": INJECT}]},
    {"policies": [{"name": "p", "srcintf": ["port1"], "dstintf": ["port2"], "service": ["HTTPS"], "comments": INJECT}]},
    {"policies": [{"name": "p", "srcintf": ["port1"], "dstintf": ["port2"], "service": ["HTTPS"], "schedule": INJECT}]},
    {"policies": [{"name": "p", "srcintf": ["port1"], "dstintf": ["port2"], "service": ["HTTPS"], "ssl_ssh_profile": INJECT}]},
    {"vdom": INJECT},
])
def test_sec05_cli_injection_rejected(spec):
    with pytest.raises(ValidationError):
        PlanSpec.model_validate(spec)


def test_sec05_plan_name_cannot_start_a_command_and_quote_is_defensive():
    out = render_apply(PlanSpec.model_validate({"addresses": [{"name": "a", "subnet": "10.0.0.1/32"}]}), 1,
                       "name\nconfig system admin")
    assert "\nconfig system admin" not in out
    with pytest.raises(ValueError):
        q('bad"value')


# ------------------------------------------------------------------ SEC-07 session revocation
def _cookie(c):
    return c.cookies.get("siem_session")


async def test_sec07_logout_revokes_the_token(api):  # noqa: F811
    h = await login(api, "analyst1")
    stolen = _cookie(api)
    assert (await api.post("/api/auth/logout", headers=h)).status_code == 200
    api.cookies.set("siem_session", stolen)
    assert (await api.get("/api/auth/me")).status_code == 401


async def test_sec07_password_change_revokes_other_sessions(api):  # noqa: F811
    await login(api, "analyst1")
    other = _cookie(api)
    h = await login(api, "analyst1")
    r = await api.put("/api/auth/me/password", headers=h, json={"current_password": PW, "new_password": "a-brand-new-password-1"})
    assert r.status_code == 200
    assert (await api.get("/api/auth/me")).status_code == 200  # the session that changed it got a fresh cookie
    api.cookies.set("siem_session", other)
    assert (await api.get("/api/auth/me")).status_code == 401


async def test_sec07_role_change_revokes_target_sessions(api, db):  # noqa: F811
    await login(api, "analyst1")
    analyst_cookie = _cookie(api)
    h = await login(api, "admin1")
    uid = next(u["id"] for u in (await api.get("/api/users")).json() if u["username"] == "analyst1")
    assert (await api.patch(f"/api/users/{uid}", headers=h, json={"is_active": True, "role": "admin"})).status_code == 200
    api.cookies.set("siem_session", analyst_cookie)
    assert (await api.get("/api/auth/me")).status_code == 401


async def test_sec07_unknown_user_still_pays_argon2(api, monkeypatch):  # noqa: F811
    import app.api.auth as auth_mod
    calls = []
    monkeypatch.setattr(auth_mod, "burn_password_check", lambda pw: calls.append(pw))
    r = await api.post("/api/auth/login", json={"username": "nobody-here", "password": "whatever"})
    assert r.status_code == 401 and calls == ["whatever"]


# ------------------------------------------------------------------ SEC-09 saved-search IDOR
async def test_sec09_private_saved_search_not_runnable_by_others(api, db):  # noqa: F811
    db.add(User(username="analyst2", password_hash=hash_password(PW), role="analyst"))
    await db.commit()
    h = await login(api, "analyst1")
    sid = (await api.post("/api/searches", headers=h, json={"name": "mine", "query": "action:deny", "shared": False})).json()["id"]
    assert (await api.post(f"/api/searches/{sid}/run", headers=h)).status_code == 200
    h2 = await login(api, "analyst2")
    r = await api.post(f"/api/searches/{sid}/run", headers=h2)
    assert r.status_code == 404 and "action:deny" not in r.text
    h3 = await login(api, "admin1")
    assert (await api.post(f"/api/searches/{sid}/run", headers=h3)).status_code == 200


# ------------------------------------------------------------------ SEC-08 query range cap
async def test_sec08_unbounded_time_range_rejected(api):  # noqa: F811
    await login(api, "analyst1")
    r = await api.get("/api/analytics/kpis?start=1970-01-01T00:00:00Z&ql=raw:a")
    assert r.status_code == 422 and "limited to" in r.text
    assert (await api.get("/api/analytics/kpis?range=30d")).status_code == 200


# ------------------------------------------------------------------ SEC-13 CSV formula injection
def test_sec13_csv_safe():
    from app.api.deps import csv_safe
    for v in ("=HYPERLINK(\"x\")", "+1", "-1+cmd", "@SUM(A1)", "\t=1", "\r=1", "  =cmd"):
        assert csv_safe(v).startswith("'"), v
    assert csv_safe("10.0.0.1") == "10.0.0.1" and csv_safe(5) == 5


# ------------------------------------------------------------------ SEC-14/18 misc hardening
def test_sec18_retention_partition_id_must_be_identifier():
    from app.retention import _check_partition_id
    _check_partition_id("a1b2c3d4e5f6_20261021")
    with pytest.raises(ValueError):
        _check_partition_id("x' OR 1=1 --")


async def test_sec12_openapi_disabled_in_production(monkeypatch):
    from app.main import create_app
    monkeypatch.setenv("ENVIRONMENT", "production")
    get_settings.cache_clear()
    try:
        app = create_app()
    finally:
        monkeypatch.delenv("ENVIRONMENT")
        get_settings.cache_clear()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        assert (await c.get("/api/openapi.json")).status_code == 404
        assert (await c.get("/api/docs")).status_code == 404


async def test_sec11_csrf_header_must_match(api):  # noqa: F811
    await login(api, "admin1")
    assert (await api.post("/api/firewalls", json=FW, headers={"X-CSRF-Token": "wrong"})).status_code == 403
    assert (await api.post("/api/firewalls", json=FW, headers={"X-CSRF-Token": ""})).status_code == 403
