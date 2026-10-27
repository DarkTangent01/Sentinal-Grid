"""Hardening plans: validation, CLI rendering, RBAC, read-only firewall check, suggestions."""
import httpx
import pytest
import pytest_asyncio
import respx
from pydantic import ValidationError

from app.config import get_settings
from app.db.models import Firewall, User
from app.hardening.cli import render_apply, render_rollback
from app.hardening.spec import PlanSpec
from app.main import create_app
from app.security import TokenCipher, hash_password

SPEC = {
    "addresses": [{"name": "LAN-Users", "subnet": "10.10.0.5/16"}, {"name": "Partner", "fqdn": "api.partner.example.com"}],
    "address_groups": [{"name": "Allowed-Clients", "members": ["LAN-Users", "Partner"]}],
    "services": [{"name": "TCP-8443", "tcp": ["8443"]}, {"name": "App-Range", "tcp": ["9000-9010"], "udp": ["9000"]}],
    "service_groups": [{"name": "Internet-Allowed", "members": ["HTTPS", "DNS", "TCP-8443", "App-Range"]}],
    "url_filters": [{"table_id": 100, "name": "SIEM-Allow", "entries": [{"url": "*.example.com"}, {"url": "bad.example.net", "type": "simple", "action": "block"}],
                     "block_others": True, "profile_name": "SIEM-Web"}],
    "policies": [{"name": "LAN-Internet-Restricted", "srcintf": ["port1"], "dstintf": ["wan1"], "srcaddr": ["Allowed-Clients"],
                  "service": ["Internet-Allowed"], "webfilter_profile": "SIEM-Web"}],
}


def test_render_apply_contents_and_order():
    cli = render_apply(PlanSpec.model_validate(SPEC), 3, "test")
    assert "set subnet 10.10.0.0 255.255.0.0" in cli  # host bits normalized
    assert 'set type fqdn\n        set fqdn "api.partner.example.com"' in cli
    assert "set tcp-portrange 9000-9010" in cli and "set udp-portrange 9000" in cli
    assert 'set member "HTTPS" "DNS" "TCP-8443" "App-Range"' in cli
    assert 'edit 3\n                set url "*"\n                set type wildcard\n                set action block' in cli  # block-others last
    assert "set urlfilter-table 100" in cli and 'set webfilter-profile "SIEM-Web"' in cli
    order = [cli.index(f"\n{x}\n") for x in ("config firewall address", "config firewall addrgrp", "config firewall service custom",
                                             "config firewall service group", "config webfilter urlfilter", "config webfilter profile",
                                             "config firewall policy")]
    assert order == sorted(order)  # dependencies are created before use
    assert "REVIEW BEFORE APPLYING" in cli and "edit 0" in cli


def test_rollback_reverse_order():
    rb = render_rollback(PlanSpec.model_validate(SPEC), 3)
    order = [rb.index(x) for x in ("config firewall policy", "config webfilter profile", "config webfilter urlfilter",
                                   "config firewall service group", "config firewall service custom",
                                   "config firewall addrgrp", "config firewall address")]
    assert order == sorted(order)
    assert "<ID of LAN-Internet-Restricted>" in rb


def test_vdom_wrapping():
    cli = render_apply(PlanSpec.model_validate({"vdom": "corp", "services": [{"name": "S1", "tcp": ["1"]}]}))
    assert 'config vdom\n    edit "corp"\n    config firewall service custom' in cli


@pytest.mark.parametrize("bad, msg", [
    ({"services": [{"name": "X", "tcp": ["70000"]}]}, "out of range"),
    ({"services": [{"name": "X", "tcp": ["10-5"]}]}, "out of range"),
    ({"services": [{"name": "X"}]}, "at least one"),
    ({"services": [{"name": "HTTPS", "tcp": ["443"]}]}, "predefined"),
    ({"addresses": [{"name": "v6", "subnet": "2001:db8::/32"}]}, "IPv4"),
    ({"addresses": [{"name": "a", "subnet": "10.0.0.0/8", "fqdn": "x.com"}]}, "exactly one"),
    ({"addresses": [{"name": 'evil" \nconfig system admin', "subnet": "10.0.0.1"}]}, "invalid name"),
    ({"url_filters": [{"table_id": 1, "name": "u", "entries": [{"url": 'x" \n end'}]}]}, "invalid url"),
    ({"url_filters": [{"table_id": 1, "name": "u", "entries": [{"url": "https://x.com"}]}]}, "without http"),
    ({"policies": [{"name": "p" * 36, "srcintf": ["a"], "dstintf": ["b"], "service": ["ALL"]}]}, "invalid name"),
    ({"services": [{"name": "D", "tcp": ["1"]}], "service_groups": [{"name": "D", "members": ["HTTP"]}]}, "duplicate"),
])
def test_validation_rejects_bad_input(bad, msg):
    with pytest.raises(ValidationError, match=msg):
        PlanSpec.model_validate(bad)


def test_external_references():
    refs = PlanSpec.model_validate({"service_groups": [{"name": "G", "members": ["HTTPS", "Legacy-App"]}],
                                    "policies": [{"name": "p", "srcintf": ["port1"], "dstintf": ["wan1"], "srcaddr": ["Existing-LAN"],
                                                  "service": ["G"], "webfilter_profile": "default"}]}).external_references()
    assert refs == {"address": {"Existing-LAN"}, "service": {"Legacy-App"}, "webfilter_profile": {"default"},
                    "interface": {"port1", "wan1"}}


# ------------------------------------------------------------------ API
PW = "correct-horse-battery-staple"


@pytest_asyncio.fixture
async def api(db, clean_ch):
    get_settings.cache_clear()
    db.add_all([User(username="admin1", password_hash=hash_password(PW), role="admin"),
                User(username="analyst1", password_hash=hash_password(PW), role="analyst"),
                Firewall(name="fw1", host="fgt.test.local", https_port=443, token_ciphertext=TokenCipher().encrypt("tok-1234567890"),
                         tags=[], syslog_source_ips=[], capabilities={}, health={}, api_log_cursor={})])
    await db.commit()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app()), base_url="http://test") as c:
        yield c


async def login(c, user):
    r = await c.post("/api/auth/login", json={"username": user, "password": PW})
    return {"X-CSRF-Token": r.json()["csrf_token"]}


async def test_plan_crud_rbac_and_export(api):
    h = await login(api, "analyst1")
    assert (await api.post("/api/hardening/plans", json={"name": "p", "spec": SPEC}, headers=h)).status_code == 403
    h = await login(api, "admin1")
    r = await api.post("/api/hardening/plans", json={"name": "Restrict internet", "firewall_id": 1, "spec": SPEC}, headers=h)
    assert r.status_code == 201, r.text
    pid = r.json()["id"]
    bad = await api.put(f"/api/hardening/plans/{pid}", json={"name": "x", "spec": {"services": [{"name": "X", "tcp": ["0"]}]}}, headers=h)
    assert bad.status_code == 422 and "out of range" in str(bad.json())
    await login(api, "analyst1")  # analysts can read and export for review
    cli = (await api.get(f"/api/hardening/plans/{pid}/cli")).json()
    assert "config firewall service group" in cli["apply"] and "delete" in cli["rollback"]
    assert cli["external_references"]["interface"] == ["port1", "wan1"]
    await login(api, "admin1")
    audit_actions = [a["action"] for a in (await api.get("/api/admin/audit")).json()]
    assert "hardening_plan_export" in audit_actions and "hardening_plan_create" in audit_actions


@respx.mock
async def test_check_reports_overwrites_and_missing_using_get_only(api):
    h = await login(api, "admin1")
    pid = (await api.post("/api/hardening/plans", json={"name": "chk", "firewall_id": 1, "spec": SPEC}, headers=h)).json()["id"]
    base = "https://fgt.test.local:443"
    respx.get(f"{base}/api/v2/cmdb/firewall.service/custom/TCP-8443").mock(return_value=httpx.Response(200, json={"results": [{"name": "TCP-8443"}]}))
    respx.get(f"{base}/api/v2/cmdb/system/interface/port1").mock(return_value=httpx.Response(200, json={"results": [{"name": "port1"}]}))
    respx.get(url__regex=r".*/api/v2/cmdb/firewall/policy.*").mock(return_value=httpx.Response(200, json={"results": []}))
    route_any = respx.get(url__regex=r".*/api/v2/cmdb/.*").mock(return_value=httpx.Response(404))
    r = await api.post(f"/api/hardening/plans/{pid}/check", headers=h)
    assert r.status_code == 200, r.text
    res = r.json()
    assert {"kind": "service", "name": "TCP-8443"} in res["overwrites"]
    assert {"kind": "interface/zone", "name": "wan1"} in res["missing"]
    assert {"kind": "interface/zone", "name": "port1"} not in res["missing"]
    assert all(c.request.method == "GET" for c in respx.calls)  # never writes to the firewall
    assert route_any.called


async def test_suggestions_from_observed_traffic(api, clean_ch):
    from .test_storage_analytics import _load, traffic
    await _load(clean_ch, [traffic(i, dport=443) for i in range(5)] + [traffic(10 + i, dport=23, action="deny") for i in range(3)])
    await login(api, "analyst1")
    resp = await api.get("/api/hardening/suggest?range=1h")
    assert resp.status_code == 200, resp.text
    r = resp.json()
    ports = {(p["port"], p["proto"]): p for p in r["ports"]}
    assert ports[(443, "TCP")]["allowed"] == 5 and ports[(23, "TCP")]["denied"] == 3
