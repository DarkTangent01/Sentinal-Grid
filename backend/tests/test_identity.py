"""User and identity analytics: VPN identity (xauthuser), sessions and assigned-IP traffic, user↔IP↔device, failures,
success-after-failure, unusual logins, admin activity and account / privilege changes, rules and API."""
from datetime import timedelta

import pytest
from sqlalchemy import select

from app import identity
from app.alerts.engine import ensure_default_rules, run_rules
from app.db.models import AlertRule
from app.ingest.normalize import normalize
from app.ingest.parser import parse_kv
from app.ingest.pipeline import EventSink

from .test_api import api, login  # noqa: F401
from .test_ops import NOW, line
from .test_storage_analytics import registry, traffic


def vpn(ts, logid, action, user, *, remip="122.183.41.159", country="India", assign="10.1.5.1", fct="58180492C815", extra="", tunnel="blinkit-remote_0"):
    return line(ts, logid, "vpn", f'logdesc="x" msg="x" action="{action}" remip={remip} locip=180.151.194.162 remport=5350 locport=4500 '
                f'outintf="port2" srccountry="{country}" user="192.168.1.5" group="N/A" xauthuser="{user}" xauthgroup="blinkit-vm-group" '
                f'assignip={assign} vpntunnel="{tunnel}" fctuid="{fct}" {extra}')


def admin(ts, logid, user, action, status="success", src="172.29.30.167", profile="super_admin"):
    return line(ts, logid, "system", f'logdesc="Admin login" sn="0" user="{user}" ui="https({src})" method="https" srcip={src} dstip=172.31.255.1 '
                f'action="{action}" status="{status}" reason="none" profile="{profile}" msg="Administrator {user} {action} {status} from https({src})"')


def cfg(ts, user, path, obj, action, attr=""):
    return line(ts, "0100044547", "system", f'logdesc="Object attribute configured" user="{user}" ui="https(172.29.30.167)" action="{action}" '
                f'cfgtid=1 cfgpath="{path}" cfgobj="{obj}" cfgattr="{attr}" msg="{action} {path} {obj}"')


def test_vpn_user_is_xauthuser():
    ev = normalize(parse_kv(vpn(NOW, "0101037138", "tunnel-up", "Akhtar.ali")), source="syslog", raw="x")
    assert ev["user"] == "Akhtar.ali"
    s2s = normalize(parse_kv(vpn(NOW, "0101037141", "tunnel-stats", "N/A")), source="syslog", raw="x")
    assert s2s["user"] == ""  # the peer id (an IP) is not a person
    assert normalize({"type": "event", "subtype": "vpn", "user": "test", "xauthuser": "N/A", "logid": "1"}, source="s")["user"] == "test"


async def _ingest(ch):
    sink = EventSink(ch, registry())
    m = lambda x: NOW - timedelta(minutes=x)  # noqa: E731
    lines = []
    # 30-day baseline for akhtar: India, daytime, one device
    for d in range(2, 9):
        t = NOW.replace(hour=10, minute=0) - timedelta(days=d)
        lines += [vpn(t, "0101037138", "tunnel-up", "Akhtar.ali", extra='tunneltype="ipsec"'),
                  vpn(t + timedelta(hours=1), "0101037138", "tunnel-down", "Akhtar.ali")]
    # now: session with traffic, then a login from a new country / device
    lines += [vpn(m(50), "0101037138", "tunnel-up", "Akhtar.ali"),
              vpn(m(50), "0101037139", "phase2-up", "Akhtar.ali"),
              vpn(m(20), "0101037138", "tunnel-down", "Akhtar.ali", extra="duration=1800 sentbyte=5000 rcvdbyte=90000"),
              vpn(m(10), "0101037138", "tunnel-up", "Akhtar.ali", remip="185.220.101.5", country="Netherlands", fct="FFFF0000AAAA",
                  assign="10.1.5.9", tunnel="blinkit-remote_1")]
    # XAUTH failures for adarsh from 4 sources, then success
    for i in range(12):
        lines.append(line(m(40 - i), "0101037121", "vpn", f'logdesc="Negotiate IPsec phase 1" msg="negotiate IPsec phase 1" action="negotiate" '
                          f'remip=203.0.113.{10 + i % 4} locip=180.151.194.162 user="192.168.0.106" xauthuser="Adarsh" vpntunnel="blinkit-remote" '
                          f'status="failure" result="XAUTH authentication failed"', "error"))
    lines.append(vpn(m(25), "0101037138", "tunnel-up", "Adarsh", remip="203.0.113.99", fct="ADARSHDEV", assign="10.1.5.20", tunnel="blinkit-remote_2"))
    # administrators
    lines += [admin(m(30), "0100032002", "Mayank", "login", "failed"), admin(m(29), "0100032001", "Mayank", "login"),
              admin(m(5), "0100032003", "Mayank", "logout"),
              cfg(m(28), "Mayank", "system.admin", "bob", "Add", "accprofile[super_admin]"),
              cfg(m(27), "Mayank", "system.admin", "TACACS-REMOTE-ADMINS", "Edit", "trusthost1[10.0.0.0 255.0.0.0]"),
              cfg(m(26), "Mayank", "firewall.policy", "53", "Edit", "action[deny->accept]"),
              # an admin resizing their own dashboard widget: logged as Edit system.admin, but not an account change
              cfg(m(26), "Ankit", "system.admin", "TACACS-REMOTE-ADMINS", "Edit", "gui-dashboard:1[widget:11[width[4->7]]]"),
              line(m(26), "0100044548", "system", 'user="Mayank" ui="ssh(172.29.30.167)" action="Execute" msg="execute cfg save"'),
              # the same change replicated to the HA peer
              line(m(26), "0100044547", "system", 'user="FGT_ha_admin" ui="ha_daemon" action="Edit" cfgpath="firewall.policy" cfgobj="53" '
                   'cfgattr="action[deny->accept]" msg="Edit firewall.policy 53"')]
    for ln in lines:
        assert sink.add_line(ln, source="syslog", peer_ip="10.1.0.1") is not None, ln
    for ev in [traffic(i, src="10.1.5.1", dst="142.250.1.1", ts=m(40), sent=1000, rcvd=5000) for i in range(5)]:
        sink.add_fields(ev, source="syslog", raw=None, peer_ip="10.1.0.1")
    await sink.flush()


@pytest.mark.asyncio
async def test_overview_sessions_failures_anomalies(clean_ch):
    await _ingest(clean_ch)
    o = await identity.overview(clean_ch, NOW - timedelta(hours=1), NOW + timedelta(seconds=1))
    users = {u["user"]: u for u in o["users"]}
    ak = users["Akhtar.ali"]
    assert ak["active"] and set(ak["countries"]) == {"India", "Netherlands"} and "10.1.5.1" in ak["assigned_ips"] and "192.168.1.5" in ak["client_ips"]
    assert set(ak["devices"]) == {"58180492C815", "FFFF0000AAAA"} and ak["risk"] > 0
    assert users["Mayank"]["is_admin"] and users["Mayank"]["failures"] == 1 and "super_admin" in users["Mayank"]["profiles"]
    s = [x for x in o["sessions"] if x["user"] == "Akhtar.ali"]
    assert len(s) == 2 and s[0]["active"] and not s[1]["active"] and s[1]["duration_s"] == 1800 and s[1]["rcvd"] == 90000
    f = o["failures"]
    assert f["by_user"][0]["user"] == "Adarsh" and f["by_user"][0]["failures"] == 12 and len(f["by_user"][0]["sources"]) == 4
    sa = [x for x in f["success_after_failures"] if x["user"] == "Adarsh"]
    assert sa and not sa[0]["same_source"]
    an = [a for a in o["anomalies"] if a["user"] == "Akhtar.ali"]
    assert {r["type"] for r in an[0]["reasons"]} >= {"new_country", "new_device"}
    assert any(m["type"] == "vpn-assigned" and m["ip"] == "10.1.5.1" for m in o["ip_map"])
    adm = o["admin"]
    assert adm["admins"][0]["admin"] == "Mayank" and adm["admins"][0]["changes"] == 3 and adm["admins"][0]["commands"] == 1
    assert adm["ha_synced"] == 1 and "FGT_ha_admin" not in {a["admin"] for a in adm["admins"]}
    priv = {(a["object"], a["privilege"]) for a in adm["account_changes"]}
    assert priv == {("bob", True), ("TACACS-REMOTE-ADMINS", True)}
    assert o["totals"]["privilege_changes"] == 2 and o["totals"]["active_sessions"] >= 2


@pytest.mark.asyncio
async def test_user_detail_and_traffic(clean_ch):
    await _ingest(clean_ch)
    d = await identity.user_detail(clean_ch, "akhtar.ali", NOW - timedelta(hours=1), NOW + timedelta(seconds=1))
    assert d["user"] == "Akhtar.ali" and d["baseline"]["countries"] == ["India"] and d["baseline"]["hours"][10] == 7
    assert d["traffic"]["events"] == 5 and d["traffic"]["bytes_rcvd"] == 25000 and d["traffic"]["destinations"][0]["dst_ip"] == "142.250.1.1"
    assert await identity.user_detail(clean_ch, "nobody", NOW - timedelta(hours=1), NOW) is None


def test_anomaly_rules_offline():
    base = identity.baseline([{"key": "u", "result": "success", "country": "India", "src_ip": "1.2.3.4", "device": "D1", "local_hour": 10}] * 12)
    ev = {"key": "u", "user": "u", "result": "success", "country": "India", "src_ip": "1.2.3.9", "device": "D1", "local_hour": 3, "local_dow": 2,
          "kind": "vpn", "firewall_id": 1, "firewall_name": "f", "t": NOW}
    a = identity.anomalies([ev], base)
    assert [r["type"] for r in a[0]["reasons"]] == ["unusual_hour"]
    adm = {**ev, "kind": "admin", "src_ip": "8.8.8.8", "local_hour": 23, "local_dow": 6}
    types = {r["type"] for r in identity.anomalies([adm], base)[0]["reasons"]}
    assert {"new_admin_source", "off_hours"} <= types


@pytest.mark.asyncio
async def test_identity_rules(clean_ch, db):
    await _ingest(clean_ch)
    await ensure_default_rules(db)
    keys = ("identity_auth_failures", "identity_success_after_failures", "identity_unusual_login", "admin_account_change", "admin_off_hours_change")
    for r in (await db.execute(select(AlertRule))).scalars():
        r.enabled = r.key in keys
        if r.enabled:
            r.params = {**r.params, "interval_minutes": 0, "window_minutes": 60}
        if r.key == "admin_off_hours_change":  # make "now" off-hours regardless of when the test runs
            r.params = {**r.params, "work_start_hour": 0, "work_end_hour": 0}
    await db.commit()
    res = await run_rules(clean_ch, db)
    assert res["identity_auth_failures"]["created"] == 1           # Adarsh, 12 failures from 4 sources
    assert res["identity_success_after_failures"]["created"] == 1  # Adarsh logged in after them
    assert res["identity_unusual_login"]["created"] >= 1           # Akhtar from the Netherlands on a new device
    assert res["admin_account_change"]["created"] == 2             # bob added (super_admin), TACACS admin edited
    assert res["admin_off_hours_change"]["created"] == 1           # Mayank; Ankit only resized a dashboard widget


@pytest.mark.asyncio
async def test_identity_api(api, clean_ch):  # noqa: F811
    await _ingest(clean_ch)
    h = await login(api, "analyst1")
    o = (await api.get("/api/identity/overview", params={"range": "24h"}, headers=h)).json()
    assert o["totals"]["users"] >= 3
    d = await api.get("/api/identity/users/Akhtar.ali", params={"range": "24h"}, headers=h)
    assert d.status_code == 200 and d.json()["sessions"]
    w = (await api.get("/api/identity/who", params={"ip": "10.1.5.20"}, headers=h)).json()
    assert w["sessions"][0]["user"] == "Adarsh"
    assert (await api.get("/api/identity/users/nobody", headers=h)).status_code == 404
