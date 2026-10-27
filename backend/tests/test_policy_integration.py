"""Policy collection + storage + API against a mocked FortiGate. All configs are SYNTHETIC TEST FIXTURES."""
from datetime import datetime, timedelta, timezone

import httpx
import pytest_asyncio
import respx
from sqlalchemy import select

from app.config import get_settings
from app.db.models import Firewall, FirewallPolicy, PolicyConfigChange, ShadowFinding, User
from app.main import create_app
from app.policy.collector import sync_firewall
from app.policy.store import COUNTER_COLS, counter_deltas_window
from app.policy.usage import CounterPoint, counter_deltas
from app.security import TokenCipher, hash_password

from .test_storage_analytics import _load, traffic

BASE = "https://fgt.test.local:443"
OBJ = {
    "firewall/address": [{"name": "LAN", "type": "ipmask", "subnet": "10.0.0.0 255.0.0.0"},
                         {"name": "Srv", "type": "ipmask", "subnet": "10.0.0.0 255.255.255.0"}],
    "firewall.service/custom": [{"name": "ALL", "protocol": "IP", "protocol-number": 0},
                                {"name": "HTTPS", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "443"}],
}


def P(pid, src="LAN", svc="HTTPS", action="accept", uuid=None, log="all", name=None):
    return {"policyid": pid, "name": name or f"p{pid}", "uuid": uuid or f"u-{pid}", "status": "enable", "action": action,
            "srcintf": [{"name": "port1"}], "dstintf": [{"name": "wan1"}], "srcaddr": [{"name": src}], "dstaddr": [{"name": "all"}],
            "service": [{"name": svc}], "schedule": "always", "logtraffic": log}


def mock_fgt(policies, counters=None, counters_status=200):
    respx.get(f"{BASE}/api/v2/cmdb/firewall/policy").mock(return_value=httpx.Response(200, json={"results": policies}))
    for path, res in OBJ.items():
        respx.get(f"{BASE}/api/v2/cmdb/{path}").mock(return_value=httpx.Response(200, json={"results": res}))
    respx.get(url__regex=r".*/api/v2/cmdb/(firewall/(addrgrp|address6|addrgrp6)|firewall.service/group|system/zone)(\?.*)?$").mock(
        return_value=httpx.Response(200, json={"results": []}))
    respx.get(f"{BASE}/api/v2/monitor/firewall/policy").mock(
        return_value=httpx.Response(counters_status, json={"results": counters or []}))
    # configuration-drift tables (not exercised here)
    respx.get(url__regex=r".*/api/v2/cmdb/(system/(interface|admin|global)|vpn\.ssl/settings)(\?.*)?$").mock(return_value=httpx.Response(404))


@pytest_asyncio.fixture
async def fw(db, clean_ch):
    clean_ch.command("TRUNCATE TABLE policy_counters")
    f = Firewall(name="fw1", host="fgt.test.local", https_port=443, vdom="root", site="Lab",
                 token_ciphertext=TokenCipher().encrypt("tok-1234567890"), tags=[], syslog_source_ips=[], capabilities={},
                 health={}, api_log_cursor={})
    db.add(f)
    await db.commit()
    return f


@respx.mock
async def test_sync_stores_policies_counters_and_findings(db, clean_ch, fw):
    mock_fgt([P(1, src="LAN", svc="ALL", action="deny"), P(2, src="Srv")],
             counters=[{"policyid": 1, "uuid": "u-1", "hit_count": 10, "bytes": 1000, "packets": 9, "last_used": 1792500000},
                       {"policyid": 2, "uuid": "u-2", "hit_count": 0, "bytes": 0, "packets": 0}])
    st = await sync_firewall(db, clean_ch, fw)
    assert st.status == "ok" and st.policies == 2 and st.counters_supported is True
    pols = {p.policyid: p for p in (await db.execute(select(FirewallPolicy))).scalars()}
    assert pols[1].seq == 1 and pols[2].seq == 2 and pols[2].analysis["shadowed_by"] == 1
    f = (await db.execute(select(ShadowFinding))).scalar_one()
    assert f.classification == "full_shadow" and f.severity == "high"
    assert clean_ch.query("SELECT count() AS n FROM policy_counters")[0]["n"] == 2
    assert all(c.request.method == "GET" for c in respx.calls)  # read-only collection


@respx.mock
async def test_change_tracking_reorder_modify_delete_reuse(db, clean_ch, fw):
    mock_fgt([P(1), P(2), P(3)])
    await sync_firewall(db, clean_ch, fw)
    respx.reset()
    # 2 modified (action), 1 and 3 reordered, 3 deleted? -> keep 3, delete nothing; ID 1 reused with new uuid
    mock_fgt([P(3), P(2, action="deny"), P(1, uuid="u-1-new")])
    await sync_firewall(db, clean_ch, fw)
    respx.reset()
    mock_fgt([P(2, action="deny"), P(1, uuid="u-1-new")])  # 3 deleted
    await sync_firewall(db, clean_ch, fw)
    ch = [(c.policyid, c.change_type) for c in (await db.execute(select(PolicyConfigChange).order_by(PolicyConfigChange.id))).scalars()]
    assert (2, "modified") in ch and (1, "reused") in ch and (3, "reordered") in ch and (3, "deleted") in ch
    p1 = (await db.execute(select(FirewallPolicy).where(FirewallPolicy.policyid == 1))).scalar_one()
    assert len(p1.uuid_history) == 2
    p3 = (await db.execute(select(FirewallPolicy).where(FirewallPolicy.policyid == 3))).scalar_one()
    assert p3.deleted_at is not None


@respx.mock
async def test_counters_unsupported_are_not_zero(db, clean_ch, fw):
    mock_fgt([P(1)], counters_status=404)
    st = await sync_firewall(db, clean_ch, fw)
    assert st.counters_supported is False and st.status == "partial"


async def test_sql_counter_deltas_match_python(clean_ch):
    t0 = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(days=5)
    seq = [(0, "a", 100), (1, "a", 150), (2, "a", 20), (3, "a", 50), (4, "b", 5)]  # reset at day 2, reuse at day 4
    rows = [{"ts": t0 + timedelta(days=d), "firewall_id": 9, "vdom": "root", "policyid": 7, "uuid": u, "hit_count": h,
             "bytes": h * 10, "packets": h, "active_sessions": None, "first_used": None, "last_used": None, "source": "test"} for d, u, h in seq]
    clean_ch.insert("policy_counters", rows, COUNTER_COLS)
    sql = (await counter_deltas_window(clean_ch, 9, "root", t0 - timedelta(hours=1), t0 + timedelta(days=6)))[7]
    py = counter_deltas([CounterPoint(r["ts"], r["uuid"], r["hit_count"], r["bytes"], r["packets"]) for r in rows])
    assert sql["hits"] == py["hits"] == 50 + 20 + 30 + 5 and sql["resets"] == 2 and sql["bytes"] == py["bytes"]


# ------------------------------------------------------------------ API
PW = "correct-horse-battery-staple"


@pytest_asyncio.fixture
async def api(db, fw):
    get_settings.cache_clear()
    db.add_all([User(username="admin1", password_hash=hash_password(PW), role="admin"),
                User(username="analyst1", password_hash=hash_password(PW), role="analyst")])
    await db.commit()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app()), base_url="http://test") as c:
        yield c


async def login(c, u):
    return {"X-CSRF-Token": (await c.post("/api/auth/login", json={"username": u, "password": PW})).json()["csrf_token"]}


@respx.mock
async def test_policy_api_end_to_end(api, db, clean_ch, fw):
    respx.route(host="test").pass_through()
    mock_fgt([P(1, src="LAN", svc="ALL", action="deny"), P(2, src="Srv"), P(3, log="disable", name="nolog")], counters_status=404)
    h = await login(api, "analyst1")
    assert (await api.post(f"/api/v1/policies/sync/{fw.id}", headers=h)).status_code == 403
    h = await login(api, "admin1")
    r = await api.post(f"/api/v1/policies/sync/{fw.id}", headers=h)
    assert r.status_code == 200 and r.json()["policies"] == 3, r.text
    await _load(clean_ch, [traffic(i) for i in range(4)])  # fixture traffic carries policyid = sessionid → use explicit below
    from app.ingest.normalize import normalize
    from app.db.ch_schema import EVENT_COLUMNS
    now_ns = int((datetime.now(timezone.utc) - timedelta(minutes=5)).timestamp() * 1e9)
    evs = [normalize({"type": "traffic", "subtype": "forward", "devid": "x", "eventtime": str(now_ns + i), "logid": "13",
                      "srcip": "10.0.0.5", "dstip": "203.0.113.5", "dstport": "443", "proto": "6", "action": "deny",
                      "policyid": "1", "poluuid": "u-1", "sessionid": str(900 + i), "vd": "root"}, source="syslog",
                     firewall={"id": fw.id, "name": "fw1", "site": "Lab"}) for i in range(6)]
    clean_ch.insert("events", evs, EVENT_COLUMNS)
    inv = (await api.get("/api/v1/policies?window_days=7")).json()
    rows = {r["policyid"]: r for r in inv["items"]}
    assert rows[1]["siem_matches"] == 6 and rows[1]["assessment"]["state"] == "in_use"
    assert rows[1]["firewall_hits"] is None  # counters unsupported -> Not available, never 0
    assert rows[2]["analysis"]["worst"] == "full_shadow" and rows[2]["assessment"]["state"] == "no_observed_hits"
    assert rows[3]["logtraffic"] == "disable"
    s = (await api.get("/api/v1/policies/summary?window_days=7")).json()
    assert s["total"] == 3 and s["in_use"] == 1 and s["shadowed"] == 2  # policies 2 and 3 both sit behind the broad deny and s["no_logging"] == 1 and s["counters_available"] is False
    assert (await api.get("/api/v1/policies/summary?window_days=8")).status_code == 422
    d = (await api.get(f"/api/v1/policies/{fw.id}/root/1?window_days=7")).json()
    assert sum(p["events"] for p in d["timeseries"]["points"]) == 6 and d["top_sources"][0]["key"] == "10.0.0.5"
    assert d["shadow"][0]["role"] == "earlier" and d["shadow"][0]["other_policyid"] == 2
    sh = (await api.get("/api/v1/policies/shadow")).json()
    assert sh["by_severity"]["high"] == 2 and sh["items"][0]["later_policyid"] == 2
    filt = (await api.get("/api/v1/policies?window_days=7&assessment=in_use")).json()
    assert [r["policyid"] for r in filt["items"]] == [1]


class NaiveDatetimeCH:
    """Simulates clickhouse-connect (server mode): timestamps come back as timezone-naive datetime objects."""

    def __init__(self, real):
        self.real = real

    def _conv(self, rows):
        out = []
        for r in rows:
            nr = {}
            for k, v in r.items():
                if isinstance(v, str) and len(v) >= 19 and v[4] == "-" and v[10] == " ":
                    try:
                        nr[k] = datetime.fromisoformat(v)  # naive
                        continue
                    except ValueError:
                        pass
                nr[k] = v
            out.append(nr)
        return out

    async def aquery(self, sql, params=None):
        return self._conv(await self.real.aquery(sql, params))

    def __getattr__(self, n):
        return getattr(self.real, n)


@respx.mock
async def test_server_mode_naive_datetimes_do_not_crash(db, clean_ch, fw):
    """Regression: sync stayed at 'never' and /policies returned 500 on a real ClickHouse server because naive
    datetimes were compared with aware ones."""
    from app.policy.store import usage_for
    t0 = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(days=2)
    clean_ch.insert("policy_counters", [
        {"ts": t0 + timedelta(hours=h), "firewall_id": fw.id, "vdom": "root", "policyid": 1, "uuid": "u-1", "hit_count": 10 * h,
         "bytes": 100 * h, "packets": h, "active_sessions": None, "first_used": None, "last_used": t0 + timedelta(hours=h), "source": "test"}
        for h in range(3)], COUNTER_COLS)
    mock_fgt([P(1)], counters=[{"policyid": 1, "uuid": "u-1", "hit_count": 30, "bytes": 300, "packets": 3, "last_used": 1792500000}])
    naive = NaiveDatetimeCH(clean_ch)
    st = await sync_firewall(db, naive, fw)
    assert st.status == "ok", st.error
    await _load(clean_ch, [traffic(1)])
    pols, usage = await usage_for(db, naive, fw.id, "root", 30, True)
    u = usage[1]
    assert u["assessment"]["state"] == "in_use" and u["counters"]["hits"] == 30  # 0→10→20 snapshots + 30 from the sync
    assert u["log_coverage_since"].endswith("+00:00")
