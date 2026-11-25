"""Topology with APs, inferred dependencies, failure impact and dependency-aware AP alerting (switches/topology.py,
switches/alerts.py, wireless/alerts.py). Synthetic LLDP rows: a core, a distribution switch and two access switches
cabled in a loop, three APs and their clients."""
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.db.models import Switch, SwitchNeighbor, WirelessAp, WirelessClient
from app.switches import topology as T

from .test_api import api  # noqa: F401  (fixture)

NOW = datetime(2026, 11, 13, 10, 0, tzinfo=timezone.utc)


async def _lab(db, roles=("core", "distribution", "access", "access")):
    names = ["CORE", "DIST", "ACC1", "ACC2"]
    sws = []
    for i, (n, r) in enumerate(zip(names, roles)):
        x = Switch(name=n, address=f"10.0.0.{i + 1}", site="HQ", role=r, state="up", capabilities={}, group_state={}, health={}, thresholds={})
        db.add(x)
        sws.append(x)
    wlc = Switch(name="WLC", address="10.0.0.9", site="HQ", role="wlc", state="up", vendor="cisco", capabilities={}, group_state={}, health={},
                 thresholds={})
    db.add(wlc)
    await db.flush()
    core, dist, a1, a2 = sws

    def cable(x, y, px, py):
        for s_, r_, lp, rp in ((x, y, px, py), (y, x, py, px)):
            db.add(SwitchNeighbor(switch_id=s_.id, local_port=lp, remote_key=r_.name.lower(), protocol="lldp", remote_name=r_.name,
                                  remote_port=rp, remote_mgmt_ip=r_.address, capabilities=["bridge"], present=True, first_seen=NOW, last_seen=NOW))
    cable(core, dist, "Te1/0/1", "Te1/0/48")
    cable(dist, a1, "Gi1/0/1", "Te1/1/1")
    cable(dist, a2, "Gi1/0/2", "Te1/1/1")
    cable(a1, a2, "Gi1/0/47", "Gi1/0/47")            # a redundant cable: a loop, not a dependency
    aps = []
    for n, (sw, clients) in enumerate([(a1, 10), (a1, 5), (a2, 7)], start=1):
        a = WirelessAp(wlc_id=wlc.id, mac=f"00:aa:00:00:00:0{n}", name=f"AP-0{n}", site="HQ", state="up", present=True, counters={},
                       clients=clients, switch_id=sw.id, uplink={"switch": sw.name, "port": f"Gi1/0/{n}"})
        db.add(a)
        aps.append(a)
    await db.flush()
    for i, ssid in enumerate(["CORP", "CORP", "GUEST"]):
        db.add(WirelessClient(wlc_id=wlc.id, mac=f"00:cc:00:00:00:0{i}", ap_id=aps[i].id, ssid=ssid, present=True, roams=0, disconnects=0))
    await db.commit()
    return core, dist, a1, a2, wlc, aps


async def test_topology_lists_aps_and_infers_parents_through_a_loop(db):
    core, dist, a1, a2, wlc, aps = await _lab(db)
    topo = await T.build(db, now=NOW, aps=True)
    assert topo["totals"]["aps"] == 3
    ap_links = [lk for lk in topo["links"] if lk["b"]["node"].startswith("ap:")]
    assert {lk["a"]["node"] for lk in ap_links} == {f"sw:{a1.id}", f"sw:{a2.id}"}
    assert (await T.build(db, now=NOW))["totals"]["aps"] == 0                     # off by default
    sug = {r["switch"]: r for r in await T.infer_parents(db)}
    assert sug["CORE"]["is_root"] and sug["CORE"]["root_basis"] == "core role"
    assert sug["DIST"]["suggested_parent"] == "CORE"
    assert sug["ACC1"]["suggested_parent"] == "DIST" and sug["ACC2"]["suggested_parent"] == "DIST"   # not each other
    assert all(r["differs"] for r in sug.values() if not r["is_root"])           # nothing configured yet
    dist.parent_id = core.id
    await db.commit()
    sug = {r["switch"]: r for r in await T.infer_parents(db)}
    assert not sug["DIST"]["differs"] and (await db.get(Switch, a1.id)).parent_id is None   # never applied automatically


async def test_inference_without_roles_uses_the_best_connected_switch(db):
    core, dist, a1, a2, *_ = await _lab(db, roles=("", "", "", ""))
    sug = {r["switch"]: r for r in await T.infer_parents(db)}
    roots = [n for n, r in sug.items() if r["is_root"]]
    assert roots == ["DIST"] and sug["DIST"]["root_basis"] == "most connected switch"
    assert sug["CORE"]["suggested_parent"] == "DIST" and sug["ACC1"]["suggested_parent"] == "DIST"


async def test_impact_counts_downstream_switches_aps_clients_and_ssids(db):
    core, dist, a1, a2, wlc, aps = await _lab(db)
    imp = await T.impact(db, dist.id)
    assert {x["name"] for x in imp["downstream_switches"]} == {"ACC1", "ACC2"} and all(x["via"] == "inferred" for x in imp["downstream_switches"])
    assert len(imp["aps"]) == 3 and imp["clients"] == 22 and imp["ssids"] == {"CORP": 2, "GUEST": 1}
    imp = await T.impact(db, a1.id)
    assert imp["downstream_switches"] == [] and {a["name"] for a in imp["aps"]} == {"AP-01", "AP-02"} and imp["clients"] == 15
    a2.parent_id = a1.id                          # a configured parent wins over the inferred one
    await db.commit()
    imp = await T.impact(db, a1.id)
    assert [x["name"] for x in imp["downstream_switches"]] == ["ACC2"] and imp["downstream_switches"][0]["via"] == "configured"


async def test_aps_behind_a_down_switch_are_not_alerted_separately(db):
    from app.switches.alerts import rule_switch_unreachable
    from app.wireless.alerts import rule_wireless_ap_down
    core, dist, a1, a2, wlc, aps = await _lab(db)
    long_ago = datetime.now(timezone.utc) - timedelta(hours=1)
    for x in (a1,):
        x.state, x.state_since, x.fail_streak, x.last_error = "down", long_ago, 9, "timeout"
    for a in aps:
        a.state, a.state_since = "down", long_ago
    await db.commit()
    now = datetime.now(timezone.utc)
    ap_alerts = await rule_wireless_ap_down(None, now, {"min_down_minutes": 2})
    assert [d.evidence["ap"] for d in ap_alerts] == ["AP-03"]           # AP-03's switch (ACC2) is up: alerted on its own
    (sw_alert,) = await rule_switch_unreachable(None, now, {"min_down_minutes": 2})
    assert sw_alert.evidence["switch"] == "ACC1" and sorted(sw_alert.evidence["dependent_aps"]) == ["AP-01", "AP-02"]
    assert sw_alert.evidence["affected_clients"] == 15 and "2 access point(s)" in sw_alert.explanation
    # a configured chain: DIST down too, ACC1 behind it → one root (DIST) carries every AP behind it
    a1.parent_id, dist.parent_id = dist.id, core.id
    dist.state, dist.state_since, dist.fail_streak = "down", long_ago, 9
    await db.commit()
    (root,) = await rule_switch_unreachable(None, now, {"min_down_minutes": 2})
    assert root.evidence["switch"] == "DIST" and root.evidence["dependent_devices"] == ["ACC1"]
    assert sorted(root.evidence["dependent_aps"]) == ["AP-01", "AP-02"]


async def test_impact_and_suggestion_api(api, db):  # noqa: F811
    from .test_iac import As
    core, dist, *_ = await _lab(db)
    N = await As.login(api, "analyst1")
    r = (await N.get(f"/api/switches/{dist.id}/impact")).json()
    assert r["clients"] == 22 and len(r["downstream_switches"]) == 2
    assert (await N.get("/api/switches/999999/impact")).status_code == 404
    sug = (await N.get("/api/nms/dependencies/suggestions")).json()
    assert sug["differs"] == 3
    topo = (await N.get("/api/switches/topology", params={"aps": "true"})).json()
    assert topo["totals"]["aps"] == 3
    rows = (await db.execute(select(Switch).where(Switch.parent_id.is_not(None)))).scalars().all()
    assert rows == []
