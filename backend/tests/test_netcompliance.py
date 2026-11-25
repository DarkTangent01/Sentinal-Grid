"""Network compliance (app/netcompliance): configuration parsing per vendor, FortiGate snapshot checks, missing evidence
never counted as pass or fail, exceptions, framework scoring, stored runs and the API (configuration lines for admins only)."""
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.db.models import (ConfigSnapshot, DeviceConfigSnapshot, DeviceSshCredential, Firewall, NetComplianceException, NetComplianceResult,
                           Switch, SwitchCredential, TacClient)
from app.netcompliance import engine
from app.netcompliance.checks import BY_ID, CHECKS, Ctx, evaluate
from app.netcompliance.frameworks import FRAMEWORKS

from .test_api import api, login  # noqa: F401  (fixture)

NOW = datetime(2026, 11, 14, 12, 0, tzinfo=timezone.utc)

CISCO_GOOD = """hostname ACC1
service timestamps log datetime msec localtime show-timezone
no ip source-route
no ip http server
ip http secure-server
aaa new-model
aaa authentication login default group tacacs+ local
aaa accounting commands 15 default start-stop group tacacs+
enable secret 9 <masked>
username netops privilege 15 secret 9 <masked>
ip ssh version 2
ip dhcp snooping vlan 10,20
spanning-tree portfast edge bpduguard default
snmp-server group SENTINEL v3 priv
logging host 10.1.1.5
ntp authentication-key 1 sha1 <masked>
ntp trusted-key 1
ntp authenticate
ntp server 10.1.1.10 key 1
banner login ^C Authorised access only ^C
line con 0
 exec-timeout 10 0
line vty 0 4
 access-class MGMT in
 exec-timeout 10 0
 transport input ssh
line vty 5 15
 access-class MGMT in
 transport input ssh
end"""

CISCO_BAD = """hostname ACC2
ip http server
enable password 7 <masked>
username admin password 0 <masked>
snmp-server community <masked> RW
service tcp-small-servers
line vty 0 4
 exec-timeout 0 0
 transport input telnet ssh
line vty 5 15
end"""

JUNIPER = """set system login idle-timeout 10
set system login message "Authorised access only"
set system authentication-order [ tacplus password ]
set system accounting events interactive-commands
set system accounting destination tacplus server 10.1.1.20
set system services ssh
set system services telnet
set system syslog host 10.1.1.5 any notice
set system ntp server 10.1.1.10
set snmp community <masked> authorization read-only
set interfaces lo0 unit 0 family inet filter input PROTECT-RE"""

RUCKUS = """hostname ICX1
aaa authentication login default tacacs+ local
no telnet server
web-management https
ip ssh idle-time 10
logging host 10.1.1.5
ntp
 server 10.1.1.10
!
banner motd ^Authorised^"""


def ctx(**kw) -> Ctx:
    base = dict(kind="switch", id=1, name="sw", now=NOW, vendor="cisco", device_type="switch", backup_assigned=True,
                config_at=NOW - timedelta(hours=2), last_success_at=NOW - timedelta(minutes=5), snmp_version="v3", snmp_priv=True)
    base.update(kw)
    return Ctx(**base)


def by_check(results):
    return {r["check"]: r for r in results}


def test_catalog_maps_every_check_to_real_controls_of_all_four_frameworks():
    assert len(CHECKS) == len(BY_ID)
    for c in CHECKS:
        assert set(c.refs) == set(FRAMEWORKS), c.id
        for fk, ids in c.refs.items():
            assert ids and all(i in FRAMEWORKS[fk]["controls"] for i in ids), (c.id, fk, ids)
        assert c.severity in ("high", "medium", "low")


def test_cisco_hardened_configuration_passes_every_config_check():
    r = by_check(evaluate(ctx(config=CISCO_GOOD)))
    failing = {k: v["evidence"] for k, v in r.items() if v["status"] != "pass" and k != "NC-20"}   # NC-20 needs fleet data
    assert failing == {}, failing
    assert "NC-03" in r and any("transport input ssh" in ln for ln in r["NC-03"]["lines"])


def test_cisco_weak_configuration_fails_with_evidence_lines():
    r = by_check(evaluate(ctx(config=CISCO_BAD, snmp_version="v2c", snmp_priv=False)))
    for cid in ("NC-01", "NC-02", "NC-03", "NC-04", "NC-05", "NC-06", "NC-07", "NC-08", "NC-09", "NC-10", "NC-11", "NC-12", "NC-13",
                "NC-15", "NC-16", "NC-17", "NC-18"):
        assert r[cid]["status"] == "fail", (cid, r[cid])
    assert any("telnet" in ln for ln in r["NC-03"]["lines"])
    assert "line vty 5 15" in r["NC-06"]["lines"]                      # missing access-class named per line block
    assert any("enable password" in ln for ln in r["NC-15"]["lines"])
    assert any("<masked>" in ln for ln in r["NC-09"]["lines"])          # evidence keeps the backup's masking
    assert "Sentinel itself polls" in r["NC-09"]["evidence"]


def test_juniper_and_ruckus_parsers():
    j = by_check(evaluate(ctx(vendor="juniper", config=JUNIPER)))
    assert j["NC-01"]["status"] == "pass" and j["NC-02"]["status"] == "pass" and j["NC-07"]["status"] == "pass"
    assert j["NC-03"]["status"] == "fail" and j["NC-09"]["status"] == "fail" and j["NC-06"]["status"] == "pass"
    assert "NC-12" not in j and "NC-15" not in j                       # Cisco-only checks do not apply
    rk = by_check(evaluate(ctx(vendor="ruckus", config=RUCKUS)))
    assert rk["NC-03"]["status"] == "pass" and rk["NC-07"]["status"] == "pass" and rk["NC-13"]["status"] == "pass"
    assert rk["NC-05"]["status"] == "fail"                              # HTTP not explicitly disabled on FastIron
    assert rk["NC-14"]["status"] == "fail" and "NC-04" not in rk


def test_missing_evidence_is_not_evaluated_never_pass_or_fail():
    r = by_check(evaluate(ctx(config=None, backup_assigned=False, snmp_version="v3")))
    for cid in ("NC-03", "NC-05", "NC-07", "NC-13"):
        assert r[cid]["status"] == "not_evaluated" and "SSH credential" in r[cid]["evidence"]
    assert r["NC-19"]["status"] == "fail"                               # no backup at all is itself a finding
    assert r["NC-10"]["status"] == "pass"                               # telemetry checks still evaluate
    assert r["NC-09"]["status"] == "not_evaluated" and "SNMPv3" in r["NC-09"]["evidence"]
    unknown = by_check(evaluate(ctx(vendor="aruba", config="x")))
    assert unknown["NC-03"]["status"] == "not_evaluated" and "parser" in unknown["NC-03"]["evidence"]


def test_telemetry_evidence_without_configuration():
    tac = {"enabled": True, "last_auth": NOW - timedelta(days=1), "last_accounting": NOW - timedelta(days=2)}
    r = by_check(evaluate(ctx(config=None, backup_assigned=False, tacacs=tac, syslog_at=NOW - timedelta(hours=1), syslog_note="log source 'acc1'")))
    assert r["NC-01"]["status"] == "pass" and r["NC-02"]["status"] == "pass" and r["NC-11"]["status"] == "pass"
    stale = by_check(evaluate(ctx(last_success_at=NOW - timedelta(days=3), monitoring="active")))
    assert stale["NC-21"]["status"] == "fail"
    fw = by_check(evaluate(ctx(model="C9300", firmware="17.9.4", fleet_firmware={"17.9.4": 1, "17.12.3": 5})))
    assert fw["NC-20"]["status"] == "fail" and "17.12.3" in fw["NC-20"]["evidence"]
    alone = by_check(evaluate(ctx(model="C9500", firmware="17.9.4", fleet_firmware={"17.9.4": 1})))
    assert alone["NC-20"]["status"] == "not_evaluated"


FG_GOOD = {
    "interface": {"port1": {"role": "wan", "allowaccess": ["ping"]}, "mgmt": {"role": "lan", "allowaccess": ["https", "ssh"]}},
    "admin": {"admin": {"two-factor": "fortitoken", "trusthost1": "10.0.0.0 255.0.0.0"}},
    "global": {"admintimeout": 10, "admin-lockout-threshold": 3, "strong-crypto": "enable", "admin-telnet": "disable", "admin-maintainer": "disable"},
    "sslvpn": {"status": "enable", "login-attempt-limit": 3, "login-block-time": 300},
    "policy": {"1": {"name": "web", "status": "enable", "action": "accept", "srcaddr": ["lan"], "dstaddr": ["all"], "service": ["HTTPS"], "logtraffic": "all"}},
}


def fw_ctx(**kw) -> Ctx:
    base = dict(kind="firewall", id=7, name="fw1", now=NOW, vendor="fortinet", device_type="firewall", fg=FG_GOOD, fg_at=NOW - timedelta(days=20),
                last_success_at=NOW - timedelta(minutes=2), syslog_at=NOW - timedelta(minutes=1))
    base.update(kw)
    return Ctx(**base)


def test_fortigate_snapshot_checks():
    r = by_check(evaluate(fw_ctx()))
    assert {k for k, v in r.items() if v["status"] == "fail"} == set()
    assert r["NC-19"]["status"] == "pass"                               # snapshot old but unchanged and collection running
    assert "NC-03" not in r and "FG-10" not in r                        # switch-only check; BGP not read → not applicable
    bad = {**FG_GOOD, "interface": {"port1": {"role": "wan", "allowaccess": ["https", "http"]}},
           "admin": {"admin": {"two-factor": "disable", "trusthost1": "0.0.0.0 0.0.0.0"}},
           "global": {**FG_GOOD["global"], "admintimeout": 480, "strong-crypto": "disable", "admin-maintainer": "enable"},
           "policy": {"9": {"name": "any", "status": "enable", "action": "accept", "srcaddr": ["all"], "dstaddr": ["all"], "service": ["ALL"],
                            "logtraffic": "disable"}}}
    rb = by_check(evaluate(fw_ctx(fg=bad, syslog_at=None, bgp_audit=[{"severity": "high", "peer": "1.1.1.1", "check": "no_auth", "title": "no MD5"}])))
    for cid in ("FG-01", "FG-02", "FG-03", "FG-04", "FG-06", "FG-07", "FG-08", "FG-10", "FG-11", "NC-11"):
        assert rb[cid]["status"] == "fail", (cid, rb[cid])
    unreadable = by_check(evaluate(fw_ctx(fg={"interface": {}}, fg_errors={"admin": "forbidden"})))
    assert unreadable["FG-03"]["status"] == "not_evaluated" and "forbidden" in unreadable["FG-03"]["evidence"]
    none = by_check(evaluate(fw_ctx(fg=None, fg_at=None)))
    assert none["FG-01"]["status"] == "not_evaluated" and none["NC-19"]["status"] == "fail"


def test_scores_exclude_missing_evidence_and_exceptions():
    rows = [("switch", 1, [{"check": "NC-03", "status": "pass"}, {"check": "NC-05", "status": "fail"}, {"check": "NC-13", "status": "not_evaluated"}]),
            ("switch", 2, [{"check": "NC-03", "status": "fail"}])]
    s = engine.framework_summary(rows)["pci"]
    assert (s["pass"], s["fail"], s["not_evaluated"], s["score"]) == (1, 2, 1, 33.3)
    exc = [NetComplianceException(check_id="NC-03", device_kind="switch", device_id=2, reason="x", expires_at=NOW)]
    s2 = engine.framework_summary(rows, exc)["pci"]
    assert (s2["pass"], s2["fail"], s2["excepted"], s2["score"]) == (1, 1, 1, 50.0)


async def _seed(db):
    cred = SwitchCredential(name="v3", version="v3", username="u", priv_protocol="aes128")
    ssh = DeviceSshCredential(name="bk", username="backup", secret_ciphertext="x")
    db.add_all([cred, ssh])
    await db.flush()
    good = Switch(name="acc1", address="10.9.0.1", vendor="cisco", device_type="switch", model="C9300", firmware="17.12.3", credential_id=cred.id,
                  ssh_credential_id=ssh.id, config_backup_at=datetime.now(timezone.utc), last_success_at=datetime.now(timezone.utc), state="up")
    bad = Switch(name="acc2", address="10.9.0.2", vendor="cisco", device_type="switch", model="C9300", firmware="17.12.3",
                 last_success_at=datetime.now(timezone.utc), state="up")
    ap = Switch(name="ap1", address="10.9.0.3", vendor="cisco", device_type="ap")
    fw = Firewall(name="fw1", host="10.9.1.1", model="FG-100F", fortios_version_detected="7.4.4", api_last_success=datetime.now(timezone.utc))
    db.add_all([good, bad, ap, fw])
    await db.flush()
    db.add_all([DeviceConfigSnapshot(switch_id=good.id, taken_at=datetime.now(timezone.utc) - timedelta(days=1), config_hash="a", text=CISCO_BAD),
                DeviceConfigSnapshot(switch_id=good.id, taken_at=datetime.now(timezone.utc), config_hash="b", text=CISCO_GOOD),
                ConfigSnapshot(firewall_id=fw.id, vdom="root", config_hash="c", data=FG_GOOD, errors={}),
                TacClient(name="acc2", address="10.9.0.2", vendor="cisco", switch_id=bad.id, last_authentication_at=datetime.now(timezone.utc))])
    await db.commit()
    return good, bad, fw


async def test_run_uses_the_newest_configuration_and_skips_access_points(db):
    good, bad, fw = await _seed(db)
    run = await engine.run(db, trigger="manual", user="t")
    rows = {(r.device_kind, r.device_name): r for r in (await db.execute(select(NetComplianceResult).where(NetComplianceResult.run_id == run.id))).scalars()}
    assert set(rows) == {("switch", "acc1"), ("switch", "acc2"), ("firewall", "fw1")}
    g = by_check(rows[("switch", "acc1")].results)
    assert g["NC-03"]["status"] == "pass"                               # newest snapshot (CISCO_GOOD), not the older one
    b = by_check(rows[("switch", "acc2")].results)
    assert b["NC-03"]["status"] == "not_evaluated" and b["NC-01"]["status"] == "pass"   # no backup; TACACS+ telemetry
    assert run.summary["cis"]["score"] is not None and run.totals["pass"] > 0
    assert await engine.due(db, datetime.now(timezone.utc)) is None
    db.add(DeviceConfigSnapshot(switch_id=good.id, taken_at=datetime.now(timezone.utc) + timedelta(seconds=5), config_hash="d", text=CISCO_GOOD))
    await db.commit()
    assert await engine.due(db, datetime.now(timezone.utc) + timedelta(seconds=10)) == "data"


async def test_api_lines_for_admins_exceptions_audited_and_csv(api, db):  # noqa: F811
    good, bad, fw = await _seed(db)
    h = await login(api, "admin1")
    assert (await api.post("/api/nms/compliance/run", headers=h)).status_code == 200
    s = (await api.get("/api/nms/compliance/summary")).json()
    assert s["run"]["devices"] == 3 and set(s["frameworks"]) == {"cis", "pci", "nist", "iso"}
    d = (await api.get(f"/api/nms/compliance/devices/switch/{good.id}")).json()
    nc03 = next(f for f in d["findings"] if f["id"] == "NC-03")
    assert nc03["lines"] and not nc03["lines_hidden"]
    c = (await api.get("/api/nms/compliance/controls?framework=pci")).json()
    assert any(i["control"] == "2.2.7" for i in c["items"])
    # exception: excepted, not failed; audited
    r = await api.post("/api/nms/compliance/exceptions", headers=h, json={"check_id": "NC-19", "device_kind": "switch", "device_id": bad.id,
                                                                           "reason": "Backup through the vendor controller instead", "days": 30})
    assert r.status_code == 200, r.text
    d2 = (await api.get(f"/api/nms/compliance/devices/switch/{bad.id}")).json()
    assert next(f for f in d2["findings"] if f["id"] == "NC-19")["status"] == "excepted"
    bad_exc = await api.post("/api/nms/compliance/exceptions", headers=h, json={"check_id": "FG-01", "device_kind": "switch", "reason": "not valid here"})
    assert bad_exc.status_code == 422
    csv_text = (await api.get("/api/nms/compliance/export.csv?framework=iso")).text
    assert csv_text.splitlines()[0].endswith("ISO 27001") and "acc1" in csv_text
    # analyst: same results, no configuration lines, cannot run or add exceptions
    await api.post("/api/auth/logout", headers=h)
    ha = await login(api, "analyst1")
    d3 = (await api.get(f"/api/nms/compliance/devices/switch/{good.id}")).json()
    nc03a = next(f for f in d3["findings"] if f["id"] == "NC-03")
    assert nc03a["lines"] == [] and nc03a["lines_hidden"] and nc03a["evidence"] == nc03["evidence"]
    assert (await api.post("/api/nms/compliance/run", headers=ha)).status_code == 403
    assert (await api.post("/api/nms/compliance/exceptions", headers=ha, json={"check_id": "NC-19", "device_kind": "switch",
                                                                               "reason": "trying as an analyst"})).status_code == 403


async def test_report_section_shows_framework_scores_and_failing_checks(db, ch):
    from app import reports as R
    now = datetime.now(timezone.utc)
    doc, summary = await R.generate(db, ch, "Compliance", now - timedelta(days=7), now, ["network_compliance"])
    assert summary["network_compliance"] is None and "No compliance evaluation has run yet" in doc
    await _seed(db)
    await engine.run(db)
    doc, summary = await R.generate(db, ch, "Compliance", now - timedelta(days=7), now, ["network_compliance"])
    assert set(summary["network_compliance"]) == {"cis", "pci", "nist", "iso"}
    assert "PCI DSS v4.0" in doc and "Most failed checks" in doc and "NC-" in doc
