"""TACACS+ AAA: configuration rendering and validation, policy engine (exec / command / vendors / precedence / conflicts),
log parsing and redaction, ingestion (cursors, duplicates, rotation, delayed data), sessions, deploy workflow (approval,
separation of duties, replay / stale protection, agent failures and rollback), health / outage, live client tests
against a simulated TACACS+ server, detections, API RBAC and validation. All servers are simulated: no real AAA
infrastructure is touched."""
import asyncio
import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import select

from app.db.models import (Alert, AlertRule, AuditLog, TacClient, TacConfigVersion, TacDeployJob, TacIdentitySource, TacRole, TacRoleMapping, TacServer,
                           TacSetting, TacUser, User)
from app.tacacs import jobs as J
from app.tacacs import parse as P
from app.tacacs import policy as PO
from app.tacacs import render as R
from app.tacacs import service as S
from app.tacacs.templates import template
from app.tacacs.vendors import ROLE_TEMPLATES, categorize

from .tacacs_sim import SimServer
from .test_api import api, login  # noqa: F401
from .test_iac import As

NOW = datetime(2026, 10, 28, 10, 0, tzinfo=timezone.utc)  # a Wednesday


def snap() -> dict:
    roles = {i + 1: {"id": i + 1, **{k: t[k] for k in ("name", "privileged", "vendor_profiles", "command_categories")}, "default_command_action": "deny"}
             for i, t in enumerate(ROLE_TEMPLATES)}
    rid = {r["name"]: r["id"] for r in roles.values()}
    return {
        "clients": [{"id": 1, "name": "wh1-acc-sw01", "address": "10.20.0.11", "vendor": "cisco", "site": "WH1", "device_group": "access", "enabled": True},
                    {"id": 2, "name": "fc2-icx-01", "address": "10.30.0.21", "vendor": "ruckus", "site": "FC2", "device_group": "access", "enabled": True},
                    {"id": 3, "name": "ggn-fw-01", "address": "10.10.0.1", "vendor": "fortinet", "site": "GGN", "device_group": "core", "enabled": True}],
        "sources": [{"id": 1, "name": "local", "kind": "local", "enabled": True, "settings": {}},
                    {"id": 2, "name": "corp-ad", "kind": "ad", "enabled": True, "settings": {"hosts": ["ldaps://dc1.example.net:636"], "base": "dc=example,dc=net",
                                                                                             "bind_dn": "CN=svc-tacacs,OU=svc,DC=example,DC=net",
                                                                                             "memberof_regex": "^CN=tac_([^,]+),.*"}}],
        "users": [{"username": "alice", "source_kind": "local", "enabled": True, "emergency": False, "groups": [], "password_hash": "$6$abc$hash"},
                  {"username": "breakglass", "source_kind": "local", "enabled": True, "emergency": True, "groups": [], "password_hash": "$6$x$y"},
                  {"username": "mallory", "source_kind": "directory", "enabled": False, "emergency": False, "groups": ["netops"], "password_hash": ""}],
        "roles": roles,
        "mappings": [{"id": 1, "principal_type": "group", "principal": "netops", "role_id": rid["network-engineer"], "scope_sites": [], "scope_device_groups": [],
                      "scope_vendors": [], "scope_clients": [], "time_window": "", "priority": 100, "expires_at": None, "enabled": True},
                     {"id": 2, "principal_type": "user", "principal": "alice", "role_id": rid["network-read-only"], "scope_sites": ["WH1"], "scope_device_groups": [],
                      "scope_vendors": [], "scope_clients": [], "time_window": "* 8-18 * * 1-5", "priority": 100, "expires_at": None, "enabled": True},
                     {"id": 3, "principal_type": "user", "principal": "breakglass", "role_id": rid["emergency-administrator"], "scope_sites": [], "scope_device_groups": [],
                      "scope_vendors": [], "scope_clients": [], "time_window": "", "priority": 10, "expires_at": None, "enabled": True},
                     {"id": 4, "principal_type": "user", "principal": "bob", "role_id": rid["network-administrator"], "scope_sites": [], "scope_device_groups": [],
                      "scope_vendors": [], "scope_clients": [], "time_window": "", "priority": 100, "expires_at": "2026-10-01T00:00:00+00:00", "enabled": True}],
        "rules": [{"id": 1, "role_id": rid["network-engineer"], "vendor": "any", "action": "deny", "match": "category", "pattern": "", "category": "reload_reset",
                   "priority": 10, "exception": False, "owner": "", "expires_at": None, "enabled": True},
                  {"id": 2, "role_id": rid["network-engineer"], "vendor": "cisco", "action": "deny", "match": "regex", "pattern": r"^debug ", "category": "",
                   "priority": 20, "exception": False, "owner": "", "expires_at": None, "enabled": True},
                  {"id": 3, "role_id": rid["network-engineer"], "vendor": "cisco", "action": "permit", "match": "regex", "pattern": r"^debug ip ospf", "category": "",
                   "priority": 5, "exception": True, "owner": "noc-lead", "expires_at": "2026-12-31T00:00:00+00:00", "enabled": True}],
        "policies": [{"name": "core-no-local", "device_groups": ["core"], "allowed_sources": ["directory"], "allow_emergency": True, "priority": 10, "enabled": True}],
    }


SECRETS = {"clients": {"wh1-acc-sw01": ["Kc1sco-Secret-Value-1234"], "fc2-icx-01": ["Ruck-Secret-xyz-9876", "Ruck-NEW-secret-4321"],
                       "ggn-fw-01": ["Fort-Secret-abc-5555"]}, "sources": {"corp-ad": "Bind-Pass-Value!"}, "tester": {"address": "172.18.0.5", "key": "Tester-Key-777"}}


def c(snapshot, name):
    return next(x for x in snapshot["clients"] if x["name"] == name)


# ------------------------------------------------------------------ rendering
def test_render_full_and_redacted():
    sn = snap()
    full = R.render(sn, SECRETS, redact=False, now=NOW)
    red = R.render(sn, SECRETS, redact=True, now=NOW)
    for secret in ("Kc1sco-Secret-Value-1234", "Ruck-NEW-secret-4321", "Bind-Pass-Value!", "Tester-Key-777", "$6$abc$hash"):
        assert secret in full and secret not in red
    assert full.count("{") == full.count("}") and red.count("{") == red.count("}")
    assert "device wh1-acc-sw01 {" in full and "address = 10.20.0.11/32" in full and "tag = cisco" in full
    assert full.count('key = "Ruck-') == 2  # rotation: both keys accepted
    assert "set priv-lvl = 15" in full and "add foundry-privlvl = 0" in full and 'add admin_prof = "prof_engineer"' in full
    assert "setenv LDAP_SERVER_TYPE = \"microsoft\"" in full and "exec = /usr/local/lib/mavis/mavis_tacplus-ng_ldap.pl" in full and "user backend = mavis" in full
    assert 'time tw1 { "* 8-18 * * 1-5" }' in full and "time == tw1" in full
    assert "accounting format = \"${msgid}${FS}${session.id}" in full and "destination = /tacacs/logs/acct.log" in full
    rs = full[full.index("ruleset {"):]
    assert rs.index("rule disabled-users") < rs.index("rule policy_core-no-local_local") < rs.index("rule tester") < rs.index("rule m3_") < rs.index("rule m1_")
    assert 'user == "mallory"' in rs and "rule m4_" not in rs  # expired mapping not rendered
    assert "if (cmd =~ /(?:^(reload|erase|format|delete|write erase|factory-reset)\\b)/) deny # rule:1" in full
    prof = full[full.index("profile r_network_engineer_cisco"):]
    assert prof.index("rule:3") < prof.index("rule:1") < prof.index("rule:2")  # exception (priority 5) before category deny before regex deny
    assert "device ggn-fw-01" in full and "profile r_network_engineer_fortinet" in full
    assert "user alice {" in full and "password login = crypt $6$abc$hash" in full and "user mallory" not in full


def test_render_rejects_bad_identifiers_and_escapes_strings():
    sn = snap()
    sn["clients"][0]["name"] = 'bad name"; deny'
    with pytest.raises(PO.PolicyError):
        R.render(sn, SECRETS, redact=False, now=NOW)
    assert R.q('a "b" \\c') == '"a \\"b\\" \\\\c"'
    assert R._re("^a/b") == "/^a\\/b/"


def test_validation_and_conflicts():
    sn = snap()
    v = S.validation(sn)
    assert v["ok"] and any("FortiGate" in w for w in v["warnings"])
    sn["rules"].append({**sn["rules"][1], "id": 9, "action": "permit"})
    sn["rules"].append({**sn["rules"][0], "id": 10, "exception": True, "owner": ""})
    sn["mappings"].append({**sn["mappings"][0], "id": 11, "role_id": 1})
    kinds = {x["type"] for x in PO.conflicts(sn, NOW)}
    assert {"contradiction", "exception_incomplete", "ambiguous_mapping"} <= kinds
    assert not S.validation(sn)["ok"]  # incomplete exceptions block a version


# ------------------------------------------------------------------ policy engine
def test_exec_authorization_precedence_and_denials():
    sn = snap()
    sw, icx, fw = c(sn, "wh1-acc-sw01"), c(sn, "fc2-icx-01"), c(sn, "ggn-fw-01")
    e = PO.evaluate_exec(sn, "carol", ["netops"], sw, NOW)
    assert e["decision"] == "permit" and e["role"] == "network-engineer" and e["vendor_profile"] == {"priv_lvl": 15}
    assert PO.evaluate_exec(sn, "carol", ["netops"], icx, NOW)["vendor_profile"] == {"priv_lvl": 0}
    assert PO.evaluate_exec(sn, "carol", ["helpdesk"], sw, NOW)["decision"] == "deny"  # default deny
    assert PO.evaluate_exec(sn, "mallory", ["netops"], sw, NOW)["reason"] == "account disabled or expired"
    a = PO.evaluate_exec(sn, "alice", [], sw, NOW)
    assert a["decision"] == "permit" and a["role"] == "network-read-only"
    assert PO.evaluate_exec(sn, "alice", [], sw, NOW.replace(hour=22))["decision"] == "deny"  # outside the time window
    assert PO.evaluate_exec(sn, "alice", [], icx, NOW)["decision"] == "deny"  # outside the site scope
    assert PO.evaluate_exec(sn, "alice", [], fw, NOW)["rule"] == "policy:core-no-local:local"  # local accounts not allowed on core
    assert PO.evaluate_exec(sn, "breakglass", [], fw, NOW)["role"] == "emergency-administrator"
    assert PO.evaluate_exec(sn, "bob", [], sw, NOW)["decision"] == "deny"  # expired mapping


def test_command_authorization_vendor_specific():
    sn = snap()
    sw, icx, fw = c(sn, "wh1-acc-sw01"), c(sn, "fc2-icx-01"), c(sn, "ggn-fw-01")
    ev = lambda cl, cmd, user="carol": PO.evaluate_command(sn, user, ["netops"], cl, cmd, NOW)  # noqa: E731
    assert ev(sw, "show running-config <cr>")["decision"] == "permit" and ev(sw, "show running-config <cr>")["category"] == "read_only"
    assert ev(sw, "reload")["decision"] == "deny" and ev(sw, "reload")["rule"] == "rule:1"
    assert ev(sw, "debug ip packet")["decision"] == "deny" and ev(sw, "debug ip ospf adj")["decision"] == "permit"  # exception wins
    assert ev(sw, "username eve privilege 15 secret 0 x")["decision"] == "deny"  # aaa_users not in the engineer role → default deny
    assert ev(sw, "frobnicate")["rule"] == "role-default"  # unmatched
    assert ev(icx, "write memory")["decision"] == "permit" and ev(icx, "erase startup-config")["decision"] == "deny"
    assert ev(icx, "debug ip packet")["decision"] == "deny"  # the cisco-only debug rule does not apply; default deny
    f = ev(fw, "config firewall policy")
    assert f["decision"] == "not_enforced" and "does not send per-command authorization" in f["reason"]
    assert ev(sw, "", "carol")["decision"] == "permit"  # shell start
    assert PO.evaluate_command(sn, "nobody", [], sw, "show version", NOW)["decision"] == "deny"


def test_categories_and_pattern_validation():
    assert categorize("cisco", "show ip int brief <cr>") == "read_only" and categorize("cisco", "reload in 5") == "reload_reset"
    assert categorize("cisco", "ip route 0.0.0.0 0.0.0.0 10.0.0.1") == "routing" and categorize("cisco", "configure terminal") == "config_mode"
    assert categorize("ruckus", "write memory") == "config_save_restore" and categorize("ruckus", "vlan 10") == "vlan"
    assert categorize("fortinet", "config firewall policy") == "firewall_policy" and categorize("fortinet", "execute factoryreset") == "reload_reset"
    for bad in (r"(?=x)", r"(a)\1", r"(?i)show", 'a"b', "(", "x" * 300):
        with pytest.raises(PO.PolicyError):
            PO.validate_pattern(bad)
    assert PO.validate_pattern(r"^show (ip|ipv6) route\b")
    with pytest.raises(PO.PolicyError):
        PO.validate_window("* 25 * * *")
    assert PO.in_window("0-59 8-18 * * 1-5", NOW) and not PO.in_window("* * * * 0,6", NOW)


def test_explain_states_enforcement_honestly():
    sn = snap()
    rid = next(k for k, r in sn["roles"].items() if r["name"] == "network-read-only")
    x = PO.explain(sn, rid, NOW)
    assert x["vendors"]["fortinet"]["enforcement"] == "profile-only" and x["vendors"]["fortinet"]["default"] == "n/a"
    assert "foundry-privlvl 5 (read-only)" == x["vendors"]["ruckus"]["privilege"] and x["vendors"]["cisco"]["privilege"] == "priv-lvl 1"


# ------------------------------------------------------------------ parsing / redaction
def line(kind, *fields, ts="2026-10-28T10:00:01.000000+00:00"):
    return ts + " " + "\t".join(fields)


def test_parse_all_kinds_and_result_classes():
    a = P.parse_line("authc", line("authc", "AUTHC-PASS", "1234", "10.20.0.11", "wh1-acc-sw01", "alice", "vty0", "10.99.0.5", "permit", "shell login", "15",
                                   "r_x", "m1_cisco", "172.18.0.2", "", ""), 1)
    assert a["parse_ok"] and a["event_type"] == "auth_success" and a["username"] == "alice" and a["remote_addr"] == "10.99.0.5"
    for msg, et in (("AUTHC-FAIL-DENY", "auth_failure"), ("AUTHC-FAIL-BACKEND", "auth_backend_error"), ("AUTHC-FAIL-ACL", "auth_policy_deny"),
                    ("AUTHC-FAIL-BUG", "protocol_error"), ("AUTHC-FAIL-NOUSER", "auth_failure"), ("AUTHC-FAIL-PASSWORD-NOT-TEXT", "auth_failure"),
                    ("AUTHC-FAIL-USERPROFILE", "auth_policy_deny"), ("AUTHC-PASS-PERMIT", "auth_success")):
        assert P.parse_line("authc", line("authc", msg, "1", "10.20.0.11", "d", "u", "p", "c", "deny", "a", "", "", "", "", "", ""), 1)["event_type"] == et
    z = P.parse_line("authz", line("authz", "AUTHZ-FAIL", "77", "10.20.0.11", "wh1", "carol", "vty1", "10.99.0.5", "deny", "shell", "15", "r_eng", "m1",
                                   "172.18.0.2", "reload <cr>", "service=shell|cmd=reload|cmd-arg=<cr>"), 1)
    assert z["event_type"] == "authz_deny" and z["cmd"] == "reload <cr>"
    s = P.parse_line("acct", line("acct", "ACCT-STOP", "88", "10.20.0.11", "wh1", "carol", "vty1", "10.99.0.5", "stop", "shell", "15", "", "", "172.18.0.2", "",
                                  "task_id=42|start_time=1|stop_time=61|elapsed_time=60|service=shell|priv-lvl=15"), 1)
    assert s["event_type"] == "acct_stop" and s["task_id"] == "42" and s["elapsed_s"] == 60 and s["priv_lvl"] == 15
    r = P.parse_line("conn", line("conn", "CONN-REJECT", "start", "tcp", "198.51.100.9", "51515", "172.18.0.2", "49"), 1)
    assert r["event_type"] == "conn_reject" and r["device_address"] == "198.51.100.9"
    bad = P.parse_line("acct", "garbage without format", 1)
    assert bad["parse_ok"] == 0 and bad["parse_error"]


def test_redaction_before_storage():
    for cmd, leak in (("username bob privilege 15 secret 9 $9$abcdefg", "$9$abcdefg"), ("snmp-server community Publ1c RO", "Publ1c"),
                      ("set password ENC AAAAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAA"), ("tacacs-server key 7 0822455D0A16", "0822455D0A16"),
                      ('set psksecret "Top Secret"', "Top Secret"), ("enable super-user-password Sup3r", "Sup3r")):
        e = P.parse_line("acct", line("acct", "ACCT-START", "1", "10.20.0.11", "d", "u", "p", "c", "start", "shell", "15", "", "", "s", cmd, ""), 1)
        assert leak not in e["cmd"] and leak not in e["raw"] and "***" in e["cmd"], cmd
    custom = P.compile_redactions([r"(token)\s+(\S+)"])
    assert "abc" not in P.redact("api token abc", custom)


# ------------------------------------------------------------------ ingestion / sessions
async def _server(db, kind="managed"):
    srv = TacServer(name="tac1", kind=kind, management_address="tacacs", port=49, agent={}, ingestion={})
    db.add(srv)
    db.add(TacClient(name="wh1-acc-sw01", address="10.20.0.11", vendor="cisco", site="WH1", secret_ciphertext=S.seal("k" * 20)))
    await db.commit()
    return srv


def _write(d: Path, kind: str, lines: list[str], mode="a"):
    with open(d / P.LOG_FILES[kind], mode) as f:
        for ln in lines:
            f.write(ln + "\n")


SESSION = [("ACCT-START", "", "task_id=100|service=shell|priv-lvl=15"), ("ACCT-START", "show version <cr>", "task_id=101|service=shell|priv-lvl=15"),
           ("ACCT-START", "configure terminal <cr>", "task_id=102|service=shell"), ("ACCT-STOP", "", "task_id=100|elapsed_time=120|service=shell")]


async def test_ingestion_cursor_duplicates_rotation_and_sessions(db, ch, tmp_path):
    from app.tacacs import queries as Q
    ch.command("TRUNCATE TABLE tacacs_events")
    srv = await _server(db)
    ts = lambda i: (NOW + timedelta(seconds=i)).isoformat().replace("+00:00", ".000000+00:00")  # noqa: E731
    _write(tmp_path, "authc", [line("authc", "AUTHC-PASS", "9", "10.20.0.11", "wh1-acc-sw01", "carol", "vty1", "10.99.0.5", "permit", "shell login", "15",
                                    "r", "m1", "s", "", "", ts=ts(0))])
    _write(tmp_path, "acct", [line("acct", m, "9", "10.20.0.11", "wh1-acc-sw01", "carol", "vty1", "10.99.0.5", "start" if "START" in m else "stop", "shell", "15",
                                   "", "", "s", cmd, args, ts=ts(i + 1)) for i, (m, cmd, args) in enumerate(SESSION)])
    with open(tmp_path / "authz.log", "w") as f:
        f.write(line("authz", "AUTHZ-FAIL", "9", "10.20.0.11", "wh1", "carol", "vty1", "c", "deny", "shell", "15", "", "", "s", "reload <cr>", "", ts=ts(3)) + "\n")
        # incomplete line (no newline yet): must not be consumed
        f.write(ts(4) + " AUTHZ-PASS\t9")
    st = await J.ingest(db, ch, srv, str(tmp_path))
    assert st["acct"]["new"] == 4 and st["authc"]["new"] == 1 and st["authz"]["new"] == 1
    assert (await J.ingest(db, ch, srv, str(tmp_path)))["acct"]["new"] == 0  # cursor: nothing re-read
    with open(tmp_path / "authz.log", "a") as f:
        f.write("\t10.20.0.11\twh1\tcarol\tvty1\tc\tpermit\tshell\t15\t\t\ts\tshow clock <cr>\t\n")
    assert (await J.ingest(db, ch, srv, str(tmp_path)))["authz"]["new"] == 1  # completed line picked up
    # rotation: file truncated and rewritten with one old (duplicate) and one new line
    _write(tmp_path, "acct", [line("acct", "ACCT-START", "9", "10.20.0.11", "wh1-acc-sw01", "carol", "vty1", "10.99.0.5", "start", "shell", "15", "", "", "s", "",
                                   "task_id=100|service=shell|priv-lvl=15", ts=ts(1)), "not a valid line"], mode="w")
    r = await J.ingest(db, ch, srv, str(tmp_path))
    assert r["acct"]["duplicates"] == 1 and r["acct"]["parse_errors"] == 1
    assert srv.ingestion["acct"]["parse_errors"] == 1 and srv.ingestion["acct"]["last_parse_error"]
    cl = (await db.execute(select(TacClient))).scalars().one()
    assert cl.last_accounting_at is not None and srv.last_accounting_at is not None
    rows = ch.query("SELECT vendor, site, cmd_category FROM tacacs_events FINAL WHERE task_id = '101'")
    assert rows[0] == {"vendor": "cisco", "site": "WH1", "cmd_category": "read_only"}
    f = {"t0": NOW - timedelta(hours=1), "t1": NOW + timedelta(hours=1)}
    se = (await Q.sessions(ch, f, 10, 0))["items"]
    assert len(se) == 1 and se[0]["state"] == "closed" and se[0]["elapsed_s"] == 120
    assert [x["cmd"] for x in se[0]["commands"]] == ["show version <cr>", "configure terminal <cr>"]
    ov = await Q.overview(db, ch, f)
    assert ov["totals"]["auth_success"] == 1 and ov["totals"]["authz_deny"] == 1 and ov["totals"]["unique_admins"] == 1
    assert ov["totals"]["active_sessions"] == 0 and ov["recent_denials"][0]["cmd"] == "reload <cr>"
    ev = await Q.events(ch, {**f, "user": "carol", "log": "acct"}, 2, 0, raw=False)
    assert ev["total"] == 4 and len(ev["items"]) == 2 and "raw" not in ev["items"][0]


async def test_missing_log_files_reported(db, ch, tmp_path):
    from app.tacacs import queries as Q
    srv = await _server(db)
    await J.ingest(db, ch, srv, str(tmp_path / "nowhere"))
    assert srv.ingestion["acct"]["missing"] is True
    f = {"t0": NOW - timedelta(hours=1), "t1": NOW + timedelta(hours=1)}
    # tac_plus-ng creates each log on its first event: a file never seen is not an ingestion problem, one that vanished is
    assert (await Q.overview(db, ch, f))["ingestion_issues"] == []
    _write(tmp_path, "acct", [])
    await J.ingest(db, ch, srv, str(tmp_path))
    (tmp_path / "acct.log").unlink()
    await J.ingest(db, ch, srv, str(tmp_path))
    assert [x["log"] for x in (await Q.overview(db, ch, f))["ingestion_issues"]] == ["acct"]


async def test_siem_health_probes_are_not_unknown_devices(db, ch, tmp_path):
    ch.command("TRUNCATE TABLE tacacs_events")
    srv = await _server(db)
    ts = (NOW).isoformat().replace("+00:00", ".000000+00:00")
    _write(tmp_path, "conn", [line("conn", "CONN-REJECT", "", "tcp", "127.0.0.1", "40000", "127.0.0.1", "49", ts=ts),
                              line("conn", "CONN-REJECT", "", "tcp", "198.51.100.9", "40001", "172.18.0.2", "49", ts=ts)])
    await J.ingest(db, ch, srv, str(tmp_path))
    rows = {r["device_address"]: r["event_type"] for r in ch.query("SELECT device_address, event_type FROM tacacs_events FINAL")}
    assert rows == {"127.0.0.1": "conn_probe", "198.51.100.9": "conn_reject"}


# Log variables tac_plus-ng accepts in a log format (parse_log_format in tac_plus-ng/utils.c at the pinned commit); a name it does
# not know makes the whole configuration fail to load ("log variable 'privlvl' is not recognized").
TAC_LOG_VARIABLES = {"msgid", "session.id", "device.address", "device.name", "device.port", "user", "client", "result", "action", "priv-lvl",
                     "profile", "rule", "server.address", "server.port", "identity-source", "hint", "service", "cmd", "args", "accttype",
                     "conn.protocol", "peer.address", "peer.port"}


def test_log_formats_use_known_variables_and_match_bootstrap():
    for kind, names in P.FIELDS.items():
        assert set(names) <= TAC_LOG_VARIABLES, (kind, set(names) - TAC_LOG_VARIABLES)
    boot = (Path(__file__).resolve().parents[2] / "deploy" / "tacacs" / "bootstrap.cfg").read_text()
    for kind in P.FIELDS:
        assert f"{P.FORMAT_KEY[kind]} format = {R.q(P.format_string(kind))}" in boot, kind


# ------------------------------------------------------------------ deploy workflow
async def _users(db):
    a = User(username="policy1", password_hash="x", role="analyst", products=["grid", "nms"], tacacs_roles=["policy_admin"])
    b = User(username="approver1", password_hash="x", role="analyst", products=["grid", "nms"], tacacs_roles=["approver"])
    db.add_all([a, b])
    await db.commit()
    return a, b


async def _fake_agent(cfg_dir: Path, status="deployed", delay=0.2):
    for _ in range(100):
        reqs = list((cfg_dir / "requests").glob("*.json"))
        if reqs:
            req = json.loads(reqs[0].read_text())
            (cfg_dir / "results" / reqs[0].name).write_text(json.dumps({"id": req["id"], "status": status, "ok": status in ("deployed", "valid"),
                                                                       "output": "parse ok"}))
            reqs[0].unlink()
            return req
        await asyncio.sleep(delay)


async def test_deploy_requires_approval_by_someone_else(db, tmp_path):
    for d in ("requests", "candidates", "results"):
        (tmp_path / d).mkdir()
    pol, appr = await _users(db)
    srv = await _server(db)
    db.add(TacSetting(data={**S.DEFAULT_SETTINGS, "client_networks": ["10.0.0.0/8"]}))
    db.add(TacIdentitySource(name="local", kind="local"))
    db.add_all(S.seed_roles())
    await db.commit()
    v = await S.commit_version(db, pol.username, "baseline")
    await db.commit()
    assert "k" * 20 in S.unseal(v.content_ciphertext) and "k" * 20 not in v.content_redacted
    job = await S.request_deploy(db, v, srv, pol, "first")
    await db.commit()
    assert job.status == "pending_approval"
    with pytest.raises(S.TacError) as e:
        await S.decide(db, job, pol, "approve", job.approval_hash, "")
    assert e.value.status == 403  # requester is not an approver
    pol.tacacs_roles = ["policy_admin", "approver"]
    with pytest.raises(S.TacError) as e:
        await S.decide(db, job, pol, "approve", job.approval_hash, "")
    assert "separation of duties" in e.value.message
    with pytest.raises(S.TacError) as e:
        await S.decide(db, job, appr, "approve", "0" * 64, "")
    assert "replayed" in e.value.message
    await S.decide(db, job, appr, "approve", job.approval_hash, "ok")
    assert job.status == "queued" and job.approved_by == "approver1"
    await db.commit()
    agent = asyncio.create_task(_fake_agent(tmp_path))
    await J.run_job(db, job, config_dir=str(tmp_path), timeout=10)
    req = await agent
    assert job.status == "succeeded" and req["sha256"] == v.sha256 and srv.deployed_version_id == v.id
    assert not (tmp_path / "candidates" / f"{job.id}.cfg").exists()
    assert (await db.execute(select(TacClient))).scalars().one().sync_status == "in_sync"
    # agent reports the candidate invalid
    j2 = TacDeployJob(version_id=v.id, server_id=srv.id, action="validate", status="queued", requested_by="policy1")
    db.add(j2)
    await db.commit()
    agent = asyncio.create_task(_fake_agent(tmp_path, "invalid"))
    await J.run_job(db, j2, config_dir=str(tmp_path), timeout=10)
    await agent
    assert j2.status == "invalid"
    # agent does not answer: failed, and the request is withdrawn so it cannot be applied later
    j3 = TacDeployJob(version_id=v.id, server_id=srv.id, action="deploy", status="queued", requested_by="policy1")
    db.add(j3)
    await db.commit()
    await J.run_job(db, j3, config_dir=str(tmp_path), timeout=1.5)
    assert j3.status == "failed" and "no answer" in j3.result["reason"] and not list((tmp_path / "requests").iterdir())
    # stale: the active configuration changed after the request
    j4 = await S.request_deploy(db, v, srv, pol, "again")
    srv.deployed_sha256 = "f" * 64
    with pytest.raises(S.TacError):
        await S.decide(db, j4, appr, "approve", j4.approval_hash, "")
    assert j4.status == "cancelled"


def _agent_module(base: Path):
    spec = importlib.util.spec_from_file_location("tacagent", Path(__file__).resolve().parents[2] / "deploy" / "tacacs" / "agent.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    m.BASE = str(base)
    m.ACTIVE = str(base / "active" / "tac_plus-ng.cfg")
    for d in ("requests", "candidates", "results", "active", "backups"):
        (base / d).mkdir(exist_ok=True)
    return m


def test_agent_validates_activates_and_rolls_back(tmp_path):
    m = _agent_module(tmp_path)
    (tmp_path / "active" / "tac_plus-ng.cfg").write_text("old config\n")
    (tmp_path / "candidates" / "5.cfg").write_text("new config key = Secret123\n")
    sha = m.sha256(str(tmp_path / "candidates" / "5.cfg"))
    m.reload = lambda: None
    m.parse_check = lambda p: (False, "line 1: syntax error near key = Secret123")
    r = m.handle("5", {"action": "deploy", "sha256": sha})
    assert r["status"] == "invalid" and "Secret123" not in r["output"] and (tmp_path / "active" / "tac_plus-ng.cfg").read_text() == "old config\n"
    m.parse_check = lambda p: (True, "")
    assert m.handle("5", {"action": "deploy", "sha256": "0" * 64})["output"] == "candidate does not match the requested sha256"
    m.healthy = lambda wait=8.0: True
    r = m.handle("5", {"action": "deploy", "sha256": sha})
    assert r["status"] == "deployed" and (tmp_path / "active" / "tac_plus-ng.cfg").read_text().startswith("new config") and r["backup"]
    (tmp_path / "candidates" / "6.cfg").write_text("broken at runtime\n")
    sha6 = m.sha256(str(tmp_path / "candidates" / "6.cfg"))
    calls = iter([False, True])
    m.healthy = lambda wait=8.0: next(calls)
    m.start = lambda: None
    m.alive = lambda: False
    r = m.handle("6", {"action": "deploy", "sha256": sha6})
    assert r["status"] == "rolled_back" and (tmp_path / "active" / "tac_plus-ng.cfg").read_text().startswith("new config")
    assert m.handle("7", {"action": "rm -rf /", "sha256": ""})["output"] == "unknown action"


# ------------------------------------------------------------------ health / outage
async def test_health_damping_outage_and_recovery(db, monkeypatch):
    srv = await _server(db, kind="external")
    res = iter([(True, 1.2, ""), (False, None, "timeout"), (False, None, "timeout"), (True, 1.0, "")])

    async def fake(host, port, timeout=3.0):
        return next(res)
    monkeypatch.setattr(J, "tcp_check", fake)
    await J.health(db, srv, NOW)
    assert srv.status == "up"
    await J.health(db, srv, NOW + timedelta(seconds=30))
    assert srv.status == "up" and srv.fail_streak == 1  # one miss is not an outage
    await J.health(db, srv, NOW + timedelta(seconds=60))
    assert srv.status == "down"
    await J.health(db, srv, NOW + timedelta(seconds=90))
    assert srv.status == "up" and srv.fail_streak == 0


async def test_tcp_check_respects_outbound_guard():
    ok, _ms, err = await J.tcp_check("127.0.0.1", 49, 0.5)
    assert not ok and "not allowed" in err


# ------------------------------------------------------------------ live client tests against a simulated TACACS+ server
async def test_client_auth_and_accounting_against_simulated_server(monkeypatch):
    from app.config import get_settings
    from app.tacacs import client as TC
    monkeypatch.setenv("OUTBOUND_ALLOWED_HOSTS", "127.0.0.1")
    get_settings.cache_clear()
    sim = await SimServer("Tester-Key-777", {"carol": "Correct-Horse-1"}).start()
    try:
        ok = await TC.authenticate("127.0.0.1", sim.port, "Tester-Key-777", "carol", "Correct-Horse-1", 3)
        assert ok["ok"] and ok["detail"] == "PASS"
        bad = await TC.authenticate("127.0.0.1", sim.port, "Tester-Key-777", "carol", "wrong-password", 3)
        assert not bad["ok"] and bad["category"] == "auth_reject" and "wrong-password" not in json.dumps(bad)
        acct = await TC.account("127.0.0.1", sim.port, "Tester-Key-777", "sentinel-grid-test", "sgtest-1", 3)
        assert acct["ok"] and any(r["type"] == "acct" and b"task_id=sgtest-1" in r["raw"] for r in sim.received)
        mismatch = await TC.authenticate("127.0.0.1", sim.port, "Wrong-Key", "carol", "Correct-Horse-1", 3)
        assert not mismatch["ok"] and mismatch["category"] in ("protocol_error", "server_error", "auth_reject")
    finally:
        await sim.stop()
        get_settings.cache_clear()
    down = await TC.tcp("192.0.2.1", 49, 0.5)  # TEST-NET: never answers
    assert not down["ok"] and down["category"] in ("timeout", "refused")
    blocked = await TC.tcp("169.254.169.254", 49, 0.5)
    assert blocked["category"] == "blocked"


async def test_ldap_test_refuses_cleartext_and_blocked_hosts():
    from app.tacacs import client as TC
    steps = await TC.ldap_bind({"hosts": ["ldap://dc1.example.net"], "starttls": False}, "x", 1)
    assert steps[0]["category"] == "ldap_tls"
    steps = await TC.ldap_bind({"hosts": ["ldaps://169.254.169.254"]}, "x", 1)
    assert steps[0]["category"] == "blocked"


# ------------------------------------------------------------------ detections
async def test_detections_thresholds_and_dedup(db, ch):
    from app.alerts.engine import ensure_default_rules, run_rules
    ch.command("TRUNCATE TABLE tacacs_events")
    db.add(TacIdentitySource(id=1, name="local", kind="local"))
    db.add(TacUser(username="breakglass", source_id=1, emergency=True))
    db.add(TacUser(username="mallory", source_id=1, enabled=False))
    await db.commit()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    rows = []

    def ev(et, user, i, dev="10.20.0.11", log="authc", client_id=1):
        rows.append({"ts": now - timedelta(minutes=10) + timedelta(seconds=i), "server_id": 1, "log": log, "msgid": "X", "event_type": et, "result": "",
                     "username": user, "device_address": dev, "device_name": "d", "client_id": client_id, "vendor": "cisco", "site": "WH1", "port": "vty0",
                     "remote_addr": "10.99.0.5", "service": "shell", "priv_lvl": None, "profile": "", "rule": "", "server_address": "", "identity_source": "",
                     "action": "", "cmd": "", "cmd_category": "", "task_id": "", "session_id": "", "elapsed_s": None, "hint": "", "raw": "",
                     "fingerprint": f"{et}{user}{i}{dev}"})
    for i in range(6):
        ev("auth_failure", "carol", i)
    ev("auth_success", "carol", 20)
    for i in range(3):
        ev("auth_backend_error", "dave", 30 + i)
    ev("auth_success", "breakglass", 40)
    ev("auth_failure", "mallory", 41)
    ev("conn_reject", "", 42, dev="198.51.100.9", log="conn", client_id=0)
    await ch.ainsert("tacacs_events", rows, J.EVENT_COLS)
    await ensure_default_rules(db)
    for r in (await db.execute(select(AlertRule))).scalars():
        r.enabled = r.key.startswith("tacacs_")
    await db.commit()
    await run_rules(ch, db, now=now, correlate=False)
    got = {a.rule_key: a for a in (await db.execute(select(Alert))).scalars()}
    assert {"tacacs_auth_failures", "tacacs_success_after_failures", "tacacs_backend_failures", "tacacs_emergency_use", "tacacs_disabled_user",
            "tacacs_unknown_device"} <= set(got)
    assert got["tacacs_auth_failures"].evidence["observed"] == 6 and got["tacacs_auth_failures"].evidence["investigation"]
    assert "not wrong passwords" in got["tacacs_backend_failures"].explanation and got["tacacs_emergency_use"].severity == "critical"
    res = await run_rules(ch, db, now=now + timedelta(minutes=1), correlate=False)
    assert res["tacacs_auth_failures"]["created"] == 0  # same burst: no new alert


async def test_server_down_alert_resolves(db, ch):
    from app.alerts.engine import ensure_default_rules, run_rules
    srv = TacServer(name="tac1", kind="external", management_address="10.1.1.1", status="down", status_since=datetime.now(timezone.utc) - timedelta(minutes=10))
    db.add(srv)
    await ensure_default_rules(db)
    for r in (await db.execute(select(AlertRule))).scalars():
        r.enabled = r.key == "tacacs_server_down"
    await db.commit()
    await run_rules(ch, db, correlate=False)
    a = (await db.execute(select(Alert))).scalars().one()
    srv.status = "up"
    await db.commit()
    await run_rules(ch, db, correlate=False)
    await db.refresh(a)
    assert a.status == "resolved"


# ------------------------------------------------------------------ templates
def test_templates_never_contain_secrets_and_start_with_emergency_access():
    for vendor in ("fortinet", "cisco", "ruckus", "other"):
        t = template({"name": "d1", "address": "10.20.0.11", "vendor": vendor, "model": "", "firmware": ""}, "10.0.0.5", "10.0.0.6")
        assert "<SHARED-SECRET-FROM-SIEM>" in t["config"] and t["rollback"] and t["validation"]
        if vendor != "other":
            assert "Emergency access FIRST" in t["config"]
    assert "aaa authorization commands 15 default group SG-TACACS local if-authenticated" in template(
        {"name": "d", "address": "10.0.0.1", "vendor": "cisco"}, "10.0.0.5", None)["config"]


# ------------------------------------------------------------------ API
async def test_api_rbac_secrets_validation_and_workflow(api, db, ch):  # noqa: F811
    admin = await As.login(api, "admin1")
    analyst = await As.login(api, "analyst1")
    assert (await analyst.post("/api/tacacs/servers", json={"name": "tac1", "management_address": "tacacs"})).status_code == 403
    refused = (await db.execute(select(AuditLog).where(AuditLog.success.is_(False)))).scalars().all()
    assert refused and refused[0].action == "tacacs_server_create"
    assert (await admin.post("/api/tacacs/servers", json={"name": "tac1", "management_address": "169.254.169.254"})).status_code == 422
    sid = (await admin.post("/api/tacacs/servers", json={"name": "tac1", "management_address": "tacacs"})).json()["id"]
    assert (await admin.post("/api/tacacs/servers", json={"name": "tac2", "management_address": "tacacs2"})).status_code == 409  # one managed server
    body = {"name": "wh1-acc-sw01", "address": "10.20.0.11", "vendor": "cisco", "site": "WH1", "primary_server_id": sid}
    r = await admin.post("/api/tacacs/clients", json=body)
    assert r.status_code == 422 and "authorised client network" in r.text
    assert (await admin.put("/api/tacacs/settings", json={"client_networks": ["10.0.0.0/8"], "tester_address": "172.18.0.5"})).json()["tester_secret_set"]
    assert (await admin.put("/api/tacacs/settings", json={"client_networks": ["0.0.0.0/0"]})).status_code == 422
    r = await admin.post("/api/tacacs/clients", json=body)
    assert r.status_code == 201 and len(r.json()["shared_secret"]) >= 32
    secret, cid = r.json()["shared_secret"], r.json()["id"]
    lst = await analyst.get("/api/tacacs/clients")
    assert secret not in lst.text and lst.json()["items"][0]["has_secret"]
    assert (await admin.post("/api/tacacs/clients", json={**body, "name": "dup"})).status_code == 409  # same address
    assert (await admin.post("/api/tacacs/clients", json={**body, "name": "net", "address": "10.20.0.0/24"})).status_code == 409  # overlaps
    w = await admin.post("/api/tacacs/clients", json={**body, "name": "wide", "address": "10.40.0.0/24"})
    assert w.status_code == 422 and "justification" in w.text
    assert (await admin.post("/api/tacacs/clients", json={**body, "name": "wide", "address": "10.40.0.0/24",
                                                          "wide_cidr_justification": "lab range approved CHG-1234"})).json()["wide_cidr_approved_by"] == "admin1"
    rot = (await admin.post(f"/api/tacacs/clients/{cid}/rotate")).json()["shared_secret"]
    assert rot != secret and (await admin.post(f"/api/tacacs/clients/{cid}/rotate")).status_code == 409
    assert (await admin.post(f"/api/tacacs/clients/{cid}/rotate/complete")).json()["secret_version"] == 2
    assert "<SHARED-SECRET-FROM-SIEM>" in (await analyst.get(f"/api/tacacs/clients/{cid}/template")).json()["config"]
    src = (await admin.post("/api/tacacs/identity-sources", json={"name": "local", "kind": "local"})).json()["id"]
    assert (await admin.post("/api/tacacs/identity-sources", json={"name": "ad", "kind": "ad", "hosts": ["ldap://dc1.example.net"]})).status_code == 422
    ad = await admin.post("/api/tacacs/identity-sources", json={"name": "ad", "kind": "ad", "hosts": ["ldaps://dc1.example.net:636"], "base": "dc=example,dc=net",
                                                                "bind_dn": "cn=svc", "bind_password": "Bind-Secret-1"})
    assert ad.status_code == 201 and "Bind-Secret-1" not in ad.text and ad.json()["has_bind_password"]
    assert (await admin.post("/api/tacacs/users", json={"username": "carol", "source_id": src, "password": "short"})).status_code == 422
    u = await admin.post("/api/tacacs/users", json={"username": "carol", "source_id": src, "password": "Correct-Horse-Battery-1", "groups": ["netops"]})
    assert u.status_code == 201 and "Correct-Horse" not in u.text and u.json()["has_password"]
    assert (await db.execute(select(TacUser))).scalars().one().password_hash.startswith("$6$")
    assert (await admin.post("/api/tacacs/users", json={"username": "dir1", "source_id": ad.json()["id"], "password": "Correct-Horse-Battery-1"})).status_code == 422
    assert (await admin.post("/api/tacacs/roles/templates")).json()["added"]
    roles = (await analyst.get("/api/tacacs/roles")).json()["items"]
    eng = next(r for r in roles if r["name"] == "network-engineer")
    assert eng["explain"]["vendors"]["fortinet"]["enforcement"] == "profile-only"
    assert (await admin.post("/api/tacacs/mappings", json={"principal_type": "group", "principal": "netops", "role_id": eng["id"]})).status_code == 422
    assert (await admin.post("/api/tacacs/mappings", json={"principal_type": "group", "principal": "netops", "role_id": eng["id"],
                                                           "justification": "network engineering team"})).status_code == 201
    assert (await admin.post("/api/tacacs/command-rules", json={"role_id": eng["id"], "vendor": "cisco", "action": "deny", "pattern": "(?=x)"})).status_code == 422
    assert (await admin.post("/api/tacacs/command-rules", json={"role_id": eng["id"], "vendor": "cisco", "action": "permit", "pattern": "^debug ip ospf",
                                                                "exception": True})).status_code == 422
    sim = (await analyst.post("/api/tacacs/policy/simulate", json={"username": "carol", "client_id": cid, "commands": ["show version", "reload"]})).json()
    assert sim["exec"]["decision"] == "permit" and [x["decision"] for x in sim["commands"]] == ["permit", "deny"]
    assert (await analyst.get("/api/tacacs/config/preview")).status_code == 403
    pv = (await admin.get("/api/tacacs/config/preview")).json()
    assert "device wh1-acc-sw01" in pv["content"] and rot not in pv["content"] and "***" in pv["content"]
    ver = (await admin.post("/api/tacacs/config/versions", json={"message": "baseline"})).json()
    detail = await admin.get(f"/api/tacacs/config/versions/{ver['id']}")
    assert rot not in detail.text and "Bind-Secret-1" not in detail.text and "Correct-Horse" not in detail.text
    job = (await admin.post(f"/api/tacacs/config/versions/{ver['id']}/deploy", json={"server_id": sid})).json()
    assert job["status"] == "pending_approval"
    own = await admin.post(f"/api/tacacs/deployments/{job['id']}/decision", json={"decision": "approve", "approval_hash": job["approval_hash"]})
    assert own.status_code == 403 and "separation of duties" in own.text
    assert (await analyst.get("/api/tacacs/events")).status_code == 403
    assert (await admin.get("/api/tacacs/events", params={"range": "1h", "limit": 5})).status_code == 200
    assert (await admin.get("/api/tacacs/events/export.csv")).status_code == 200
    assert (await analyst.get("/api/tacacs/overview")).status_code == 200
    assert (await admin.post("/api/tacacs/tests/auth", json={"server_id": sid})).status_code == 422  # credentials needed
    t = (await admin.post("/api/tacacs/tests/tcp", json={"server_id": sid})).json()
    assert t["status"] == "failed" and t["steps"][0]["category"] in ("timeout", "refused", "dns")  # no tacacs host in the test environment
    users = (await admin.get("/api/tacacs/rbac")).json()["users"]
    a1 = next(x for x in users if x["username"] == "analyst1")
    assert (await analyst.put(f"/api/tacacs/rbac/{a1['id']}", json={"tacacs_roles": ["auditor"]})).status_code == 403
    assert (await admin.put(f"/api/tacacs/rbac/{a1['id']}", json={"tacacs_roles": ["auditor"]})).json()["tacacs_roles"] == ["auditor"]
    acts = {a.action for a in (await db.execute(select(AuditLog))).scalars()}
    assert {"tacacs_client_create", "tacacs_client_rotate_start", "tacacs_version_create", "tacacs_deploy_request", "tacacs_deploy_decision"} <= acts
    assert (await db.execute(select(TacRoleMapping))).scalars().one().justification
    assert (await db.execute(select(TacConfigVersion))).scalars().one().sha256 == ver["sha256"]
    assert (await db.execute(select(TacRole))).scalars().first() is not None
