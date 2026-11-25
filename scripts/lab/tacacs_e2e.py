#!/usr/bin/env python3
"""TACACS+ end-to-end validation against a LAB copy of the stack and the real tac_plus-ng (docs/TACACS.md, Testing).

Never point this at production: it creates users, a device client and configuration versions, and deploys them.
Path: browser-equivalent API calls through the web container (TLS verified against the lab certificate) → api →
PostgreSQL / approval → deploy agent (tac_plus-ng -P, activation) → live server; the testing center; a simulated Cisco
IOS device inside the worker container (scripts/lab/tacacs_device_sim.py) → log files → ingestion → explorer / sessions.

Every password and key is generated here and never printed; output is statuses and counts. --leaks writes the generated
values to a 0600 file so the containers' logs and stores can be scanned with `grep -F -f` afterwards (delete it after).
Requires: python3 with httpx; the docker CLI (or another compatible one via --docker); COMPOSE_PROFILES=tacacs in the lab.
"""
import argparse
import json
import os
import secrets
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument("--stack", required=True, help="the lab stack directory (its compose file, secrets/ and deploy/certs/siem.crt)")
ap.add_argument("--base", default="https://127.0.0.1:443", help="URL of the web container as reachable from here")
ap.add_argument("--host-header", default="", help="certificate name to verify and send as Host / SNI (default: the URL's host)")
ap.add_argument("--docker", default=os.environ.get("DOCKER", "docker"), help="container CLI with a compose subcommand")
ap.add_argument("--leaks", default="", help="write the generated secret values here (mode 0600) for a log scan")
args = ap.parse_args()
STACK = Path(args.stack).resolve()
SIM = Path(__file__).with_name("tacacs_device_sim.py")
BASE = args.base.rstrip("/")
HOST = args.host_header or httpx.URL(BASE).host
results: list[tuple[str, bool, str]] = []
leaks_to_check: list[str] = []


def compose(*a, **kw):
    return subprocess.run([args.docker, "compose", *a], cwd=STACK, capture_output=True, text=True, **kw)


def cid(service: str) -> str:
    out = compose("ps", "-q", service).stdout.split()
    if not out:
        sys.exit(f"service {service} is not running in {STACK}")
    return out[0]


def aaa(service: str) -> tuple[str, str]:
    """(address, subnet) of a service on the compose network named *_aaa."""
    nets = json.loads(subprocess.run([args.docker, "inspect", "-f", "{{json .NetworkSettings.Networks}}", cid(service)],
                                     capture_output=True, text=True, check=True).stdout)
    name = next((n for n in nets if n.endswith("_aaa")), None)
    if name is None:
        sys.exit(f"{service} is not on the aaa network")
    net = json.loads(subprocess.run([args.docker, "network", "inspect", name], capture_output=True, text=True, check=True).stdout)[0]
    subnets = [x.get("Subnet") or x.get("subnet") for x in (net.get("IPAM", {}).get("Config") or net.get("subnets") or [])]
    return nets[name]["IPAddress"], next(x for x in subnets if x and ":" not in x)


API_IP, AAA_SUBNET = aaa("api")
WORKER_IP, _ = aaa("worker")


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}{('  — ' + detail) if detail else ''}", flush=True)


class Session:
    def __init__(self, user, pw):
        self.c = httpx.Client(base_url=BASE, verify=str(STACK / "deploy/certs/siem.crt"), headers={"Host": HOST}, timeout=60)
        self.login(user, pw)

    def login(self, user, pw):
        r = self.c.post("/api/auth/login", json={"username": user, "password": pw}, extensions={"sni_hostname": HOST})
        r.raise_for_status()
        self.csrf = r.json()["csrf_token"]

    def req(self, method, path, **kw):
        r = self.c.request(method, path, headers={"x-csrf-token": self.csrf}, extensions={"sni_hostname": HOST}, **kw)
        return r

    def ok(self, method, path, **kw):
        r = self.req(method, path, **kw)
        if r.status_code >= 400:
            raise RuntimeError(f"{method} {path} → {r.status_code} {r.text[:300]}")
        return r.json()


admin_pw = (STACK / "secrets/bootstrap_admin_password").read_text().strip()
admin = Session("admin", admin_pw)
me = admin.ok("GET", "/api/auth/me")
uid = me.get("id") or me.get("user", {}).get("id")
admin.ok("PUT", f"/api/tacacs/rbac/{uid}", json={"tacacs_roles": ["auditor", "operator", "policy_admin", "approver"]})
admin.login("admin", admin_pw)  # role change revoked the session, by design

appr_pw = secrets.token_urlsafe(18)
users = {u["username"]: u for u in admin.ok("GET", "/api/users")}
if "approver1" not in users:
    users["approver1"] = admin.ok("POST", "/api/users", json={"username": "approver1", "password": appr_pw, "role": "analyst", "products": ["grid", "nms"]})
else:
    admin.ok("PATCH", f"/api/users/{users['approver1']['id']}", json={"password": appr_pw})
admin.ok("PUT", f"/api/tacacs/rbac/{users['approver1']['id']}", json={"tacacs_roles": ["approver"]})
approver = Session("approver1", appr_pw)

# --- settings, server, identity, roles, mappings, client --------------------------------------------------------------
# the aaa subnet as tester address: survives api container recreation; the worker's /32 (the lab device) is more specific
st = admin.ok("PUT", "/api/tacacs/settings", json={"client_networks": [AAA_SUBNET], "tester_address": AAA_SUBNET, "require_approval": True})
check("settings saved; tester key generated, not returned", st["tester_secret_set"] and not any("ciphertext" in k for k in st))
bad = admin.req("PUT", "/api/tacacs/settings", json={"client_networks": [AAA_SUBNET], "tester_address": "10.0.0.0/8"})
check("settings: too-wide tester subnet refused", bad.status_code == 422, bad.json().get("detail", ""))

servers = admin.ok("GET", "/api/tacacs/servers")["items"]
srv = next((s for s in servers if s["kind"] == "managed"), None) or admin.ok("POST", "/api/tacacs/servers", json={
    "name": "tacacs-lab", "kind": "managed", "management_address": "tacacs", "client_address": "127.0.0.1", "port": 49, "environment": "lab"})
for bad_body, why in (({"name": "x1", "kind": "external", "management_address": "", "port": 49}, "empty address"),
                      ({"name": "x2", "kind": "external", "management_address": "10.0.0.9", "port": 70000}, "port out of range"),
                      ({"name": "x3", "kind": "managed", "management_address": "tacacs2", "port": 49}, "second managed server")):
    r = admin.req("POST", "/api/tacacs/servers", json=bad_body)
    check(f"server validation: {why} refused", r.status_code in (409, 422), f"HTTP {r.status_code}")

srcs = {x["name"]: x for x in admin.ok("GET", "/api/tacacs/identity-sources")["items"]}
local = srcs.get("local") or admin.ok("POST", "/api/tacacs/identity-sources", json={"name": "local", "kind": "local"})
roles = {r["name"]: r for r in admin.ok("GET", "/api/tacacs/roles")["items"]}
if "network-engineer" not in roles:
    admin.ok("POST", "/api/tacacs/roles/templates")
    roles = {r["name"]: r for r in admin.ok("GET", "/api/tacacs/roles")["items"]}

pw = {k: secrets.token_urlsafe(15) for k in ("netops1", "viewer1", "olduser")}
leaks_to_check += list(pw.values()) + [appr_pw, admin_pw]
existing = {u["username"]: u for u in admin.ok("GET", "/api/tacacs/users")["items"]}
for name, groups, enabled in (("netops1", ["netops"], True), ("viewer1", [], True), ("olduser", [], False)):
    body = {"username": name, "source_id": local["id"], "groups": groups, "enabled": enabled, "password": pw[name],
            "disabled_reason": "" if enabled else "left the team"}
    if name in existing:
        admin.ok("PUT", f"/api/tacacs/users/{existing[name]['id']}", json=body)
    else:
        u = admin.ok("POST", "/api/tacacs/users", json=body)
        check(f"user {name}: password write-only", "password" not in u and u["has_password"])
r = admin.req("POST", "/api/tacacs/users", json={"username": "weak1", "source_id": local["id"], "password": "short"})
check("user validation: short password refused", r.status_code == 422, f"HTTP {r.status_code}")

maps = admin.ok("GET", "/api/tacacs/mappings")["items"]
if not maps:
    admin.ok("POST", "/api/tacacs/mappings", json={"principal_type": "group", "principal": "netops", "role_id": roles["network-engineer"]["id"],
                                                   "justification": "lab end-to-end test of the engineer role", "priority": 100})
    admin.ok("POST", "/api/tacacs/mappings", json={"principal_type": "user", "principal": "viewer1", "role_id": roles["network-read-only"]["id"], "priority": 100})
    admin.ok("POST", "/api/tacacs/mappings", json={"principal_type": "user", "principal": "olduser", "role_id": roles["network-read-only"]["id"], "priority": 100})
r = admin.req("POST", "/api/tacacs/mappings", json={"principal_type": "group", "principal": "x", "role_id": roles["network-administrator"]["id"]})
check("mapping validation: privileged role without justification refused", r.status_code == 422, f"HTTP {r.status_code}")

clients = {c["name"]: c for c in admin.ok("GET", "/api/tacacs/clients", params={"limit": 1000})["items"]}
if "lab-sw01" in clients:
    admin.ok("DELETE", f"/api/tacacs/clients/{clients['lab-sw01']['id']}")
created = admin.ok("POST", "/api/tacacs/clients", json={"name": "lab-sw01", "address": WORKER_IP, "vendor": "cisco", "site": "LAB",
                                                        "device_group": "access", "primary_server_id": srv["id"]})
device_key = created.pop("shared_secret")
leaks_to_check.append(device_key)
check("client created; shared secret returned once (32 chars)", len(device_key) == 32)
again = next(c for c in admin.ok("GET", "/api/tacacs/clients", params={"limit": 1000})["items"] if c["name"] == "lab-sw01")
check("client list never returns the secret", "shared_secret" not in again and device_key not in json.dumps(again) and again["has_secret"])
r = admin.req("POST", "/api/tacacs/clients", json={"name": "outside", "address": "192.0.2.10", "vendor": "cisco"})
check("client validation: address outside authorised networks refused", r.status_code == 422, r.json().get("detail", "")[:80])
r = admin.req("POST", "/api/tacacs/clients", json={"name": "bad name;", "address": WORKER_IP, "vendor": "cisco"})
check("client validation: bad identifier refused", r.status_code == 422, f"HTTP {r.status_code}")
tpl = admin.ok("GET", f"/api/tacacs/clients/{created['id']}/template")
check("device template contains no secret", device_key not in json.dumps(tpl))

# --- configuration studio → approval → agent → live server ------------------------------------------------------------
prev = admin.ok("GET", "/api/tacacs/config/preview")
check("preview is redacted", device_key not in json.dumps(prev) and not any(p in json.dumps(prev) for p in pw.values()))
v = admin.ok("POST", "/api/tacacs/config/versions", json={"message": f"e2e {int(time.time())}"})
vd = admin.ok("GET", f"/api/tacacs/config/versions/{v['id']}")
check("stored version text is redacted", device_key not in vd["content"] and "***" in vd["content"])


def wait_job(jid, timeout=150):
    t0 = time.time()
    while time.time() - t0 < timeout:
        j = next(x for x in admin.ok("GET", "/api/tacacs/deployments")["items"] if x["id"] == jid)
        if j["status"] not in ("queued", "running", "pending_approval"):
            return j
        time.sleep(3)
    return j


j = admin.ok("POST", f"/api/tacacs/config/versions/{v['id']}/deploy", json={"server_id": srv["id"], "action": "validate", "comment": "e2e validate"})
if j["status"] == "pending_approval":
    r = admin.req("POST", f"/api/tacacs/deployments/{j['id']}/decision", json={"decision": "approve", "approval_hash": j["approval_hash"]})
    check("separation of duties: requester cannot approve", r.status_code == 403, f"HTTP {r.status_code}")
    j = approver.ok("POST", f"/api/tacacs/deployments/{j['id']}/decision", json={"decision": "approve", "approval_hash": j["approval_hash"]})
j = wait_job(j["id"])
check("validation job: real tac_plus-ng -P accepted the version", j["status"] == "succeeded", f"{j['status']} {json.dumps(j.get('result'))[:200]}")
j = admin.ok("POST", f"/api/tacacs/config/versions/{v['id']}/deploy", json={"server_id": srv["id"], "action": "deploy", "comment": "e2e deploy"})
r = approver.req("POST", f"/api/tacacs/deployments/{j['id']}/decision", json={"decision": "approve", "approval_hash": "0" * 64})
check("replayed / wrong approval hash refused", r.status_code in (403, 409, 422), f"HTTP {r.status_code}")
if r.status_code < 400 or next(x for x in admin.ok("GET", "/api/tacacs/deployments")["items"] if x["id"] == j["id"])["status"] == "cancelled":
    j = admin.ok("POST", f"/api/tacacs/config/versions/{v['id']}/deploy", json={"server_id": srv["id"], "action": "deploy", "comment": "e2e deploy"})
j = approver.ok("POST", f"/api/tacacs/deployments/{j['id']}/decision", json={"decision": "approve", "approval_hash": j["approval_hash"]})
j = wait_job(j["id"])
check("deployment job: agent validated, activated and health-checked", j["status"] == "succeeded", f"{j['status']} {json.dumps(j.get('result'))[:200]}")
srv = next(x for x in admin.ok("GET", "/api/tacacs/servers")["items"] if x["id"] == srv["id"])
check("server records the deployed version", srv["deployed_version_id"] == v["id"])
active_sha = compose("exec", "-T", "tacacs", "sha256sum", "/tacacs/config/active/tac_plus-ng.cfg").stdout.split()[0]
check("live configuration on the server equals the committed version", active_sha == v["sha256"])
left = compose("exec", "-T", "tacacs", "sh", "-c", "ls /tacacs/config/candidates /tacacs/config/requests").stdout.split()
check("no candidate (with secrets) or request left on the shared volume", not [x for x in left if x.endswith((".cfg", ".json", ".tmp"))], " ".join(left))

# --- health -------------------------------------------------------------------------------------------------------------
h = admin.ok("POST", f"/api/tacacs/servers/{srv['id']}/check")
check("server health check: TCP/49 and agent", h["status"] == "up" and h["tcp_ok"] and h["agent_ok"], f"{h['status']} {h.get('detail', '')}")

# --- testing center (api → tac_plus-ng as the tester device) ------------------------------------------------------------
t = admin.ok("POST", "/api/tacacs/tests/tcp", json={"server_id": srv["id"]})
check("test center: TCP/49", t["status"] == "passed", t["steps"][0]["detail"])
time.sleep(13)  # the auth-test rate limit is 5/min; space them out
t = admin.ok("POST", "/api/tacacs/tests/auth", json={"server_id": srv["id"], "username": "netops1", "password": pw["netops1"]})
check("test center: valid credentials → PASS, server log correlated", t["status"] == "passed", " | ".join(s["detail"] for s in t["steps"]))
t = admin.ok("POST", "/api/tacacs/tests/auth", json={"server_id": srv["id"], "username": "netops1", "password": pw["netops1"] + "x"})
check("test center: wrong password → failed, auth_reject", t["status"] == "failed" and t["category"] == "auth_reject", f"{t['category']} | " + " | ".join(s["detail"] for s in t["steps"]))
t = admin.ok("POST", "/api/tacacs/tests/auth", json={"server_id": srv["id"], "username": "ghost", "password": "Whatever-Password-1"})
check("test center: unknown user → failed", t["status"] == "failed", f"{t['category']} | " + " | ".join(s["detail"] for s in t["steps"]))
t = admin.ok("POST", "/api/tacacs/tests/auth", json={"server_id": srv["id"], "username": "olduser", "password": pw["olduser"]})
check("test center: disabled user → failed", t["status"] == "failed", f"{t['category']} | " + " | ".join(s["detail"] for s in t["steps"]))
t = admin.ok("POST", "/api/tacacs/tests/accounting", json={"server_id": srv["id"]})
check("test center: accounting round trip ingested", t["status"] == "passed", " | ".join(s["detail"] for s in t["steps"]))
hist = admin.ok("GET", "/api/tacacs/tests")
check("test history stores no password", not any(p in json.dumps(hist) for p in pw.values()))

# --- a device (Cisco IOS simulated in the worker container) -------------------------------------------------------------
canary = "Canary" + secrets.token_hex(6)
leaks_to_check.append(canary)
task = int(time.time()) % 100000 * 10
sim_in = json.dumps({"host": "tacacs", "key": device_key, "wrong_key": secrets.token_urlsafe(24), "users": pw, "task": task, "canary": canary})
sim_start = datetime.now(timezone.utc).isoformat()
subprocess.run([args.docker, "cp", str(SIM), f"{cid('worker')}:/tmp/device_sim.py"], check=True, capture_output=True)
p = compose("exec", "-T", "worker", "python3", "/tmp/device_sim.py", input=sim_in, timeout=120)
dev = json.loads(p.stdout.strip().splitlines()[-1])
expect = {
    "authn engineer good password (PAP)": lambda v: v == "PASS",
    "authn engineer good password (ASCII login)": lambda v: v in ("PASS", "status 5"),  # ASCII is interactive: GETUSER/GETPASS exchange
    "authn engineer wrong password": lambda v: v == "FAIL",
    "authn unknown user": lambda v: v == "FAIL",
    "authn disabled user": lambda v: v == "FAIL",
    "authn read-only good password": lambda v: v == "PASS",
    "authn wrong shared secret": lambda v: v != "PASS",  # the device cannot decode the reply: never a pass
    "authz engineer exec": lambda v: v.startswith("PASS") and "priv-lvl=15" in v,
    "authz engineer 'show version'": lambda v: v.startswith("PASS"),
    "authz engineer 'configure terminal'": lambda v: v.startswith("PASS"),
    "authz engineer 'reload'": lambda v: v.startswith("FAIL"),
    "authz read-only exec": lambda v: v.startswith("PASS"),
    "authz read-only 'show ip route'": lambda v: v.startswith("PASS"),
    "authz read-only 'configure terminal'": lambda v: v.startswith("FAIL"),
    "authz unknown user exec": lambda v: v.startswith("FAIL"),
    "acct exec start": lambda v: v == "SUCCESS", "acct command": lambda v: v == "SUCCESS", "acct command with secret": lambda v: v == "SUCCESS",
    "acct exec stop": lambda v: v == "SUCCESS",
}
for k, f in expect.items():
    check(f"device: {k}", f(dev.get(k, "missing")), dev.get(k, "missing"))

# --- ingestion → API → what the UI shows --------------------------------------------------------------------------------
time.sleep(25)
ev = admin.ok("GET", "/api/tacacs/events", params={"range": "1h", "user": "netops1", "limit": 200})
items = ev["items"]
kinds = {(e.get("log"), e.get("event_type")) for e in items}
check("events: authentication success and failure ingested", any(e.get("event_type") == "auth_success" for e in items) and any(e.get("event_type") == "auth_failure" for e in items), str(sorted(kinds))[:300])
check("events: authorization deny for 'reload' ingested", any(e.get("log") == "authz" and "reload" in (e.get("cmd") or "") and e.get("result") in ("deny", "fail") for e in items),
      str([(e.get("log"), e.get("result"), e.get("cmd")) for e in items if e.get("log") == "authz"])[:300])
check("events: device name is the registered client (not the server's hostname)", items and all(e.get("device_name") == "lab-sw01" and e.get("site") == "LAB" and e.get("vendor") == "cisco" for e in items if e.get("log") in ("authc", "authz", "acct") and e.get("ts", "") >= sim_start and e.get("remote_addr") == "192.0.2.50"), str({(e.get("device_name"), e.get("site")) for e in items})[:200])
acct_cmd = [e for e in items if e.get("log") == "acct" and "username bob" in (e.get("cmd") or "")]
check("accounting: secret in a command redacted before storage", acct_cmd and canary not in json.dumps(ev), (acct_cmd[0]["cmd"] if acct_cmd else "no record"))
page2 = admin.ok("GET", "/api/tacacs/events", params={"range": "1h", "user": "netops1", "limit": 2, "offset": 2})
check("events: pagination", len(page2["items"]) <= 2 and page2["total"] == ev["total"], f"total {ev['total']}")
csv = admin.req("GET", "/api/tacacs/events/export.csv", params={"range": "1h", "user": "netops1"})
check("events: CSV export", csv.status_code == 200 and "netops1" in csv.text and canary not in csv.text, f"{len(csv.text.splitlines())} lines")
se = admin.ok("GET", "/api/tacacs/sessions", params={"range": "1h"})
mine = [x for x in se["items"] if x.get("username") == "netops1" and str(task) == str(x.get("task_id"))]
check("sessions: exec start/stop reconstructed", mine and mine[0].get("state") == "closed", json.dumps(mine[:1])[:300])
ov = admin.ok("GET", "/api/tacacs/overview", params={"range": "1h"})
check("overview counts", ov["totals"]["auth_success"] >= 2 and ov["totals"]["auth_failure"] >= 2, json.dumps(ov["totals"])[:300])
dev_unknown = admin.ok("GET", "/api/tacacs/events", params={"range": "1h", "log": "conn", "limit": 500})["items"]
check("SIEM's own probes are not unknown devices", not [e for e in dev_unknown if e.get("event_type") == "conn_unknown_device" and e.get("device_address") in (API_IP, WORKER_IP)])

# --- RBAC -----------------------------------------------------------------------------------------------------------------
for path, method, body in (("/api/tacacs/clients", "POST", {"name": "rbac-probe", "address": WORKER_IP, "vendor": "cisco"}),
                           ("/api/tacacs/settings", "PUT", {"client_networks": [AAA_SUBNET]}), ("/api/tacacs/events", "GET", None)):
    r = approver.req(method, path, json=body)
    check(f"RBAC: approver-only user refused {method} {path}", r.status_code == 403, f"HTTP {r.status_code}")

if args.leaks:
    fd = os.open(args.leaks, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(leaks_to_check) + "\n")
    print(f"{len(leaks_to_check)} generated values written to {args.leaks} (0600) for the log scan; delete it afterwards")
failed = [n for n, ok, _ in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
sys.exit(1 if failed else 0)
