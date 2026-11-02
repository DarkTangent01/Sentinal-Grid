"""IaC security validation and the configurable rule catalogue (security rules for desired state, drift rules for
classifying differences). Severity, enablement, deployment blocking and parameters live in iac_rules; organisation
exceptions (owner, justification, expiry) in iac_exceptions. Findings never modify the desired configuration."""
from __future__ import annotations

import fnmatch
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import IacException, IacRule
from ..policy.model import normalize_policy
from ..policy.shadow import analyze as shadow_analyze
from .resources import canonical_hash, to_cmdb

PREDEFINED_ADDR = {"all", "none", "login.microsoftonline.com", "FABRIC_DEVICE", "FIREWALL_AUTH_PORTAL_ADDRESS", "SSLVPN_TUNNEL_ADDR1"}
PREDEFINED_SVC = {"ALL", "ALL_TCP", "ALL_UDP", "ALL_ICMP", "ALL_ICMP6", "HTTP", "HTTPS", "DNS", "NTP", "SSH", "SMTP", "SMTPS", "IMAP",
                  "IMAPS", "POP3", "POP3S", "FTP", "RDP", "SNMP", "PING", "TELNET", "SAMBA", "LDAP", "KERBEROS", "Web Access",
                  "Email Access", "Windows AD", "Exchange Server", "GRE", "AH", "ESP", "IKE", "DHCP", "SYSLOG", "TRACEROUTE"}
# factory-default definitions of common predefined services, for shadow analysis when the device was not read
BUILTIN_SVC = {"ALL": {"protocol": "IP", "protocol_number": 0}, "HTTP": {"protocol": "TCP/UDP/SCTP", "tcp": ["80"]},
               "HTTPS": {"protocol": "TCP/UDP/SCTP", "tcp": ["443"]}, "SSH": {"protocol": "TCP/UDP/SCTP", "tcp": ["22"]},
               "DNS": {"protocol": "TCP/UDP/SCTP", "tcp": ["53"], "udp": ["53"]}, "NTP": {"protocol": "TCP/UDP/SCTP", "udp": ["123"]},
               "RDP": {"protocol": "TCP/UDP/SCTP", "tcp": ["3389"]}, "SMTP": {"protocol": "TCP/UDP/SCTP", "tcp": ["25"]}}
PREDEFINED_INTF = {"any"}
PREDEFINED_SCHED = {"always", "none"}

DEFAULT_RULES = [
    # security rules on the desired state
    ("IAC-SEC-001", "security", "Overly permissive policy: any source to any destination", "high", True, {"environments_blocking": ["production"]},
     "Restrict srcaddr / dstaddr to the networks that need the access."),
    ("IAC-SEC-002", "security", "Unrestricted service (ALL) on an accept policy", "medium", False, {},
     "List the services the application needs instead of ALL."),
    ("IAC-SEC-003", "security", "Accept policy without traffic logging", "medium", False, {},
     "Set logtraffic: all (or utm) so the SIEM sees the traffic this policy allows."),
    ("IAC-SEC-004", "security", "Insecure administrative access setting", "high", True, {},
     "Keep admin-telnet disabled, strong-crypto and admin-https-redirect enabled."),
    ("IAC-SEC-005", "security", "Weak administrative session / lockout baseline", "low", False, {"max_admintimeout": 30, "max_lockout_threshold": 5},
     "Use an admin timeout of 30 minutes or less and lock out after 5 or fewer failures."),
    ("IAC-SEC-006", "security", "Invalid object reference", "high", True, {},
     "Declare the referenced object, or reference one that exists on the device."),
    ("IAC-SEC-007", "security", "Potentially shadowed or redundant policy (analysis)", "medium", False, {},
     "Confirm with policy lookup and hit counters before reordering or removing; this is static analysis, not proof."),
    ("IAC-SEC-008", "security", "Unused (unreferenced) declared object", "info", False, {},
     "Remove the object from the desired state if nothing uses it."),
    ("IAC-SEC-009", "security", "Default route added, changed or removed", "high", False, {},
     "Confirm the change window and an out-of-band path before changing the default route."),
    ("IAC-SEC-010", "security", "Risky NAT change", "medium", False, {},
     "Verify source NAT for the affected policy; NAT changes alter the address the internet sees."),
    ("IAC-SEC-011", "security", "Security logging disabled", "high", True, {},
     "Keep syslog forwarding enabled so the SIEM keeps receiving logs."),
    ("IAC-SEC-012", "security", "Required organisational control missing", "medium", False,
     {"required": {"system_global.strong-crypto": "enable", "syslog.status": "enable"}},
     "Declare the required settings in the desired state."),
    ("IAC-SEC-013", "security", "Deployment would overwrite unapproved live changes", "medium", False, {},
     "Review the drift first: the device was changed outside IaC since the last check."),
    ("IAC-SEC-014", "security", "Deleting an object still in use on the device", "high", True, {},
     "Remove the object's users first, or stop pruning it."),
    # drift / plan classification rules (severity defaults live in diff.classify; these rows let operators override them)
    ("DRIFT-POLICY-ADDED", "drift", "Unexpected or new firewall policy", "high", False, {}, "Review who added the policy and why."),
    ("DRIFT-POLICY-DELETED", "drift", "Firewall policy deleted", "high", False, {}, ""),
    ("DRIFT-POLICY-ORDER", "drift", "Policy order changed", "medium", False, {}, ""),
    ("DRIFT-POLICY-ACTION", "drift", "Policy action changed", "high", False, {}, ""),
    ("DRIFT-POLICY-STATUS", "drift", "Policy enabled / disabled", "high", False, {}, ""),
    ("DRIFT-POLICY-MATCH", "drift", "Policy sources, destinations, services, schedule or interfaces changed", "medium", False, {}, ""),
    ("DRIFT-POLICY-NAT", "drift", "Policy NAT changed", "medium", False, {}, ""),
    ("DRIFT-POLICY-LOG", "drift", "Policy logging changed", "medium", False, {}, ""),
    ("DRIFT-POLICY-META", "drift", "Policy name / comments changed", "info", False, {}, ""),
    ("DRIFT-ROUTE", "drift", "Static route changed", "high", False, {}, ""),
    ("DRIFT-ADMIN", "drift", "Administrative access settings changed", "critical", False, {}, ""),
    ("DRIFT-LOGGING", "drift", "Syslog settings changed", "high", False, {}, ""),
    ("DRIFT-OBJECT-ADDED", "drift", "Object added", "low", False, {}, ""),
    ("DRIFT-OBJECT-DELETED", "drift", "Object deleted", "medium", False, {}, ""),
    ("DRIFT-OBJECT-MODIFIED", "drift", "Object modified", "medium", False, {}, ""),
]
SEV_ORDER = ["info", "low", "medium", "high", "critical"]


async def ensure_rules(s: AsyncSession) -> None:
    have = {r.rule_id for r in (await s.execute(select(IacRule))).scalars()}
    for rid, fam, title, sev, block, params, rem in DEFAULT_RULES:
        if rid not in have:
            s.add(IacRule(rule_id=rid, family=fam, title=title, severity=sev, blocks_deploy=block, params=params, remediation=rem))
    await s.commit()


async def load_ruleset(s: AsyncSession, project_id: int | None = None) -> dict:
    await ensure_rules(s)
    rules = {r.rule_id: r for r in (await s.execute(select(IacRule))).scalars()}
    now = datetime.now(timezone.utc)
    exc = [e for e in (await s.execute(select(IacException))).scalars()
           if (e.expires_at if e.expires_at.tzinfo else e.expires_at.replace(tzinfo=timezone.utc)) > now
           and (e.project_id in (None, project_id))]
    fingerprint = canonical_hash({"rules": [(r.rule_id, r.severity, r.blocks_deploy, r.enabled, r.params) for r in rules.values()],
                                  "exceptions": [(e.id, e.rule_id, e.project_id, e.firewall_id, e.resource, str(e.expires_at)) for e in exc]})
    return {"rules": rules, "exceptions": exc, "hash": fingerprint,
            "overrides": {k: r.severity for k, r in rules.items() if r.family == "drift"}}


def _excepted(rs: dict, rule_id: str, firewall_id: int | None, resource: str) -> IacException | None:
    for e in rs["exceptions"]:
        if e.rule_id == rule_id and (e.firewall_id in (None, firewall_id)) and fnmatch.fnmatchcase(resource, e.resource or "*"):
            return e
    return None


def finding(rs: dict, rule_id: str, resource: str, evidence: dict, explanation: str, environment: str,
            firewall_id: int | None = None, firewall_name: str = "") -> dict | None:
    r = rs["rules"].get(rule_id)
    if r is None or not r.enabled:
        return None
    blocks = bool(r.blocks_deploy)
    envs = (r.params or {}).get("environments_blocking")
    if envs is not None:
        blocks = blocks and environment in envs
    exc = _excepted(rs, rule_id, firewall_id, resource)
    return {"rule_id": rule_id, "title": r.title, "severity": r.severity, "firewall_id": firewall_id, "firewall_name": firewall_name,
            "resource": resource, "evidence": evidence, "explanation": explanation, "remediation": r.remediation,
            "blocks": blocks and exc is None,
            "exception": {"id": exc.id, "owner": exc.owner, "justification": exc.justification, "expires_at": exc.expires_at.isoformat()} if exc else None}


def evaluate(rs: dict, desired: dict, order: list[str], environment: str, *, observed: dict | None = None,
             refs: dict | None = None, firewall_id: int | None = None, firewall_name: str = "") -> list[dict]:
    """Security findings for one rendered desired state. `observed` / `refs` (live objects, interfaces, zones,
    schedules) make reference checks definitive; without them unknown names are reported as unresolved."""
    out: list[dict] = []

    def add(rid, res, ev, why):
        f = finding(rs, rid, res, ev, why, environment, firewall_id, firewall_name)
        if f:
            out.append(f)

    obs = observed or {}
    refs = refs or {}
    addr_names = set(desired.get("address", {})) | set(desired.get("address_group", {})) | set((obs.get("address") or {})) \
        | set((obs.get("address_group") or {})) | PREDEFINED_ADDR
    svc_names = set(desired.get("service", {})) | set(desired.get("service_group", {})) | set((obs.get("service") or {})) \
        | set((obs.get("service_group") or {})) | PREDEFINED_SVC
    intf_names = set(refs.get("interface", [])) | set(refs.get("zone", [])) | PREDEFINED_INTF
    sched_names = set(refs.get("schedule", [])) | PREDEFINED_SCHED
    definitive = observed is not None

    def check_ref(kind, name, pool, resource):
        if name in pool:
            return
        add("IAC-SEC-006", resource, {"missing": name, "kind": kind, "checked_against_device": definitive},
            f"{resource} references {kind} '{name}', which is not declared" + (" and does not exist on the device." if definitive
                                                                               else " (not yet checked against a device)."))

    for g, (pool, kind) in (("address_group", (addr_names, "address")), ("service_group", (svc_names, "service"))):
        for name, o in (desired.get(g) or {}).items():
            for m in o.get("members", []):
                check_ref(kind, m, pool, f"{g}:{name}")
    used_addr, used_svc = set(), set()
    for g in ("address_group",):
        for o in (desired.get(g) or {}).values():
            used_addr |= set(o.get("members", []))
    for o in (desired.get("service_group") or {}).values():
        used_svc |= set(o.get("members", []))
    for pid, p in (desired.get("policy") or {}).items():
        res = f"policy:{pid}"
        for f in ("srcaddr", "dstaddr"):
            for a in p.get(f, []):
                check_ref("address", a, addr_names, res)
                used_addr.add(a)
        for x in p.get("service", []):
            check_ref("service", x, svc_names, res)
            used_svc.add(x)
        if definitive:
            for f in ("srcintf", "dstintf"):
                for i in p.get(f, []):
                    check_ref("interface/zone", i, intf_names, res)
            check_ref("schedule", p.get("schedule", "always"), sched_names, res)
        if p.get("action") == "accept" and p.get("status", "enable") == "enable":
            if "all" in p.get("srcaddr", []) and "all" in p.get("dstaddr", []):
                add("IAC-SEC-001", res, {"srcaddr": p["srcaddr"], "dstaddr": p["dstaddr"]},
                    f"policy {pid} '{p.get('name', '')}' accepts traffic from any source to any destination")
            if "ALL" in p.get("service", []):
                add("IAC-SEC-002", res, {"service": p["service"]}, f"policy {pid} accepts every service")
            if p.get("logtraffic") == "disable":
                add("IAC-SEC-003", res, {"logtraffic": "disable"}, f"policy {pid} accepts traffic without logging it")
            if p.get("nat") == "enable" and "all" in p.get("dstaddr", []) and "all" in p.get("srcaddr", []):
                add("IAC-SEC-010", res, {"nat": "enable"}, f"policy {pid} source-NATs any source to any destination")
    for t, used in (("address", used_addr), ("service", used_svc)):
        for name in (desired.get(t) or {}):
            if name not in used:
                add("IAC-SEC-008", f"{t}:{name}", {}, f"{t} '{name}' is declared but no declared policy or group uses it")
    g = (desired.get("system_global") or {}).get("") or {}
    bad = {k: v for k, v in g.items() if (k == "admin-telnet" and v == "enable") or (k in ("strong-crypto", "admin-https-redirect") and v == "disable")}
    if bad:
        add("IAC-SEC-004", "system_global", bad, "insecure administrative access: " + ", ".join(f"{k}={v}" for k, v in bad.items()))
    p5 = (rs["rules"].get("IAC-SEC-005").params if rs["rules"].get("IAC-SEC-005") else {}) or {}
    if g.get("admintimeout") and g["admintimeout"] > p5.get("max_admintimeout", 30):
        add("IAC-SEC-005", "system_global", {"admintimeout": g["admintimeout"]}, f"admin sessions stay open {g['admintimeout']} minutes")
    if g.get("admin-lockout-threshold") and g["admin-lockout-threshold"] > p5.get("max_lockout_threshold", 5):
        add("IAC-SEC-005", "system_global", {"admin-lockout-threshold": g["admin-lockout-threshold"]}, "admin lockout allows many failed logins")
    sl = (desired.get("syslog") or {}).get("") or {}
    if sl.get("status") == "disable":
        add("IAC-SEC-011", "syslog", {"status": "disable"}, "syslog forwarding would be disabled; the SIEM stops receiving logs from this firewall")
    req = ((rs["rules"].get("IAC-SEC-012").params if rs["rules"].get("IAC-SEC-012") else {}) or {}).get("required", {})
    for path, want in req.items():
        t, _, k = path.partition(".")
        have = ((desired.get(t) or {}).get("") or {}).get(k)
        if have != want:
            add("IAC-SEC-012", path, {"required": want, "declared": have}, f"{path} must be declared as '{want}'")
    # shadow / redundancy: reuse the policy-analytics engine on the declared policies (desired order)
    pols = desired.get("policy") or {}
    if len(pols) > 1:
        def merged(t):  # declared objects win over the device's copy; device objects fill in the rest
            return {**(obs.get(t) or {}), **(desired.get(t) or {})}
        svc = {**{k: v for k, v in BUILTIN_SVC.items()}, **merged("service")}
        objs = {"address": [to_cmdb("address", k, v) for k, v in {"all": {"type": "ipmask", "subnet": "0.0.0.0/0"}, **merged("address")}.items()],
                "addrgrp": [to_cmdb("address_group", k, v) for k, v in merged("address_group").items()],
                "service_custom": [to_cmdb("service", k, v) for k, v in svc.items()],
                "service_group": [to_cmdb("service_group", k, v) for k, v in merged("service_group").items()]}
        # Internet Service (ISDB) policies match on database entries the analyzer cannot evaluate; leaving them out can
        # only hide a shadow finding, never invent one
        seq = [k for k in ([k for k in order if k in pols] or sorted(pols, key=int)) if pols[k].get("internet_service") != "enable"]
        norm = [normalize_policy(to_cmdb("policy", k, pols[k]), i) for i, k in enumerate(seq)]
        try:
            res = shadow_analyze(norm, objs)
        except Exception as e:  # analysis must never block validation by crashing
            res = {"findings": [], "error": str(e)}
        for f in res.get("findings", []):
            if f["classification"] in ("full_shadow", "redundant"):
                add("IAC-SEC-007", f"policy:{f['later_policyid']}",
                    {"earlier_policy": f["earlier_policyid"], "classification": f["classification"], "confidence": f["confidence"],
                     "assumptions": f["assumptions"][:5]},
                    f"policy {f['later_policyid']} may never match: {f['explanation']} (confidence {f['confidence']})")
    return out


def plan_findings(rs: dict, changes: list[dict], observed: dict, environment: str, firewall_id: int, firewall_name: str,
                  drift_status: str) -> list[dict]:
    """Findings that depend on the change itself (default routes, NAT changes, deletes of in-use objects, drift)."""
    out = []

    def add(rid, res, ev, why):
        f = finding(rs, rid, res, ev, why, environment, firewall_id, firewall_name)
        if f:
            out.append(f)

    deleting = {(c["type"], c["key"]) for c in changes if c["action"] == "delete"}
    for c in changes:
        res = f"{c['type']}:{c['key']}"
        if c["type"] == "static_route":
            dst = (c.get("desired") or c.get("current") or {}).get("dst")
            if dst in ("0.0.0.0/0", "::/0"):
                add("IAC-SEC-009", res, {"action": c["action"], "current": c.get("current"), "desired": c.get("desired")},
                    f"default route {c['action']}")
        if c["type"] == "policy" and c["action"] == "update" and any(f["field"] == "nat" for f in c.get("fields", [])):
            add("IAC-SEC-010", res, {"fields": c["fields"]}, f"NAT changes on existing policy {c['key']}")
        if c["action"] == "delete" and c["type"] in ("address", "address_group", "service", "service_group"):
            users = []
            for t, field_names in (("policy", ("srcaddr", "dstaddr", "service")), ("address_group", ("members",)), ("service_group", ("members",))):
                for k, o in (observed.get(t) or {}).items():
                    if (t, k) in deleting:
                        continue
                    if any(c["key"] in (o.get(f) or []) for f in field_names):
                        users.append(f"{t}:{k}")
            if users:
                add("IAC-SEC-014", res, {"used_by": users[:20]}, f"{c['type']} '{c['key']}' is still used by {', '.join(users[:5])}")
    if drift_status == "drift" and changes:
        add("IAC-SEC-013", "device", {}, "the device has unapproved live changes; this plan will overwrite some of them")
    return out


def worst(findings: list[dict]) -> str:
    return max((f["severity"] for f in findings), key=lambda s: SEV_ORDER.index(s), default="info")
