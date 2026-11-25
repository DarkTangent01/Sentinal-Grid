"""Network compliance checks.

Each check reads only data Sentinel has already collected:
  * the masked running configuration from the read-only SSH backup (switches, routers, WLCs: Cisco IOS / IOS-XE,
    Juniper Junos in "display set" form, Ruckus ICX);
  * the read-only FortiGate configuration snapshot (drift collection: interfaces, administrators, global settings,
    SSL-VPN settings, firewall policies) and the BGP configuration audit;
  * telemetry: SNMP polling state and credential, TACACS+ authentications and accounting, syslog arrival.
Nothing here contacts a device or changes one. A suggested CLI fix is text for an engineer to review and apply.

Result statuses:
  pass            the evidence shows the requirement is met
  fail            the evidence shows it is not met
  not_evaluated   the evidence needed is missing (the reason says what to collect): never counted as pass or fail
  not_applicable  the check does not apply to this device (vendor, type or role); not stored
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable

CATALOG_VERSION = "1.0"
CONFIG_VENDORS = ("cisco", "juniper", "ruckus")


@dataclass
class Ctx:
    """Everything known about one device, assembled by engine.py."""
    kind: str                                   # switch (switches, routers, WLCs from the NMS inventory) | firewall (FortiGate)
    id: int
    name: str
    now: datetime
    vendor: str = ""
    device_type: str = ""
    role: str = ""
    site: str = ""
    address: str = ""
    model: str = ""
    firmware: str = ""
    fleet_firmware: dict = field(default_factory=dict)   # {firmware: count} of devices of the same kind and model
    # configuration (switch kind)
    config: str | None = None
    config_at: datetime | None = None           # last successful backup (the text is stored only when it changed)
    backup_assigned: bool = False
    backup_error: str = ""
    # monitoring
    monitoring: str = "active"
    last_success_at: datetime | None = None
    snmp_version: str | None = None             # polling credential: v3 | v2c | None (no credential)
    snmp_priv: bool | None = None
    # TACACS+
    tacacs: dict | None = None                  # {"enabled", "last_auth", "last_accounting"} when the device is a TACACS+ client
    # syslog
    syslog_at: datetime | None = None           # last log received from this device (exact)
    syslog_note: str = ""                       # how the syslog evidence was found / why there is none
    # FortiGate
    fg: dict | None = None                      # latest snapshot data {interface, admin, global, sslvpn, policy}
    fg_errors: dict = field(default_factory=dict)
    fg_at: datetime | None = None
    bgp_audit: list | None = None               # None: BGP configuration not read

    def lines(self) -> list[str]:
        return (self.config or "").splitlines()


@dataclass
class R:
    status: str
    evidence: str
    lines: list[str] = field(default_factory=list)


@dataclass
class Check:
    id: str
    title: str
    severity: str                               # high | medium | low
    kinds: tuple[str, ...]
    category: str
    rationale: str
    refs: dict[str, list[str]]                  # framework → control ids (frameworks.py)
    evaluate: Callable[[Ctx], R | None]
    fix: dict[str, str] = field(default_factory=dict)   # vendor → suggested CLI (review before applying)
    source: str = "config"                      # config | telemetry | config+telemetry | snapshot


# ------------------------------------------------------------------ helpers
def ago(now: datetime, t: datetime | None) -> str:
    if not t:
        return "never"
    s = (now - t).total_seconds()
    return f"{int(s // 60)} min ago" if s < 3600 else f"{int(s // 3600)} h ago" if s < 172800 else f"{int(s // 86400)} days ago"


def grep(ctx: Ctx, rx: str) -> list[str]:
    r = re.compile(rx, re.I)
    return [ln.strip() for ln in ctx.lines() if r.search(ln)]


def sections(ctx: Ctx, header: str) -> list[tuple[str, list[str]]]:
    """Indented blocks (Cisco / Ruckus): [(header line, child lines)]."""
    r, out, cur = re.compile(header, re.I), [], None
    for ln in ctx.lines():
        if ln and not ln[0].isspace():
            cur = (ln.strip(), []) if r.search(ln) else None
            if cur:
                out.append(cur)
        elif cur is not None and ln.strip() and ln.strip() != "!":
            cur[1].append(ln.strip())
    return out


def no_config(ctx: Ctx) -> R:
    if ctx.vendor not in CONFIG_VENDORS:
        return R("not_evaluated", f"No configuration parser for vendor '{ctx.vendor or 'unknown'}' (supported: Cisco, Juniper, Ruckus).")
    if not ctx.backup_assigned:
        return R("not_evaluated", "No configuration backup: assign a read-only SSH credential (NMS → Config Changes).")
    if ctx.config is None:
        return R("not_evaluated", f"No configuration backup yet{': ' + ctx.backup_error if ctx.backup_error else ''}.")
    return R("not_evaluated", "No configuration available.")


def by_vendor(**fns: Callable[[Ctx], R | None]) -> Callable[[Ctx], R | None]:
    """Configuration check dispatched on vendor; vendors without an entry are not applicable."""
    def run(ctx: Ctx) -> R | None:
        if ctx.vendor not in fns:
            return None if ctx.vendor in CONFIG_VENDORS else no_config(ctx)
        if ctx.config is None:
            return no_config(ctx)
        return fns[ctx.vendor](ctx)
    return run


def present(ctx: Ctx, rx: str, ok: str, missing: str) -> R:
    hit = grep(ctx, rx)
    return R("pass", ok, hit[:10]) if hit else R("fail", missing)


def absent(ctx: Ctx, rx: str, ok: str, found: str) -> R:
    hit = grep(ctx, rx)
    return R("fail", found, hit[:10]) if hit else R("pass", ok)


def recent(now: datetime, t: datetime | None, days: float) -> bool:
    return bool(t and now - t <= timedelta(days=days))


def switch_only(fn: Callable[[Ctx], R | None]) -> Callable[[Ctx], R | None]:
    return lambda ctx: fn(ctx) if ctx.device_type == "switch" else None


# ------------------------------------------------------------------ AAA
def _aaa(ctx: Ctx) -> R | None:
    tac = ctx.tacacs
    tele = tac and tac.get("enabled") and recent(ctx.now, tac.get("last_auth"), 30)
    tele_txt = f"TACACS+ authentications from this device ({ago(ctx.now, tac.get('last_auth'))})." if tele else ""
    if ctx.kind == "firewall":
        if tele:
            return R("pass", tele_txt)
        return R("not_evaluated", "No TACACS+ authentication from this firewall in 30 days, and remote-admin settings are not part of the "
                                  "FortiGate snapshot: verify 'config user tacacs+' / 'config system admin' (wildcard remote admin).")
    if ctx.config is None or ctx.vendor not in CONFIG_VENDORS:
        return R("pass", tele_txt) if tele else no_config(ctx)
    if ctx.vendor == "cisco":
        model = grep(ctx, r"^aaa new-model\b")
        login = grep(ctx, r"^aaa authentication login \S+ .*\bgroup\s+\S+")
        ok = bool(model and login)
    elif ctx.vendor == "juniper":
        login = grep(ctx, r"^set system authentication-order .*\b(tacplus|radius)\b")
        ok = bool(login)
    else:
        login = grep(ctx, r"^aaa authentication login default .*\b(tacacs\+|radius)\b")
        ok = bool(login)
    if ok:
        return R("pass", "Administrative login authenticates against TACACS+ / RADIUS." + (" " + tele_txt if tele_txt else ""), login[:5])
    return R("fail", "Administrative login does not use a central AAA server (local accounts only).")


def _accounting(ctx: Ctx) -> R | None:
    tac = ctx.tacacs
    tele = tac and tac.get("enabled") and recent(ctx.now, tac.get("last_accounting"), 30)
    if ctx.config is None or ctx.vendor not in CONFIG_VENDORS:
        if tele:
            return R("pass", f"TACACS+ accounting records from this device ({ago(ctx.now, tac.get('last_accounting'))}).")
        return no_config(ctx)
    if ctx.vendor == "cisco":
        hit = grep(ctx, r"^aaa accounting commands \d+ \S+ .*\bgroup\s+\S+")
    elif ctx.vendor == "juniper":
        ev = grep(ctx, r"^set system accounting events .*interactive-commands")
        dest = grep(ctx, r"^set system accounting destination (tacplus|radius)")
        hit = ev + dest if ev and dest else []
    else:
        hit = grep(ctx, r"^aaa accounting commands \d+ default start-stop (tacacs\+|radius)")
    if hit:
        return R("pass", "Administrative commands are sent to the AAA server for accounting.", hit[:5])
    return R("fail", "Command accounting is not configured: administrator actions are not recorded centrally.")


# ------------------------------------------------------------------ management plane
def _vty(ctx: Ctx) -> list[tuple[str, list[str]]]:
    return sections(ctx, r"^line (vty|con)")


def _cisco_telnet(ctx: Ctx) -> R:
    vty = [(h, c) for h, c in _vty(ctx) if "vty" in h]
    if not vty:
        return R("not_evaluated", "No 'line vty' section in the configuration.")
    bad, missing = [], []
    for h, c in vty:
        t = [x for x in c if x.startswith("transport input")]
        if not t:
            missing.append(h)
        elif any(re.search(r"\b(telnet|all)\b", x) for x in t):
            bad.append(f"{h}: {t[0]}")
    if bad:
        return R("fail", "Telnet is allowed on VTY lines.", bad)
    if missing:
        return R("fail", "VTY lines without 'transport input': the default accepts Telnet on many IOS releases.", missing)
    return R("pass", "Every VTY line accepts SSH only.", [f"{h}: {next(x for x in c if x.startswith('transport input'))}" for h, c in vty])


def _ruckus_explicit(ctx: Ctx, off: str, on: str, what: str) -> R:
    if grep(ctx, on):
        return R("fail", f"{what} is enabled.", grep(ctx, on)[:5])
    hit = grep(ctx, off)
    if hit:
        return R("pass", f"{what} is disabled.", hit[:5])
    return R("fail", f"{what} is not explicitly disabled (the default depends on the FastIron release).")


def _cisco_timeout(ctx: Ctx) -> R:
    bad, ok = [], []
    for h, c in _vty(ctx):
        t = next((x for x in c if x.startswith("exec-timeout")), None)
        if t is None:
            ok.append(f"{h}: default exec-timeout 10 0")
            continue
        parts = t.split()
        m, s = int(parts[1]) if len(parts) > 1 else 10, int(parts[2]) if len(parts) > 2 else 0
        (bad if (m == 0 and s == 0) or m * 60 + s > 900 else ok).append(f"{h}: {t}")
    if bad:
        return R("fail", "Idle sessions stay open longer than 15 minutes (or never time out).", bad)
    return R("pass", "Console and VTY sessions time out within 15 minutes.", ok) if ok else R("not_evaluated", "No line sections found.")


def _juniper_timeout(ctx: Ctx) -> R:
    vals = [(ln, int(m.group(1))) for ln in grep(ctx, r"idle-timeout \d+") if (m := re.search(r"idle-timeout (\d+)", ln))]
    if not vals:
        return R("fail", "No 'idle-timeout' on the login classes: Junos sessions never time out by default.")
    bad = [ln for ln, v in vals if v == 0 or v > 15]
    return R("fail", "Idle timeout above 15 minutes.", bad) if bad else R("pass", "Login classes time out within 15 minutes.", [ln for ln, _ in vals])


def _ruckus_timeout(ctx: Ctx) -> R:
    hit = [(ln, int(m.group(1))) for ln in grep(ctx, r"^ip ssh idle-time \d+") if (m := re.search(r"(\d+)\s*$", ln))]
    if not hit:
        return R("fail", "No 'ip ssh idle-time': SSH sessions never time out by default.")
    ln, v = hit[0]
    return R("pass" if 0 < v <= 15 else "fail", "SSH idle timeout " + ("within" if 0 < v <= 15 else "above") + " 15 minutes.", [ln])


def _cisco_mgmt_acl(ctx: Ctx) -> R:
    vty = [(h, c) for h, c in _vty(ctx) if "vty" in h]
    if not vty:
        return R("not_evaluated", "No 'line vty' section in the configuration.")
    missing = [h for h, c in vty if not any(x.startswith("access-class") for x in c)]
    if missing:
        return R("fail", "VTY lines accept management sessions from any address (no access-class).", missing)
    return R("pass", "Every VTY line is restricted by an access-class.", [f"{h}: {next(x for x in c if x.startswith('access-class'))}" for h, c in vty])


# ------------------------------------------------------------------ SNMP
def _snmp_communities(ctx: Ctx) -> R | None:
    tele_fail = ctx.snmp_version == "v2c"
    if ctx.config is not None and ctx.vendor in CONFIG_VENDORS:
        rx = r"^set snmp community" if ctx.vendor == "juniper" else r"^snmp-server community"
        hit = grep(ctx, rx)
        if hit or tele_fail:
            return R("fail", "SNMPv1/v2c communities are configured (plain-text, no authentication)."
                     + (" Sentinel itself polls this device with SNMPv2c." if tele_fail else ""), hit[:10])
        return R("pass", "No SNMPv1/v2c community in the configuration.")
    if tele_fail:
        return R("fail", "Sentinel polls this device with SNMPv2c, so a community is configured.")
    r = no_config(ctx)
    if ctx.snmp_version == "v3":
        r.evidence = "Polled with SNMPv3, but other communities can only be ruled out from the configuration. " + r.evidence
    return r


def _snmpv3(ctx: Ctx) -> R | None:
    if ctx.snmp_version is None:
        return R("not_evaluated", "Not polled over SNMP (no credential assigned).")
    if ctx.snmp_version != "v3":
        return R("fail", "Polled with SNMPv2c: monitoring traffic is neither authenticated nor encrypted.")
    weak = grep(ctx, r"^snmp-server group \S+ v3 (noauth|auth)\b") if ctx.config and ctx.vendor in ("cisco", "ruckus") else []
    if weak:
        return R("fail", "SNMPv3 groups without privacy (encryption) are configured.", weak)
    if not ctx.snmp_priv:
        return R("fail", "Polled with SNMPv3 without privacy (authNoPriv): values travel unencrypted.")
    return R("pass", "Polled with SNMPv3 authPriv (authentication and encryption).")


# ------------------------------------------------------------------ logging and time
def _syslog(ctx: Ctx) -> R | None:
    seen = recent(ctx.now, ctx.syslog_at, 1)
    if ctx.kind == "firewall":
        if seen:
            return R("pass", f"Syslog from this firewall reaches Sentinel (last {ago(ctx.now, ctx.syslog_at)}).")
        return R("fail", f"No syslog from this firewall in the last 24 h (last {ago(ctx.now, ctx.syslog_at)}).")
    seen_txt = f" Logs arrive at Sentinel ({ctx.syslog_note}, last {ago(ctx.now, ctx.syslog_at)})." if seen else ""
    if ctx.config is None or ctx.vendor not in CONFIG_VENDORS:
        return R("pass", seen_txt.strip()) if seen else no_config(ctx)
    rx = {"cisco": r"^logging (host \S+|\d+\.\d+\.\d+\.\d+)", "juniper": r"^set system syslog host \S+", "ruckus": r"^logging host \S+"}[ctx.vendor]
    hit = grep(ctx, rx)
    if hit or seen:
        return R("pass", ("Remote syslog server configured." if hit else "No logging host in the configuration, but") + seen_txt, hit[:5])
    return R("fail", "No remote syslog server configured: logs stay on the device.")


def _ntp(ctx: Ctx) -> R | None:
    if ctx.vendor == "ruckus":
        servers = [f"ntp: {x}" for _, c in sections(ctx, r"^ntp\b") for x in c if x.startswith("server")]
        return R("pass", "NTP servers configured.", servers) if servers else R("fail", "No NTP server: the clock is not synchronised.")
    rx = r"^set system ntp server \S+" if ctx.vendor == "juniper" else r"^ntp server \S+"
    return present(ctx, rx, "NTP servers configured.", "No NTP server: the clock is not synchronised.")


def _ntp_auth(ctx: Ctx) -> R | None:
    if ctx.vendor == "cisco":
        a, k = grep(ctx, r"^ntp authenticate\b"), grep(ctx, r"^ntp trusted-key \d+")
        return R("pass", "NTP authentication enabled with trusted keys.", a + k) if a and k else R("fail", "NTP is not authenticated.")
    if ctx.vendor == "juniper":
        return present(ctx, r"^set system ntp (authentication-key|trusted-key)", "NTP authentication keys configured.", "NTP is not authenticated.")
    hit = [f"ntp: {x}" for _, c in sections(ctx, r"^ntp\b") for x in c if x.startswith("authenticat")]
    return R("pass", "NTP authentication configured.", hit) if hit else R("fail", "NTP is not authenticated.")


# ------------------------------------------------------------------ credentials and services
def _cisco_passwords(ctx: Ctx) -> R:
    weak = grep(ctx, r"^enable password\b") + grep(ctx, r"^username \S+ .*\bpassword\b")
    if weak:
        return R("fail", "Reversible passwords ('password' type 0 / 7) instead of hashed secrets.", weak[:10])
    return R("pass", "Enable and local user credentials are stored as hashed secrets.", grep(ctx, r"^(enable secret|username \S+ .*\bsecret\b)")[:5])


def _cisco_services(ctx: Ctx) -> R:
    bad = grep(ctx, r"^service (tcp|udp)-small-servers") + grep(ctx, r"^ip finger\b") + grep(ctx, r"^ip bootp server\b") + grep(ctx, r"^service pad\b")
    if not grep(ctx, r"^no ip source-route\b"):
        bad.append("ip source-route (enabled by default; 'no ip source-route' missing)")
    return R("fail", "Unneeded legacy services are enabled.", bad) if bad else R("pass", "Legacy services (small servers, finger, BOOTP, source routing) are off.")


# ------------------------------------------------------------------ layer 2
def _access_switch(fn):
    return lambda ctx: fn(ctx) if ctx.device_type == "switch" and ctx.role not in ("core", "distribution") else None


# ------------------------------------------------------------------ lifecycle and operations
def _backup(ctx: Ctx) -> R | None:
    if ctx.kind == "firewall":
        if not ctx.fg_at:
            return R("fail", "No configuration snapshot of this firewall (drift collection has not stored one).")
        if not recent(ctx.now, ctx.last_success_at, 7):
            return R("fail", f"Configuration collection is failing: API last reachable {ago(ctx.now, ctx.last_success_at)}.")
        return R("pass", f"Configuration tracked: latest snapshot {ago(ctx.now, ctx.fg_at)} (stored when it changes), API reachable "
                         f"{ago(ctx.now, ctx.last_success_at)}.")
    if not ctx.backup_assigned:
        return R("fail", "No configuration backup: no SSH credential assigned (NMS → Config Changes).")
    if recent(ctx.now, ctx.config_at, 7):
        return R("pass", f"Configuration backed up {ago(ctx.now, ctx.config_at)}.")
    return R("fail", f"Last successful backup {ago(ctx.now, ctx.config_at)}" + (f": {ctx.backup_error}" if ctx.backup_error else "."))


def _firmware(ctx: Ctx) -> R | None:
    if not ctx.model or not ctx.firmware:
        return R("not_evaluated", "Model or firmware version not known yet.")
    total = sum(ctx.fleet_firmware.values())
    if total < 2:
        return R("not_evaluated", f"Only device of model {ctx.model}: no fleet standard to compare with.")
    std, n = max(ctx.fleet_firmware.items(), key=lambda kv: (kv[1], kv[0]))
    if ctx.firmware == std:
        return R("pass", f"Runs {ctx.firmware}, the version on {n} of {total} {ctx.model} devices.")
    return R("fail", f"Runs {ctx.firmware}; {n} of {total} {ctx.model} devices run {std}. Check the vendor advisories for this version.")


def _monitored(ctx: Ctx) -> R | None:
    if ctx.monitoring == "paused":
        return R("fail", "Monitoring is paused for this device.")
    if recent(ctx.now, ctx.last_success_at, 1):
        return R("pass", f"Monitored: last successful poll {ago(ctx.now, ctx.last_success_at)}.")
    return R("fail", f"No successful poll in 24 h (last {ago(ctx.now, ctx.last_success_at)}).")


# ------------------------------------------------------------------ FortiGate (snapshot)
def fg_table(ctx: Ctx, table: str) -> tuple[dict | None, R | None]:
    if ctx.fg is None:
        return None, R("not_evaluated", "No FortiGate configuration snapshot yet (drift collection).")
    if table in ctx.fg_errors or table not in ctx.fg:
        why = ctx.fg_errors.get(table, "not collected")
        return None, R("not_evaluated", f"FortiGate table '{table}' not readable ({why}): grant the API profile read access to it.")
    return ctx.fg[table], None


def _access_set(v) -> set:
    return set(v) if isinstance(v, list) else set(str(v or "").split())


def _fg_insecure_mgmt(ctx: Ctx) -> R:
    t, r = fg_table(ctx, "interface")
    if r:
        return r
    bad = [f"{n}: allowaccess {' '.join(sorted(_access_set(i.get('allowaccess'))))}" for n, i in t.items()
           if _access_set(i.get("allowaccess")) & {"http", "telnet"}]
    return R("fail", "Interfaces accept HTTP or Telnet management (clear text).", bad) if bad else \
        R("pass", f"No interface allows HTTP or Telnet management ({len(t)} interfaces).")


def _fg_wan_mgmt(ctx: Ctx) -> R:
    t, r = fg_table(ctx, "interface")
    if r:
        return r
    wan = {n: i for n, i in t.items() if i.get("role") == "wan"}
    if not wan:
        return R("not_evaluated", "No interface has the WAN role, so internet exposure cannot be judged from roles.")
    bad = [f"{n}: allowaccess {' '.join(sorted(_access_set(i.get('allowaccess')) & {'https', 'ssh', 'http', 'telnet', 'snmp', 'fgfm'}))}"
           for n, i in wan.items() if _access_set(i.get("allowaccess")) & {"https", "ssh", "http", "telnet", "snmp"}]
    return R("fail", "WAN interfaces accept administrative access.", bad) if bad else \
        R("pass", f"No administrative access on the {len(wan)} WAN interface(s).", [f"{n}: role wan" for n in wan])


def _fg_trusthosts(ctx: Ctx) -> R:
    from ..drift import _no_trusthost
    t, r = fg_table(ctx, "admin")
    if r:
        return r
    if not t:
        return R("not_evaluated", "No administrator accounts in the snapshot.")
    bad = [n for n, a in t.items() if _no_trusthost(a)]
    return R("fail", "Administrators can log in from any address (no trusted hosts).", bad) if bad else \
        R("pass", f"All {len(t)} administrators are limited to trusted hosts.")


def _fg_global(field_: str, test: Callable[[object], bool], ok: str, bad: str, missing: str = "") -> Callable[[Ctx], R]:
    def run(ctx: Ctx) -> R:
        t, r = fg_table(ctx, "global")
        if r:
            return r
        if field_ not in t:
            return R("not_evaluated", missing or f"'{field_}' not in the snapshot.")
        v = t.get(field_)
        return R("pass" if test(v) else "fail", (ok if test(v) else bad) + f" ({field_} {v}).", [f"config system global: set {field_} {v}"])
    return run


def _int(v, default=0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _fg_legacy_admin(ctx: Ctx) -> R:
    t, r = fg_table(ctx, "global")
    if r:
        return r
    bad = [f"{k} {t[k]}" for k in ("admin-telnet", "admin-maintainer") if t.get(k) == "enable"]
    known = [k for k in ("admin-telnet", "admin-maintainer") if k in t]
    if not known:
        return R("not_evaluated", "admin-telnet / admin-maintainer not in the snapshot.")
    return R("fail", "Telnet administration or the maintainer (password-recovery) account is enabled.", bad) if bad else \
        R("pass", "Telnet administration and the maintainer account are disabled.", [f"{k} {t[k]}" for k in known])


def _fg_mfa(ctx: Ctx) -> R:
    t, r = fg_table(ctx, "admin")
    if r:
        return r
    if not t:
        return R("not_evaluated", "No administrator accounts in the snapshot.")
    if not any("two-factor" in a for a in t.values()):
        return R("not_evaluated", "The two-factor setting of administrators is not in the snapshot.")
    bad = [n for n, a in t.items() if str(a.get("two-factor", "disable")) == "disable"]
    return R("fail", "Administrators without multi-factor authentication.", bad) if bad else \
        R("pass", f"All {len(t)} administrators use two-factor authentication.")


def _fg_sslvpn(ctx: Ctx) -> R | None:
    t, r = fg_table(ctx, "sslvpn")
    if r:
        return r
    if t.get("status") == "disable":
        return None
    limit, block = _int(t.get("login-attempt-limit"), 2), _int(t.get("login-block-time"), 60)
    ev = [f"login-attempt-limit {t.get('login-attempt-limit', '(default 2)')}", f"login-block-time {t.get('login-block-time', '(default 60)')}"]
    if 0 < limit <= 10 and block > 0:
        return R("pass", "SSL-VPN locks out repeated failed logins.", ev)
    return R("fail", "SSL-VPN does not limit failed logins (unlimited attempts or no block time).", ev)


def _fg_bgp(ctx: Ctx) -> R | None:
    if ctx.bgp_audit is None:
        return None
    worst = [x for x in ctx.bgp_audit if x.get("severity") in ("high", "medium")]
    if worst:
        return R("fail", f"{len(worst)} BGP audit finding(s): sessions without authentication, prefix limits or route filters.",
                 [f"{x.get('neighbor') or x.get('peer') or ''} {x.get('check')}: {x.get('title') or x.get('detail') or ''}".strip() for x in worst][:20])
    return R("pass", "BGP neighbors have authentication, prefix limits and route filters (BGP configuration audit).")


def _fg_policies(ctx: Ctx) -> R:
    from ..drift import assess_risks
    t, r = fg_table(ctx, "policy")
    if r:
        return r
    risks = [x for x in assess_risks({"policy": t}, None) if x["table"] == "policy"]
    return R("fail", "Over-permissive or unlogged accept policies.", [x["title"] for x in risks][:20]) if risks else \
        R("pass", f"No any → any / ALL accept policy and every accept policy logs traffic ({len(t)} policies).")


# ------------------------------------------------------------------ the catalog
S, F, BOTH = ("switch",), ("firewall",), ("switch", "firewall")

CHECKS: list[Check] = [
    Check("NC-01", "Central AAA (TACACS+ / RADIUS) for administrative login", "high", BOTH, "Authentication",
          "Shared local accounts cannot be attributed to a person or revoked centrally.",
          {"cis": ["5.2", "6.7"], "pci": ["8.2.1"], "nist": ["IA-2", "AC-17"], "iso": ["5.15", "8.5"]}, _aaa,
          {"cisco": "aaa new-model\naaa authentication login default group tacacs+ local\naaa authorization exec default group tacacs+ local",
           "juniper": "set system authentication-order [ tacplus password ]\nset system tacplus-server <server> secret <key>",
           "ruckus": "aaa authentication login default tacacs+ local\ntacacs-server host <server>",
           "fortinet": "config user tacacs+\n  edit <server>\n    set server <ip>\n    set key <key>\n  next\nend"}, "config+telemetry"),
    Check("NC-02", "Administrative command accounting", "medium", S, "Logging",
          "Without command accounting there is no record of who changed what on the device.",
          {"cis": ["8.5"], "pci": ["10.2.1.2"], "nist": ["AU-2", "AU-12"], "iso": ["8.15", "8.2"]}, _accounting,
          {"cisco": "aaa accounting commands 15 default start-stop group tacacs+\naaa accounting exec default start-stop group tacacs+",
           "juniper": "set system accounting events interactive-commands\nset system accounting destination tacplus",
           "ruckus": "aaa accounting commands 0 default start-stop tacacs+"}, "config+telemetry"),
    Check("NC-03", "Telnet disabled for management", "high", S, "Management plane",
          "Telnet sends credentials and sessions in clear text.",
          {"cis": ["4.6", "12.3", "3.10"], "pci": ["2.2.7", "2.2.5"], "nist": ["SC-8", "AC-17"], "iso": ["8.21", "8.24"]},
          by_vendor(cisco=_cisco_telnet,
                    juniper=lambda c: absent(c, r"^set system services telnet\b", "Telnet service is not enabled.", "Telnet service is enabled."),
                    ruckus=lambda c: _ruckus_explicit(c, r"^no telnet server\b", r"^telnet server\b", "Telnet")),
          {"cisco": "line vty 0 15\n transport input ssh", "juniper": "delete system services telnet", "ruckus": "no telnet server"}),
    Check("NC-04", "SSH protocol version 2 only", "medium", S, "Management plane",
          "SSH version 1 has known cryptographic weaknesses.",
          {"cis": ["4.6", "3.10"], "pci": ["2.2.7"], "nist": ["SC-8", "SC-13"], "iso": ["8.24"]},
          by_vendor(cisco=lambda c: present(c, r"^ip ssh version 2\b", "SSH is restricted to version 2.",
                                            "'ip ssh version 2' is not set: releases before IOS XE 17 also accept SSHv1."),
                    juniper=lambda c: absent(c, r"protocol-version v1\b", "SSHv1 is not enabled.", "SSHv1 is enabled.")),
          {"cisco": "ip ssh version 2", "juniper": "delete system services ssh protocol-version v1"}),
    Check("NC-05", "Plain HTTP management disabled", "medium", S, "Management plane",
          "The HTTP server exposes a clear-text management interface.",
          {"cis": ["4.8", "3.10"], "pci": ["2.2.4", "2.2.7"], "nist": ["CM-7", "SC-8"], "iso": ["8.21"]},
          by_vendor(cisco=lambda c: absent(c, r"^ip http server\b", "The HTTP server is disabled (HTTPS may remain).", "'ip http server' is enabled."),
                    juniper=lambda c: absent(c, r"^set system services web-management http(\s|$)", "HTTP web management is not enabled.",
                                             "HTTP web management is enabled."),
                    ruckus=lambda c: _ruckus_explicit(c, r"^no web-management http\b|^no web-management\s*$", r"^web-management http\b",
                                                      "HTTP web management")),
          {"cisco": "no ip http server\nip http secure-server", "juniper": "delete system services web-management http",
           "ruckus": "no web-management http"}),
    Check("NC-06", "Management access restricted to authorised sources", "medium", S, "Management plane",
          "Management sessions from any address widen the attack surface.",
          {"cis": ["12.3", "4.2"], "pci": ["1.3.1", "2.2.6"], "nist": ["AC-17", "SC-7"], "iso": ["8.20"]},
          by_vendor(cisco=_cisco_mgmt_acl,
                    juniper=lambda c: present(c, r"^set interfaces lo0 unit \d+ family inet filter input \S+",
                                              "A firewall filter protects the routing engine (lo0).", "No input filter on lo0: management is open to any source."),
                    ruckus=lambda c: present(c, r"^(ssh|web) access-group \S+", "Management access is limited by an access group.",
                                             "No 'ssh access-group': SSH accepts any source.")),
          {"cisco": "ip access-list standard MGMT\n permit <mgmt-network> <wildcard>\nline vty 0 15\n access-class MGMT in",
           "juniper": "set firewall filter PROTECT-RE term mgmt from source-address <mgmt-network>\n"
                      "set interfaces lo0 unit 0 family inet filter input PROTECT-RE",
           "ruckus": "ip access-list standard MGMT\n permit <mgmt-network>\nssh access-group MGMT"}),
    Check("NC-07", "Idle session timeout of 15 minutes or less", "medium", S, "Management plane",
          "Unattended sessions can be reused by someone else.",
          {"cis": ["4.3"], "pci": ["8.2.8"], "nist": ["AC-12"], "iso": ["8.5"]},
          by_vendor(cisco=_cisco_timeout, juniper=_juniper_timeout, ruckus=_ruckus_timeout),
          {"cisco": "line con 0\n exec-timeout 10 0\nline vty 0 15\n exec-timeout 10 0", "juniper": "set system login idle-timeout 10",
           "ruckus": "ip ssh idle-time 10"}),
    Check("NC-08", "Login banner", "low", S, "Management plane",
          "A warning banner states that access is restricted and monitored.",
          {"cis": ["4.2"], "pci": ["2.2.1"], "nist": ["AC-8"], "iso": ["8.9"]},
          by_vendor(cisco=lambda c: present(c, r"^banner (login|motd)\b", "A login banner is configured.", "No login banner."),
                    juniper=lambda c: present(c, r"^set system login message\b", "A login banner is configured.", "No login banner."),
                    ruckus=lambda c: present(c, r"^banner (motd|exec)\b", "A login banner is configured.", "No login banner.")),
          {"cisco": "banner login ^Authorised access only. Activity is monitored.^", "juniper": 'set system login message "Authorised access only."',
           "ruckus": "banner motd ^Authorised access only.^"}),
    Check("NC-09", "No SNMPv1 / v2c communities", "high", S, "Monitoring",
          "SNMP communities are clear-text passwords; read-write communities allow configuration changes.",
          {"cis": ["4.6", "4.8"], "pci": ["2.2.5", "2.2.7"], "nist": ["CM-7", "SC-8"], "iso": ["8.21"]}, _snmp_communities,
          {"cisco": "no snmp-server community <community>\nsnmp-server group SENTINEL v3 priv\nsnmp-server user <user> SENTINEL v3 auth sha <auth> priv aes 128 <priv>",
           "juniper": "delete snmp community <community>",
           "ruckus": "no snmp-server community <community>"}, "config+telemetry"),
    Check("NC-10", "SNMPv3 with encryption (authPriv)", "medium", S, "Monitoring",
          "Monitoring credentials and values must be authenticated and encrypted.",
          {"cis": ["3.10"], "pci": ["2.2.7", "8.3.2"], "nist": ["SC-8", "SC-13"], "iso": ["8.24"]}, _snmpv3,
          {"cisco": "snmp-server group SENTINEL v3 priv\nsnmp-server user <user> SENTINEL v3 auth sha <auth> priv aes 128 <priv>"}, "telemetry"),
    Check("NC-11", "Logs sent to a central log server", "medium", BOTH, "Logging",
          "Logs kept only on the device are lost on reboot and can be altered by an intruder.",
          {"cis": ["8.2", "8.9"], "pci": ["10.2.1", "10.3.3"], "nist": ["AU-9", "AU-12", "SI-4"], "iso": ["8.15", "8.16"]}, _syslog,
          {"cisco": "logging host <sentinel-ip>\nlogging trap informational", "juniper": "set system syslog host <sentinel-ip> any notice",
           "ruckus": "logging host <sentinel-ip>",
           "fortinet": "config log syslogd setting\n  set status enable\n  set server <sentinel-ip>\nend"}, "config+telemetry"),
    Check("NC-12", "Log timestamps with date and time", "low", S, "Logging",
          "Events without full timestamps cannot be correlated.",
          {"cis": ["8.5"], "pci": ["10.6.2"], "nist": ["AU-8"], "iso": ["8.17"]},
          by_vendor(cisco=lambda c: present(c, r"^service timestamps log datetime\b", "Log messages carry date and time.",
                                            "'service timestamps log datetime' is not set.")),
          {"cisco": "service timestamps log datetime msec localtime show-timezone\nservice timestamps debug datetime msec localtime show-timezone"}),
    Check("NC-13", "Time synchronised with NTP", "medium", S, "Time",
          "Correct time is needed for log correlation, certificates and forensics.",
          {"cis": ["8.4"], "pci": ["10.6.1"], "nist": ["AU-8", "SC-45"], "iso": ["8.17"]},
          by_vendor(cisco=_ntp, juniper=_ntp, ruckus=_ntp),
          {"cisco": "ntp server <ntp-1>\nntp server <ntp-2>", "juniper": "set system ntp server <ntp-1>", "ruckus": "ntp\n server <ntp-1>"}),
    Check("NC-14", "NTP authentication", "low", S, "Time",
          "Unauthenticated NTP can be spoofed to shift the clock.",
          {"cis": ["8.4"], "pci": ["10.6.3"], "nist": ["SC-45"], "iso": ["8.17"]},
          by_vendor(cisco=_ntp_auth, juniper=_ntp_auth, ruckus=_ntp_auth),
          {"cisco": "ntp authentication-key 1 sha1 <key>\nntp trusted-key 1\nntp authenticate\nntp server <ntp-1> key 1",
           "juniper": "set system ntp authentication-key 1 type sha1 value <key>\nset system ntp trusted-key 1",
           "ruckus": "ntp\n authenticate\n authentication-key key-id 1 sha1 <key>"}),
    Check("NC-15", "Credentials stored as hashed secrets", "high", S, "Authentication",
          "Type 0 / 7 passwords are readable or trivially reversible from a configuration copy.",
          {"cis": ["5.2"], "pci": ["8.3.2"], "nist": ["IA-5"], "iso": ["5.17"]},
          by_vendor(cisco=_cisco_passwords),
          {"cisco": "no enable password\nenable algorithm-type scrypt secret <secret>\nusername <user> algorithm-type scrypt secret <secret>"}),
    Check("NC-16", "Unneeded legacy services disabled", "medium", S, "Hardening",
          "Small servers, finger, BOOTP, PAD and IP source routing are attack surface with no operational use.",
          {"cis": ["4.8"], "pci": ["2.2.4"], "nist": ["CM-7"], "iso": ["8.9", "8.21"]},
          by_vendor(cisco=_cisco_services,
                    juniper=lambda c: absent(c, r"^set system services (finger|ftp|rlogin|rsh|tftp-server)\b",
                                             "No legacy services (finger, FTP, rlogin, rsh, TFTP) enabled.", "Legacy services are enabled.")),
          {"cisco": "no service tcp-small-servers\nno service udp-small-servers\nno ip finger\nno ip bootp server\nno service pad\nno ip source-route",
           "juniper": "delete system services finger\ndelete system services ftp"}),
    Check("NC-17", "BPDU guard on edge ports", "low", S, "Layer 2",
          "Without BPDU guard a device plugged into an access port can take over the spanning tree.",
          {"cis": ["12.2"], "pci": ["2.2.6"], "nist": ["SC-7", "CM-6"], "iso": ["8.20"]},
          switch_only(by_vendor(
              cisco=lambda c: present(c, r"spanning-tree portfast (edge )?bpduguard default|spanning-tree bpduguard enable",
                                      "BPDU guard is enabled.", "No BPDU guard on edge ports."),
              juniper=lambda c: present(c, r"bpdu-block-on-edge|layer2-control bpdu-block", "BPDU protection is enabled.", "No BPDU protection on edge ports."),
              ruckus=lambda c: present(c, r"stp-bpdu-guard|bpdu-guard", "BPDU guard is enabled.", "No BPDU guard on edge ports."))),
          {"cisco": "spanning-tree portfast edge bpduguard default", "juniper": "set protocols rstp bpdu-block-on-edge",
           "ruckus": "interface ethernet <port>\n stp-bpdu-guard"}),
    Check("NC-18", "DHCP snooping on access switches", "low", S, "Layer 2",
          "DHCP snooping stops rogue DHCP servers and is the base for ARP inspection.",
          {"cis": ["13.9"], "pci": ["2.2.6"], "nist": ["SC-7"], "iso": ["8.20"]},
          _access_switch(by_vendor(
              cisco=lambda c: present(c, r"^ip dhcp snooping vlan \S+", "DHCP snooping is enabled.", "DHCP snooping is not enabled."),
              juniper=lambda c: present(c, r"dhcp-security|examine-dhcp", "DHCP security is enabled.", "DHCP security is not enabled."),
              ruckus=lambda c: present(c, r"^ip dhcp snooping vlan \S+", "DHCP snooping is enabled.", "DHCP snooping is not enabled."))),
          {"cisco": "ip dhcp snooping\nip dhcp snooping vlan <vlans>\ninterface <uplink>\n ip dhcp snooping trust",
           "juniper": "set vlans <vlan> forwarding-options dhcp-security", "ruckus": "ip dhcp snooping vlan <vlan>"}),
    Check("NC-19", "Configuration backed up and change-tracked", "medium", BOTH, "Change management",
          "A current configuration copy is needed for recovery, review and change control.",
          {"cis": ["11.2", "4.1"], "pci": ["1.2.2", "1.2.8"], "nist": ["CP-9", "CM-2", "CM-3"], "iso": ["8.13", "8.32", "8.9"]}, _backup,
          {}, "telemetry"),
    Check("NC-20", "Firmware matches the fleet standard for the model", "low", BOTH, "Lifecycle",
          "Version outliers usually mean missed upgrades and unpatched vulnerabilities.",
          {"cis": ["12.1"], "pci": ["6.3.3"], "nist": ["SI-2", "CM-2"], "iso": ["8.8"]}, _firmware, {}, "telemetry"),
    Check("NC-21", "Device monitored", "low", BOTH, "Inventory",
          "Every network device must be in the inventory and reachable by monitoring.",
          {"cis": ["1.1"], "pci": ["12.5.1"], "nist": ["CM-8", "SI-4"], "iso": ["5.9", "8.16"]}, _monitored, {}, "telemetry"),
    # FortiGate (configuration snapshot)
    Check("FG-01", "No HTTP or Telnet administrative access on interfaces", "high", F, "Management plane",
          "HTTP and Telnet send administrator credentials in clear text.",
          {"cis": ["4.6", "3.10"], "pci": ["2.2.7", "2.2.5"], "nist": ["SC-8", "AC-17"], "iso": ["8.21", "8.24"]}, _fg_insecure_mgmt,
          {"fortinet": "config system interface\n  edit <port>\n    unselect allowaccess http telnet\n  next\nend"}, "snapshot"),
    Check("FG-02", "No administrative access on WAN interfaces", "high", F, "Management plane",
          "Management exposed to the internet is a primary attack path on firewalls.",
          {"cis": ["4.4", "12.3"], "pci": ["1.4.2", "1.3.1"], "nist": ["SC-7", "AC-17"], "iso": ["8.20"]}, _fg_wan_mgmt,
          {"fortinet": "config system interface\n  edit <wan-port>\n    unset allowaccess\n  next\nend"}, "snapshot"),
    Check("FG-03", "Administrators limited to trusted hosts", "high", F, "Management plane",
          "Trusted hosts confine administrator logins to management networks.",
          {"cis": ["12.3"], "pci": ["1.3.1", "2.2.6"], "nist": ["AC-17"], "iso": ["8.2", "8.20"]}, _fg_trusthosts,
          {"fortinet": "config system admin\n  edit <admin>\n    set trusthost1 <mgmt-network> <mask>\n  next\nend"}, "snapshot"),
    Check("FG-04", "Administrator idle timeout of 15 minutes or less", "medium", F, "Management plane",
          "Unattended administrator sessions can be reused.",
          {"cis": ["4.3"], "pci": ["8.2.8"], "nist": ["AC-12"], "iso": ["8.5"]},
          _fg_global("admintimeout", lambda v: 0 < _int(v, 999) <= 15, "Administrator sessions time out within 15 minutes",
                     "Administrator sessions stay open longer than 15 minutes"),
          {"fortinet": "config system global\n  set admintimeout 10\nend"}, "snapshot"),
    Check("FG-05", "Administrator lockout after failed logins", "medium", F, "Authentication",
          "Lockout slows down password guessing.",
          {"cis": ["4.2"], "pci": ["8.3.4"], "nist": ["AC-7"], "iso": ["8.5"]},
          _fg_global("admin-lockout-threshold", lambda v: 0 < _int(v, 3) <= 10, "Administrator lockout after at most 10 failures",
                     "Administrator lockout threshold is above 10 failures", "admin-lockout-threshold not in the snapshot (FortiOS default 3)."),
          {"fortinet": "config system global\n  set admin-lockout-threshold 3\n  set admin-lockout-duration 300\nend"}, "snapshot"),
    Check("FG-06", "Strong cryptography enforced", "medium", F, "Cryptography",
          "strong-crypto disables weak ciphers and protocols for HTTPS and SSH administration.",
          {"cis": ["3.10"], "pci": ["2.2.7"], "nist": ["SC-13", "SC-8"], "iso": ["8.24"]},
          _fg_global("strong-crypto", lambda v: v == "enable", "Strong cryptography is enforced", "Weak ciphers are allowed"),
          {"fortinet": "config system global\n  set strong-crypto enable\nend"}, "snapshot"),
    Check("FG-07", "Telnet administration and maintainer account disabled", "medium", F, "Hardening",
          "The maintainer account allows password recovery with console access; Telnet is clear text.",
          {"cis": ["4.8"], "pci": ["2.2.4", "2.2.5"], "nist": ["CM-7"], "iso": ["8.9"]}, _fg_legacy_admin,
          {"fortinet": "config system global\n  set admin-telnet disable\n  set admin-maintainer disable\nend"}, "snapshot"),
    Check("FG-08", "Multi-factor authentication for administrators", "high", F, "Authentication",
          "Administrative access to network security controls needs more than a password.",
          {"cis": ["6.5"], "pci": ["8.4.1"], "nist": ["IA-2(1)"], "iso": ["8.5", "8.2"]}, _fg_mfa,
          {"fortinet": "config system admin\n  edit <admin>\n    set two-factor fortitoken\n    set fortitoken <serial>\n  next\nend"}, "snapshot"),
    Check("FG-09", "SSL-VPN brute-force protection", "medium", F, "Authentication",
          "Unlimited VPN login attempts allow password spraying from the internet.",
          {"cis": ["4.2"], "pci": ["8.3.4"], "nist": ["AC-7"], "iso": ["8.5"]}, _fg_sslvpn,
          {"fortinet": "config vpn ssl settings\n  set login-attempt-limit 3\n  set login-block-time 300\nend"}, "snapshot"),
    Check("FG-10", "Routing protocol sessions protected", "medium", F, "Routing",
          "BGP sessions need authentication, prefix limits and filters against hijacks and leaks.",
          {"cis": ["12.2"], "pci": ["1.2.7"], "nist": ["SC-7"], "iso": ["8.20"]}, _fg_bgp, {}, "snapshot"),
    Check("FG-11", "No over-permissive or unlogged accept policies", "high", F, "Policy",
          "any → any / ALL accept rules bypass segmentation; unlogged accepts are invisible to monitoring.",
          {"cis": ["4.4", "12.2"], "pci": ["1.3.1", "1.2.7", "10.2.1"], "nist": ["SC-7", "AU-12"], "iso": ["8.20", "8.15"]}, _fg_policies,
          {"fortinet": "config firewall policy\n  edit <id>\n    set srcaddr <specific>\n    set dstaddr <specific>\n    set service <specific>\n"
                       "    set logtraffic all\n  next\nend"}, "snapshot"),
]
BY_ID = {c.id: c for c in CHECKS}


def evaluate(ctx: Ctx) -> list[dict]:
    """All applicable checks for one device: [{check, status, evidence, lines}]."""
    out = []
    for c in CHECKS:
        if ctx.kind not in c.kinds:
            continue
        try:
            r = c.evaluate(ctx)
        except Exception as e:  # a parser bug must show as missing evidence, never as pass
            r = R("not_evaluated", f"Check error: {type(e).__name__}: {e}"[:300])
        if r is None:
            continue
        out.append({"check": c.id, "status": r.status, "evidence": r.evidence, "lines": [ln[:300] for ln in r.lines[:20]]})
    return out


def address_in(address: str, entries: list) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    for e in entries or []:
        try:
            if ip in ipaddress.ip_network(str(e), strict=False):
                return True
        except ValueError:
            continue
    return False
