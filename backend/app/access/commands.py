"""Vendor command library, command risk classification and the terminal line guard.

Risk levels, lowest to highest:
  READ_ONLY      shows state (show / get / display, read-only diagnose)
  LOW_RISK       harmless session or reachability actions (terminal length, ping, traceroute, enable, exit)
  MODERATE_RISK  changes runtime state without changing configuration (clear counters, debug, write memory, copy out);
                 also every command the classifier does not recognise
  HIGH_RISK      enters configuration mode or changes configuration or routing (configure, set, no, commit, clear ip bgp)
  DESTRUCTIVE    reboots, erases or formats (reload, write erase, execute factoryreset, request system zeroize)

Classification is conservative. Commands may be abbreviated the way CLIs accept ("sh run", "conf t"). An abbreviation
that could expand to several verbs takes the highest risk among them ("s" could be show, set or ssh: HIGH_RISK).
Text after a pipe must be a known output filter, and a line holding several commands takes the highest risk of its
parts.

The classifier decides what the gateway allows; the device's own AAA (TACACS+ / RADIUS command authorisation,
privilege levels) remains the authority over what an account can do on the device.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

LEVELS = ("READ_ONLY", "LOW_RISK", "MODERATE_RISK", "HIGH_RISK", "DESTRUCTIVE")
RANK = {k: i for i, k in enumerate(LEVELS)}
R, L, M, H, D = LEVELS


def worst(*risks: str) -> str:
    return max(risks, key=lambda r: RANK[r]) if risks else R


# word tree: value is a risk, or a dict of next words with "_" as the risk when the line ends or the next word is not
# listed. Lookups accept unambiguous or ambiguous abbreviations (ambiguous = highest risk of the candidates).
TREE: dict = {
    "show": R, "display": R, "get": R, "dir": R, "more": R, "who": R, "whoami": R, "help": R, "history": R,
    "ping": L, "ping6": L, "traceroute": L, "traceroute6": L, "tracert": L, "verify": L,
    "enable": L, "disable": L, "exit": L, "end": L, "quit": L, "logout": L, "return": L, "cli": L,
    "skip-page-display": L, "undebug": L, "screen-length": L, "page": L,
    "terminal": {"_": L},
    "clear": {"_": M, "counters": M, "logging": M, "log": M, "mac": M, "mac-address-table": M, "arp": M, "arp-cache": M,
              "statistics": M, "bgp": H, "ospf": H, "isis": H, "route": H, "configuration": H, "crypto": H, "vpn": H,
              "ip": {"_": M, "bgp": H, "ospf": H, "route": H, "eigrp": H, "nat": H}, "ipv6": {"_": M, "bgp": H, "ospf": H, "route": H}},
    "write": {"_": M, "memory": M, "network": M, "terminal": R, "erase": D},
    "save": M, "archive": M, "license": M, "monitor": M, "test": M, "debug": {"_": M, "all": H}, "reset": M,
    "ssh": M, "telnet": M, "connect": M,
    "reload": D, "reboot": D, "erase": D, "format": D, "delete": D, "rmdir": D, "squeeze": D, "halt": D, "poweroff": D,
    "factory-reset": D,
    "configure": H, "config": H, "system-view": H, "edit": H, "unset": H, "commit": H, "rollback": H, "load": H,
    "activate": H, "deactivate": H, "interface": H, "no": {"_": H, "paging": L, "page": L}, "undo": H, "shutdown": H,
    "username": H, "aaa": H, "boot": H, "install": H, "upgrade": H, "restart": H, "start": H, "bash": H, "tclsh": H,
    "guestshell": H, "fsck": H,
    "set": {"_": H, "cli": L},
    "file": {"_": M, "show": R, "list": R, "delete": D, "copy": M},
    "request": {"_": M, "system": {"_": M, "reboot": D, "halt": D, "power-off": D, "zeroize": D, "software": H, "configuration": H}},
    "execute": {"_": M, "ping": L, "ping6": L, "ping-options": L, "traceroute": L, "traceroute6": L, "tracert6": L,
                "reboot": D, "shutdown": D, "factoryreset": D, "factoryreset2": D, "formatlogdisk": D, "erase-disk": D,
                "restore": D, "disk": D},
    "diagnose": {"_": M,
                 "sys": {"_": M, "top": R, "top-summary": R, "kill": H, "sdwan": {"_": M, "health-check": R},
                         "virtual-wan-link": {"_": M, "health-check": R}, "session": {"_": M, "stat": R},
                         "ha": {"_": M, "status": R}, "flash": {"_": M, "list": R}},
                 "hardware": {"_": M, "sysinfo": R, "deviceinfo": R},
                 "vpn": {"_": M, "tunnel": {"_": M, "list": R}, "ike": {"_": M, "gateway": {"_": M, "list": R}}},
                 "netlink": {"_": M, "interface": {"_": M, "list": R}},
                 "ip": {"_": M, "address": {"_": M, "list": R}, "route": {"_": M, "list": R}},
                 "debug": M},
}
# "run" (Junos configuration mode, NX-OS) and "do" (IOS configuration mode) run the rest of the line as an
# operational command: it is classified on its own
RECURSE = ("run", "do")
# Abbreviations every supported CLI resolves the same way in operational (exec) mode, where a session starts. In a
# change session the user can be in configuration mode, where "sh" means shutdown: there the aliases are not used and
# the ambiguous reading (highest risk) is recorded.
ALIASES = {"sh": "show", "sho": "show", "conf": "configure", "wr": "write", "exec": "execute", "diag": "diagnose",
           "int": "interface", "dis": "display", "disp": "display", "term": "terminal"}
SAFE_PIPES = ("include", "exclude", "begin", "section", "count", "match", "except", "find", "no-more", "display", "last",
              "trim", "grep", "head", "tail", "resolve", "refresh")
_SPLIT = re.compile(r";|&&|\|\||`|\$\(")


def _subtree_max(node) -> str:
    if isinstance(node, str):
        return node
    return worst(*(_subtree_max(v) for v in node.values()))


def _lookup(node: dict, word: str):
    if word in node and word != "_":
        return node[word], ""
    cands = [k for k in node if k != "_" and k.startswith(word)]
    if not cands:
        return None, ""
    if len(cands) == 1:
        return node[cands[0]], ""
    return worst(*(_subtree_max(node[c]) for c in cands)), f"ambiguous abbreviation '{word}' ({', '.join(sorted(cands)[:5])})"


def _walk(words: list[str]) -> tuple[str, str]:
    node: object = TREE
    for i, w in enumerate(words):
        if isinstance(node, str):
            return node, ""
        nxt, note = _lookup(node, w)       # type: ignore[arg-type]
        if nxt is None:
            if i == 0:
                return M, f"unrecognised command '{w}'"
            return node.get("_", M), ""     # type: ignore[union-attr]
        if note:
            return nxt if isinstance(nxt, str) else _subtree_max(nxt), note
        node = nxt
    return (node if isinstance(node, str) else node.get("_", M)), ""   # type: ignore[union-attr]


def _copy(words: list[str]) -> tuple[str, str]:
    args = [w for w in words[1:] if not w.startswith("/")]
    if len(args) < 2:
        return M, "copy"
    src, dst = args[0], args[-1]
    if re.match(r"^(system:)?run", dst):
        return H, "copy into the running configuration"
    if re.match(r"^(nvram:)?start", dst):
        return (M, "save running configuration") if re.match(r"^(system:)?run", src) else (H, "replace the startup configuration")
    return M, "copy out"


def _mikrotik(cmd: str) -> tuple[str, str]:
    if re.search(r"\b(reboot|shutdown|reset-configuration|format-drive)\b", cmd):
        return D, "MikroTik reboot / reset"
    if re.search(r"\bexport\b.*\bfile=", cmd):
        return M, "export to a file"
    if re.search(r"(^|\s)(print|export|monitor)(\s|$)", cmd) and not re.search(r"\b(set|add|remove|enable|disable|edit)\b", cmd):
        return R, ""
    if re.search(r"(^|\s)ping(\s|$)|(^|\s)traceroute(\s|$)", cmd):
        return L, ""
    return H, "MikroTik command that is not print / export"


def classify(command: str, config_context: bool = False) -> tuple[str, str]:
    """(risk, reason) for one command line. config_context: the CLI may be in configuration mode (change sessions)."""
    cmd = " ".join((command or "").strip().lower().split())
    if not cmd or cmd.endswith("?"):
        return R, "empty or help"
    parts = [p.strip() for p in _SPLIT.split(cmd) if p.strip()]
    if len(parts) > 1:
        res = [classify(p, config_context) for p in parts]
        top = worst(*(r for r, _ in res))
        return top, "several commands on one line" if top != R else ""
    segs = [s.strip() for s in cmd.split("|")]
    base, pipes = segs[0], segs[1:]
    pipe_risk, pipe_note = R, ""
    for p in pipes:
        w = (p.split() or [""])[0]
        if not w or not any(sp.startswith(w) for sp in SAFE_PIPES):
            pipe_risk, pipe_note = M, f"output piped to '{w}'"
        elif w.startswith("save") or w.startswith("tee") or w.startswith("redirect"):
            pipe_risk, pipe_note = M, f"output saved with '{w}'"
    if base.startswith("/"):
        r, why = _mikrotik(base)
        return worst(r, pipe_risk), why or pipe_note
    words = base.split()
    if not config_context and words[0] in ALIASES:
        words[0] = ALIASES[words[0]]
    if words[0] in RECURSE and len(words) > 1:
        r, why = classify(" ".join(words[1:]) + ("".join(" | " + p for p in pipes)), False)
        return r, why
    if words[0] == "copy" or (len(words[0]) >= 2 and "copy".startswith(words[0]) and words[0] not in TREE):
        r, why = _copy(words)
    else:
        r, why = _walk(words)
    top = worst(r, pipe_risk)
    return top, (why if RANK[r] >= RANK[pipe_risk] else pipe_note)


# ------------------------------------------------------------------ diagnostic templates
@dataclass(frozen=True)
class Template:
    id: str
    platform: str
    title: str
    category: str
    commands: tuple[str, ...]
    note: str = ""


PLATFORMS: dict[str, dict] = {
    "cisco_ios": {"label": "Cisco IOS / IOS-XE", "vendor": "cisco", "mode": "exec", "pager": "terminal length 0"},
    "cisco_nxos": {"label": "Cisco NX-OS", "vendor": "cisco", "mode": "exec", "pager": "terminal length 0"},
    "cisco_wlc9800": {"label": "Cisco Catalyst 9800 WLC (IOS-XE)", "vendor": "cisco", "mode": "exec", "pager": "terminal length 0"},
    "fortios": {"label": "FortiOS (FortiGate)", "vendor": "fortinet", "mode": "exec", "pager": ""},
    "junos": {"label": "Junos (EX / QFX / MX / SRX)", "vendor": "juniper", "mode": "exec", "pager": ""},
    "ruckus_icx": {"label": "Ruckus ICX (FastIron)", "vendor": "ruckus", "mode": "shell", "pager": "skip-page-display"},
    "ruckus_smartzone": {"label": "Ruckus SmartZone / vSZ", "vendor": "ruckus", "mode": "shell", "pager": ""},
    "aruba_aoscx": {"label": "Aruba AOS-CX", "vendor": "aruba", "mode": "shell", "pager": "no page"},
    "arista_eos": {"label": "Arista EOS", "vendor": "arista", "mode": "exec", "pager": "terminal length 0"},
    "huawei_vrp": {"label": "Huawei VRP", "vendor": "huawei", "mode": "shell", "pager": "screen-length 0 temporary"},
    "mikrotik_routeros": {"label": "MikroTik RouterOS", "vendor": "mikrotik", "mode": "exec", "pager": ""},
}

_T = Template
TEMPLATES: tuple[Template, ...] = (
    # Cisco IOS / IOS-XE (Catalyst, ISR / ASR)
    _T("ios.version", "cisco_ios", "Version and uptime", "system", ("show version",)),
    _T("ios.inventory", "cisco_ios", "Hardware inventory", "hardware", ("show inventory",)),
    _T("ios.if_status", "cisco_ios", "Interface status", "interfaces", ("show interfaces status",)),
    _T("ios.if_errors", "cisco_ios", "Interface error counters", "interfaces", ("show interfaces counters errors",)),
    _T("ios.ip_brief", "cisco_ios", "IP interfaces", "interfaces", ("show ip interface brief",)),
    _T("ios.route", "cisco_ios", "Routing table", "routing", ("show ip route",)),
    _T("ios.bgp", "cisco_ios", "BGP summary", "routing", ("show ip bgp summary",)),
    _T("ios.cdp", "cisco_ios", "CDP neighbours", "topology", ("show cdp neighbors detail",)),
    _T("ios.lldp", "cisco_ios", "LLDP neighbours", "topology", ("show lldp neighbors detail",)),
    _T("ios.log", "cisco_ios", "Logging buffer", "system", ("show logging",)),
    _T("ios.cpu", "cisco_ios", "CPU", "health", ("show processes cpu sorted",)),
    _T("ios.mem", "cisco_ios", "Memory", "health", ("show processes memory sorted",)),
    _T("ios.env", "cisco_ios", "Environment (power, fans, temperature)", "hardware", ("show environment all",)),
    # Cisco NX-OS
    _T("nxos.version", "cisco_nxos", "Version and uptime", "system", ("show version",)),
    _T("nxos.inventory", "cisco_nxos", "Hardware inventory", "hardware", ("show inventory",)),
    _T("nxos.if_brief", "cisco_nxos", "Interfaces", "interfaces", ("show interface brief",)),
    _T("nxos.if_errors", "cisco_nxos", "Interface error counters", "interfaces", ("show interface counters errors",)),
    _T("nxos.route", "cisco_nxos", "Routing table", "routing", ("show ip route",)),
    _T("nxos.bgp", "cisco_nxos", "BGP summary", "routing", ("show bgp ipv4 unicast summary",)),
    _T("nxos.lldp", "cisco_nxos", "LLDP neighbours", "topology", ("show lldp neighbors detail",)),
    _T("nxos.cpu", "cisco_nxos", "CPU", "health", ("show processes cpu sort",)),
    _T("nxos.res", "cisco_nxos", "System resources", "health", ("show system resources",)),
    # Cisco Catalyst 9800 wireless controller
    _T("wlc.version", "cisco_wlc9800", "Version and uptime", "system", ("show version",)),
    _T("wlc.summary", "cisco_wlc9800", "Wireless summary", "wireless", ("show wireless summary",)),
    _T("wlc.aps", "cisco_wlc9800", "Access points", "wireless", ("show ap summary",)),
    _T("wlc.clients", "cisco_wlc9800", "Wireless clients", "wireless", ("show wireless client summary",)),
    _T("wlc.wlans", "cisco_wlc9800", "WLANs", "wireless", ("show wlan summary",)),
    _T("wlc.ha", "cisco_wlc9800", "Redundancy (HA)", "health", ("show redundancy",)),
    _T("wlc.cpu", "cisco_wlc9800", "CPU", "health", ("show processes cpu sorted",)),
    # FortiOS
    _T("fos.status", "fortios", "System status", "system", ("get system status",)),
    _T("fos.perf", "fortios", "Performance status", "health", ("get system performance status",)),
    _T("fos.top", "fortios", "Top processes (one sample)", "health", ("diagnose sys top 1 20 1",)),
    _T("fos.mem", "fortios", "Memory", "health", ("diagnose hardware sysinfo memory",)),
    _T("fos.route", "fortios", "Routing table", "routing", ("get router info routing-table all",)),
    _T("fos.bgp", "fortios", "BGP summary", "routing", ("get router info bgp summary",)),
    _T("fos.vpn", "fortios", "IPsec tunnels", "vpn", ("diagnose vpn tunnel list",)),
    _T("fos.sdwan", "fortios", "SD-WAN health checks", "wan", ("diagnose sys sdwan health-check",),
       "FortiOS 6.4+ (older releases: diagnose sys virtual-wan-link health-check)"),
    _T("fos.ha", "fortios", "HA status", "health", ("get system ha status",)),
    # Junos
    _T("junos.version", "junos", "Version", "system", ("show version",)),
    _T("junos.chassis", "junos", "Chassis hardware", "hardware", ("show chassis hardware",)),
    _T("junos.alarms", "junos", "Chassis alarms", "hardware", ("show chassis alarms",)),
    _T("junos.if_terse", "junos", "Interfaces", "interfaces", ("show interfaces terse",)),
    _T("junos.if_ext", "junos", "Interface details (extensive)", "interfaces", ("show interfaces extensive | no-more",)),
    _T("junos.route", "junos", "Route summary", "routing", ("show route summary",)),
    _T("junos.bgp", "junos", "BGP summary", "routing", ("show bgp summary",)),
    _T("junos.proc", "junos", "Processes", "health", ("show system processes extensive | no-more",)),
    _T("junos.re", "junos", "Routing engine", "health", ("show chassis routing-engine",)),
    # Ruckus ICX
    _T("icx.version", "ruckus_icx", "Version", "system", ("show version",)),
    _T("icx.system", "ruckus_icx", "System (power, fans, temperature)", "hardware", ("show chassis",)),
    _T("icx.if_brief", "ruckus_icx", "Interfaces", "interfaces", ("show interfaces brief",)),
    _T("icx.vlan", "ruckus_icx", "VLANs", "interfaces", ("show vlan",)),
    _T("icx.lldp", "ruckus_icx", "LLDP neighbours", "topology", ("show lldp neighbors",)),
    _T("icx.poe", "ruckus_icx", "PoE", "hardware", ("show inline power",)),
    _T("icx.cpu", "ruckus_icx", "CPU", "health", ("show cpu-utilization",)),
    # Ruckus SmartZone / vSZ CLI
    _T("sz.version", "ruckus_smartzone", "Version", "system", ("show version",)),
    _T("sz.cluster", "ruckus_smartzone", "Cluster state", "health", ("show cluster-state",)),
    # Aruba AOS-CX
    _T("cx.version", "aruba_aoscx", "Version", "system", ("show version",)),
    _T("cx.if_brief", "aruba_aoscx", "Interfaces", "interfaces", ("show interface brief",)),
    _T("cx.lldp", "aruba_aoscx", "LLDP neighbours", "topology", ("show lldp neighbor-info",)),
    _T("cx.env", "aruba_aoscx", "Environment", "hardware", ("show environment fan", "show environment power-supply")),
    # Arista EOS
    _T("eos.version", "arista_eos", "Version", "system", ("show version",)),
    _T("eos.if_status", "arista_eos", "Interface status", "interfaces", ("show interfaces status",)),
    _T("eos.bgp", "arista_eos", "BGP summary", "routing", ("show ip bgp summary",)),
    _T("eos.lldp", "arista_eos", "LLDP neighbours", "topology", ("show lldp neighbors detail",)),
    # Huawei VRP
    _T("vrp.version", "huawei_vrp", "Version", "system", ("display version",)),
    _T("vrp.if_brief", "huawei_vrp", "Interfaces", "interfaces", ("display interface brief",)),
    _T("vrp.cpu", "huawei_vrp", "CPU", "health", ("display cpu-usage",)),
    _T("vrp.bgp", "huawei_vrp", "BGP peers", "routing", ("display bgp peer",)),
    # MikroTik RouterOS
    _T("ros.resource", "mikrotik_routeros", "System resources", "health", ("/system resource print",)),
    _T("ros.if", "mikrotik_routeros", "Interfaces", "interfaces", ("/interface print",)),
    _T("ros.route", "mikrotik_routeros", "Routes", "routing", ("/ip route print",)),
)
BY_ID = {t.id: t for t in TEMPLATES}
# Which platforms the test suite exercises against a simulated SSH device (tests/test_device_access.py). None of them is
# validated against lab hardware by this repository; see docs/nms/VENDOR_SUPPORT_MATRIX.md.
SIMULATED = {"cisco_ios", "fortios", "junos", "ruckus_icx"}

for _t in TEMPLATES:   # a template that is not read-only is a programming error, caught at import and by the tests
    for _c in _t.commands:
        if RANK[classify(_c)[0]] > RANK[L]:
            raise RuntimeError(f"diagnostic template {_t.id} holds a command above LOW_RISK: {_c}")


def platform_of(sw) -> str | None:
    """Command-library platform of an inventory device, or None when no template set applies."""
    ov = (getattr(sw, "access_platform", "") or "").strip()
    if ov:
        return ov if ov in PLATFORMS else None
    vendor = (sw.vendor_override or sw.vendor or "").lower()
    fam = (sw.family_override or sw.family or sw.product_line or "").lower()
    os_ = (sw.os or "").lower()
    if vendor == "cisco":
        if "9800" in fam:
            return "cisco_wlc9800"
        if "nx-os" in os_ or "nexus" in fam:
            return "cisco_nxos"
        if os_ == "asa" or "asa" in fam:
            return None
        return "cisco_ios"
    if vendor == "fortinet":
        return "fortios" if "fortigate" in fam or "fortios" in os_ or (sw.device_type or "") == "firewall" else None
    if vendor == "juniper":
        return "junos"
    if vendor == "ruckus":
        if "smartzone" in fam or "smartzone" in os_:
            return "ruckus_smartzone"
        if "icx" in fam or "fastiron" in os_ or (sw.device_type or "") == "switch":
            return "ruckus_icx"
    return None


def templates_for(platform: str | None) -> list[Template]:
    return [t for t in TEMPLATES if t.platform == platform]


# ------------------------------------------------------------------ terminal line guard
_PASSWORD_PROMPT = re.compile(r"(password|passphrase|secret|passcode)\s*:\s*$", re.I)
_LOGIN_PROMPT = re.compile(r"(user\s*name|login)\s*:\s*$", re.I)    # a console / Telnet login: the answer is not a command
_HISTORY = ("\x1b[A", "\x1b[B", "\x1bOA", "\x1bOB", "\x10", "\x0e")   # up / down, Ctrl-P / Ctrl-N
_FRESH_PROMPT = re.compile(r"\n[^\n]{0,80}?[\w\-.()@/:~\]\[]+\s?[#>$%]\s?$")   # a new line that is only a prompt


@dataclass
class Decision:
    command: str             # the line as tracked (empty for a secret line)
    risk: str
    allowed: bool
    reason: str
    secret: bool = False


@dataclass
class LineGuard:
    """Tracks what the user types and decides, at Enter, whether the line may reach the device.

    The bytes of a line reach the device as they are typed (so echo, tab completion and help work); only the Enter is
    held back. A refused line's Enter is never sent: the gateway sends Ctrl-U (erase the line) and Ctrl-C (abandon it)
    instead, and then drops every keystroke except Ctrl-C until the device shows a fresh prompt on a new line. So the
    refused text can never be submitted later, even on a CLI that ignores Ctrl-U or completes words by itself.

    max_risk: the highest risk let through. A line edited with history or cursor keys cannot be tracked reliably: it
    is refused unless max_risk is HIGH_RISK or above (a change session), where it is let through and recorded as
    "untracked edit".
    """
    max_risk: str = L
    buf: list = field(default_factory=list)
    uncertain: bool = False
    expect_secret: bool = False
    held: bool = False          # a refused line may still sit in the device's line buffer
    expect_login: bool = False

    def device_output(self, text: str) -> None:
        clean = text.replace("\r", "")
        if self.held and _FRESH_PROMPT.search(clean):
            self.held, self.buf, self.uncertain = False, [], False
        tail = clean.split("\n")[-1]
        if _PASSWORD_PROMPT.search(tail):
            self.expect_secret = True
        elif _LOGIN_PROMPT.search(tail):
            self.expect_login = True

    def feed(self, data: str) -> tuple[str, list[Decision]]:
        """Returns (bytes to forward to the device, decisions for completed lines)."""
        out, decisions, i = [], [], 0
        if self.held:
            if "\x03" in data:
                return "\x03", []
            if "\r" in data or "\n" in data:
                return "", [Decision("", M, False, "the device has not shown a fresh prompt since the refused line; press Ctrl-C")]
            return "", []
        while i < len(data):
            ch = data[i]
            if ch == "\x1b":
                seq = data[i:i + 3]
                if any(seq.startswith(h) for h in _HISTORY):
                    self.uncertain = True
                elif seq[:3] in ("\x1b[C", "\x1b[D", "\x1bOC", "\x1bOD") or seq[:2] == "\x1b[":
                    self.uncertain = True
                j = i + 1
                if j < len(data) and data[j] in "[O":
                    j += 1
                    while j < len(data) and not data[j].isalpha() and data[j] != "~":
                        j += 1
                    j += 1
                out.append(data[i:j])
                i = j
                continue
            if ch in "\r\n":
                d = self._decide()
                decisions.append(d)
                if not d.allowed:
                    out.append("\x15\x03")      # erase and abandon the line; nothing more until a fresh prompt
                    self.held = True
                    return "".join(out), decisions
                out.append(ch)
                if ch == "\r" and i + 1 < len(data) and data[i + 1] == "\n":
                    i += 1
                    out.append("\n")
                i += 1
                continue
            if ch in ("\x7f", "\x08"):
                if self.buf:
                    self.buf.pop()
            elif ch in ("\x15", "\x03"):                 # Ctrl-U clears the line, Ctrl-C abandons it
                self.buf, self.uncertain = [], False
            elif ch == "\x17":                           # Ctrl-W: delete the previous word
                while self.buf and self.buf[-1] == " ":
                    self.buf.pop()
                while self.buf and self.buf[-1] != " ":
                    self.buf.pop()
            elif ch == "\t":
                self.buf.append(" ")                     # completion extends the word: prefix rules cover it
            elif ch in _HISTORY or ord(ch) < 32:
                if ch not in ("\x04",):
                    self.uncertain = True
            else:
                self.buf.append(ch)
            out.append(ch)
            i += 1
        return "".join(out), decisions

    def _decide(self) -> Decision:
        line = "".join(self.buf).strip()
        uncertain, secret, login = self.uncertain, self.expect_secret, self.expect_login
        self.buf, self.uncertain, self.expect_secret, self.expect_login = [], False, False, False
        if secret:
            return Decision("", R, True, "answer to a password prompt (not recorded)", secret=True)
        if login and not uncertain and " " not in line:
            return Decision(f"<login {line[:64]}>", R, True, "answer to a login prompt")
        risk, why = classify(line, config_context=RANK[self.max_risk] >= RANK[H])
        if uncertain:
            if RANK[self.max_risk] >= RANK[H] and RANK[risk] < RANK[D]:
                return Decision(line, risk, True, "untracked edit (history / cursor keys)")
            return Decision(line, worst(risk, M), False, "the line was edited with history or cursor keys; press Ctrl-U and type it again")
        if RANK[risk] > RANK[self.max_risk]:
            hint = ("configuration changes need an approved change request" if risk in (H, M) else
                    "destructive commands are never allowed from the terminal" if risk == D else "")
            return Decision(line, risk, False, "; ".join(x for x in (why, f"{risk} is above this session's limit ({self.max_risk})", hint) if x))
        return Decision(line, risk, True, why)
