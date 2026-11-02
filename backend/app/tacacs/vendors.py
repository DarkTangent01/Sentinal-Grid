"""Vendor capability matrix, command categories and privilege semantics for TACACS+ clients.

Privilege levels do not mean the same thing across vendors, and not every vendor sends per-command authorization
requests, so nothing here is shared blindly:

* Cisco IOS / IOS-XE: exec authorization returns priv-lvl (0-15; 1 = user EXEC, 15 = full). With
  `aaa authorization commands <lvl>` every command is authorised individually, and command accounting is available.
* Ruckus ICX FastIron: privilege is returned as the optional AV pair foundry-privlvl, where **0 is super-user**, 4 is
  port-config and 5 is read-only (the opposite direction to Cisco). FastIron supports command authorization and
  accounting (`aaa authorization commands 0 default tacacs+`, `aaa accounting commands 0 default start-stop tacacs+`).
* FortiGate FortiOS: TACACS+ authenticates administrators; with `set authorization enable` the server returns the admin
  profile (optional AV pair admin_prof, service fortigate). FortiOS does **not** send per-command authorization
  requests, so command rules cannot be enforced on FortiGates; accounting support depends on the FortiOS release.
"""
from __future__ import annotations

import re

CATEGORIES = {
    "read_only": "Read-only inspection (show / get / ping / traceroute)",
    "interface": "Interface configuration",
    "vlan": "VLAN configuration",
    "routing": "Routing changes",
    "firewall_policy": "Firewall policy / ACL changes",
    "vpn": "VPN changes",
    "system": "System administration (hostname, NTP, logging, SNMP, clock)",
    "aaa_users": "User and AAA administration",
    "config_save_restore": "Configuration save / copy / restore",
    "reload_reset": "Reload, reboot, erase, factory reset",
    "config_mode": "Entering configuration mode",
    "other": "Not categorised",
}

# ordered: the first matching category wins (destructive and AAA checks come before generic ones)
COMMAND_CATALOG: dict[str, list[tuple[str, str]]] = {
    "cisco": [
        ("reload_reset", r"^(reload|erase|format|delete|write erase|factory-reset)\b"),
        ("aaa_users", r"^(no )?(username|aaa|tacacs|tacacs-server|radius|radius-server|enable (secret|password)|line)\b"),
        ("config_save_restore", r"^(write( memory| mem)?$|write memory|copy|configure replace|archive)\b"),
        ("config_mode", r"^configure( terminal)?$"),
        ("read_only", r"^(show|ping|traceroute|terminal|dir|more|who|exit|end|disable|enable$)\b"),
        ("firewall_policy", r"^(no )?(ip access-list|access-list|ipv6 access-list|ip access-group|object-group)\b"),
        ("vpn", r"^(no )?(crypto|tunnel)\b"),
        ("routing", r"^(no )?(router|ip route|ipv6 route|ip routing|network|neighbor|redistribute)\b"),
        ("vlan", r"^(no )?(vlan|switchport (access|trunk) vlan|spanning-tree vlan)\b"),
        ("interface", r"^(no )?(interface|shutdown|switchport|speed|duplex|description|channel-group|ip address|power inline)\b"),
        ("system", r"^(no )?(hostname|ntp|logging|snmp-server|clock|boot|license|service|ip domain|ip name-server|banner)\b"),
    ],
    "ruckus": [
        ("reload_reset", r"^(reload|erase|boot system|factory|delete)\b"),
        ("aaa_users", r"^(no )?(username|aaa|tacacs-server|radius-server|enable (super-user-password|port-config-password|read-only-password)|ip ssh|crypto key)\b"),
        ("config_save_restore", r"^(write memory|wr mem|copy)\b"),
        ("config_mode", r"^(configure|conf)( terminal| t)?$"),
        ("read_only", r"^(show|ping|traceroute|exit|end|terminal|quit|skip-page-display)\b"),
        ("firewall_policy", r"^(no )?(ip access-list|access-list|mac access-list|ip access-group)\b"),
        ("routing", r"^(no )?(ip route|router|ospf|ip router-id|bgp)\b"),
        ("vlan", r"^(no )?(vlan|tagged|untagged|router-interface|spanning-tree)\b"),
        ("interface", r"^(no )?(interface|disable|enable$|port-name|speed-duplex|inline power|lag)\b"),
        ("system", r"^(no )?(hostname|ntp|logging|snmp-server|clock|sntp|banner|ip dns)\b"),
    ],
    "fortinet": [
        ("reload_reset", r"^execute (reboot|shutdown|factoryreset|formatlogdisk)\b"),
        ("config_save_restore", r"^execute (backup|restore)\b"),
        ("aaa_users", r"^config (system admin|system accprofile|user|system api-user)\b"),
        ("read_only", r"^(get|show|diagnose|execute (ping|traceroute|telnet|ssh))\b"),
        ("firewall_policy", r"^config firewall\b"),
        ("vpn", r"^config vpn\b"),
        ("routing", r"^config router\b"),
        ("interface", r"^config system (interface|zone|switch-interface)\b"),
        ("system", r"^config (system|log)\b"),
    ],
}
COMMAND_CATALOG["other"] = COMMAND_CATALOG["cisco"]
_COMPILED = {v: [(c, re.compile(p)) for c, p in rules] for v, rules in COMMAND_CATALOG.items()}  # case-sensitive, like the server

CAPABILITIES = {
    "cisco": {"label": "Cisco IOS / IOS-XE", "authentication": "supported", "exec_authorization": "supported (priv-lvl 0-15)",
              "command_authorization": "supported (per privilege level)", "accounting_exec": "supported", "accounting_commands": "supported",
              "privilege": "priv-lvl: 1 user EXEC … 15 full; custom levels need matching 'privilege' commands on the device",
              "enforcement": "per-command", "notes": "IOS-XE 16.x / 17.x and IOS 15.x"},
    "ruckus": {"label": "Ruckus ICX FastIron", "authentication": "supported", "exec_authorization": "supported (foundry-privlvl)",
               "command_authorization": "supported (aaa authorization commands 0)", "accounting_exec": "supported",
               "accounting_commands": "supported", "privilege": "foundry-privlvl: 0 super-user, 4 port-config, 5 read-only (lower = more)",
               "enforcement": "per-command", "notes": "FastIron 08.0.x / 09.0.x / 10.0.x"},
    "fortinet": {"label": "FortiGate FortiOS", "authentication": "supported", "exec_authorization": "admin profile (admin_prof, service fortigate)",
                 "command_authorization": "not supported (FortiOS does not send per-command authorization)",
                 "accounting_exec": "release-dependent", "accounting_commands": "release-dependent (check 'config log tacacs+accounting')",
                 "privilege": "admin profile name (accprofile), not a numeric level", "enforcement": "profile-only",
                 "notes": "FortiOS 6.4 / 7.x; the admin must exist as a remote (wildcard) admin bound to the TACACS+ server"},
    "other": {"label": "Other TACACS+ device", "authentication": "supported", "exec_authorization": "priv-lvl (assumed Cisco-like)",
              "command_authorization": "unknown: verify per device", "accounting_exec": "unknown", "accounting_commands": "unknown",
              "privilege": "verify the device's semantics", "enforcement": "unverified", "notes": ""},
}

# default per-vendor privilege for the built-in role templates
ROLE_TEMPLATES = [
    {"name": "network-read-only", "description": "Network Read-Only: inspection commands only", "privileged": False,
     "vendor_profiles": {"cisco": {"priv_lvl": 1}, "ruckus": {"priv_lvl": 5}, "fortinet": {"admin_profile": "prof_readonly"}},
     "command_categories": ["read_only"]},
    {"name": "network-operator", "description": "Network Operator: inspection plus interface / VLAN changes", "privileged": False,
     "vendor_profiles": {"cisco": {"priv_lvl": 15}, "ruckus": {"priv_lvl": 4}, "fortinet": {"admin_profile": "prof_operator"}},
     "command_categories": ["read_only", "config_mode", "interface", "vlan"]},
    {"name": "network-engineer", "description": "Network Engineer: configuration except AAA, reload and factory reset", "privileged": True,
     "vendor_profiles": {"cisco": {"priv_lvl": 15}, "ruckus": {"priv_lvl": 0}, "fortinet": {"admin_profile": "prof_engineer"}},
     "command_categories": ["read_only", "config_mode", "interface", "vlan", "routing", "firewall_policy", "vpn", "system", "config_save_restore"]},
    {"name": "network-administrator", "description": "Network Administrator: everything", "privileged": True,
     "vendor_profiles": {"cisco": {"priv_lvl": 15}, "ruckus": {"priv_lvl": 0}, "fortinet": {"admin_profile": "super_admin"}},
     "command_categories": list(CATEGORIES)},
    {"name": "security-administrator", "description": "Security Administrator: firewall policy, VPN, AAA", "privileged": True,
     "vendor_profiles": {"cisco": {"priv_lvl": 15}, "ruckus": {"priv_lvl": 0}, "fortinet": {"admin_profile": "prof_security"}},
     "command_categories": ["read_only", "config_mode", "firewall_policy", "vpn", "aaa_users", "config_save_restore"]},
    {"name": "emergency-administrator", "description": "Emergency Administrator: break-glass, every use alerts", "privileged": True,
     "vendor_profiles": {"cisco": {"priv_lvl": 15}, "ruckus": {"priv_lvl": 0}, "fortinet": {"admin_profile": "super_admin"}},
     "command_categories": list(CATEGORIES)},
]


def normalize_cmd(cmd: str) -> str:
    """Cisco appends ' <cr>' to authorised command lines; collapse whitespace."""
    c = re.sub(r"\s*<cr>\s*$", "", cmd or "")
    return re.sub(r"\s+", " ", c).strip()


def categorize(vendor: str, cmd: str) -> str:
    c = normalize_cmd(cmd)
    if not c:
        return ""
    for cat, rx in _COMPILED.get(vendor if vendor in _COMPILED else "other", _COMPILED["other"]):
        if rx.search(c):
            return cat
    return "other"


def category_regex(vendor: str, category: str) -> str | None:
    pats = [p for c, p in COMMAND_CATALOG.get(vendor if vendor in COMMAND_CATALOG else "other", []) if c == category]
    return "|".join(f"(?:{p})" for p in pats) if pats else None


def per_command(vendor: str) -> bool:
    return CAPABILITIES.get(vendor, CAPABILITIES["other"])["enforcement"] == "per-command"
