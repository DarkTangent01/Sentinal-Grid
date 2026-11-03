"""Network-device syslog: Cisco IOS / IOS-XE / NX-OS / Catalyst 9800 (`%FACILITY-SEVERITY-MNEMONIC: text`) and Ruckus
ICX FastIron (`Facility: text`), normalised into the shared `events` table.

event_type = "netdev", event_subtype = one of KINDS below (or "other"), log_id = the vendor mnemonic
(e.g. "OSPF-5-ADJCHG"), app = "cisco" | "ruckus". Category is "security" for access-control and intrusion-relevant
events (login failures, port security, DHCP snooping, ARP inspection, rogue AP, 802.1X failures) and "system"
otherwise. Interfaces go to src_intf, the remote side of the event (login source, routing neighbour) to src_ip /
dst_ip, MAC addresses to src_mac, the device's own host name from the syslog header to src_name.

Every message keeps its raw line, except that `password`, `secret`, `key` and `community` arguments in commands and
configuration messages are masked before storage (devices log CLI commands verbatim).
"""
from __future__ import annotations

import re

# Cisco severity digit → normalised severity
CISCO_SEV = {0: "critical", 1: "critical", 2: "high", 3: "medium", 4: "medium", 5: "low", 6: "informational", 7: "informational"}
SECURITY_KINDS = {"login_failed", "port_security", "dhcp_snooping", "arp_inspection", "rogue_ap", "nac_failed", "bpdu_guard", "stp_guard"}

_CISCO = re.compile(r"%(?P<fac>[A-Z0-9_]+(?:-[A-Z0-9_]+)?)-(?P<sev>[0-7])-(?P<mn>[A-Z0-9_]+)\s*:\s*(?P<text>.*)$")
# syslog header host: "<pri>Mmm dd hh:mm:ss HOST ..." (RFC 3164) or "<pri>1 TIMESTAMP HOST ..." (RFC 5424)
_HOST_3164 = re.compile(r"^(?:<\d{1,3}>)?(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+)(?P<host>[A-Za-z0-9._\-]+)\s")
_HOST_5424 = re.compile(r"^(?:<\d{1,3}>)?1\s+\S+\s+(?P<host>[A-Za-z0-9._\-]+)\s")
_IP = r"(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]*:[0-9a-fA-F:]+)"
_IFACE = r"((?:[A-Z][A-Za-z\-]*?Ethernet|Gi|Te|Fa|Tw|Fo|Hu|Eth|ethernet|Port-channel|Po|Vlan|Loopback|Tunnel|mgmt|ve|lag)\s?[0-9][0-9/.:]*)"
_MAC_DOT = r"([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}|[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})"

_REDACT = re.compile(r"\b(password|secret|key-string|key|community|enable\s+secret|pre-shared-key|auth-key|priv-key)(\s+(?:\d\s+)?)(\S+)", re.I)


def redact(text: str) -> str:
    """Mask credential arguments in logged commands: 'username x password 0 abc' → 'username x password 0 ******'."""
    return _REDACT.sub(lambda m: f"{m.group(1)}{m.group(2)}******", text)


def _mac(v: str) -> str:
    h = re.sub(r"[^0-9a-fA-F]", "", v).lower()
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)) if len(h) == 12 else ""


def _first(pattern: str, text: str, flags=re.I) -> str:
    m = re.search(pattern, text, flags)
    return m.group(1) if m else ""


def header_host(line: str) -> str:
    m = _HOST_5424.match(line) or _HOST_3164.match(line)
    return m.group("host") if m else ""


# ------------------------------------------------------------------ Cisco
def _cisco_kind(fac: str, mn: str, text: str) -> tuple[str, str]:
    """→ (kind, action)."""
    key = f"{fac}-{mn}"
    t = text.lower()
    if mn in ("CONFIG_I", "VSHD_SYSLOG_CONFIG_I", "CFGLOG_LOGGEDCMD") or key.startswith("PARSER-") and "LOGGEDCMD" in mn:
        return "config_change", "config"
    if fac in ("SEC_LOGIN", "SSH", "AUTHPRIV", "AAA", "LOGIN") or "LOGIN" in mn:
        if "FAIL" in mn or "failed" in t or "failure" in t or "invalid" in t:
            return "login_failed", "logon-fail"
        if "SUCCESS" in mn or "success" in t:
            return "login_success", "logon"
    if fac in ("OSPF", "OSPFV3") and ("ADJCHG" in mn or "ADJCHANGE" in mn):
        return "ospf_adjacency", "down" if re.search(r"\bto (down|init|attempt)\b|neighbor down", t) else "up"
    if fac == "BGP" and ("ADJCHANGE" in mn or mn == "NOTIFICATION"):
        return "bgp_adjacency", "down" if (" down" in t or mn == "NOTIFICATION") else "up"
    if fac == "DUAL" and "NBRCHANGE" in mn:
        return "eigrp_adjacency", "down" if " down" in t else "up"
    if fac in ("HSRP", "STANDBY", "VRRP") and "STATECHANGE" in mn:
        return "fhrp_state", "active" if re.search(r"->\s*(active|master)", t) else "standby" if re.search(r"->\s*(standby|backup)", t) else "change"
    if fac == "SPANTREE":
        if "BPDUGUARD" in mn:
            return "bpdu_guard", "block"
        if "ROOTGUARD" in mn or "LOOPGUARD" in mn:
            return "stp_guard", "block"
        return "stp_change", "change"
    if fac == "PM" and "ERR_DISABLE" in mn:
        return ("bpdu_guard", "block") if "bpduguard" in t else ("err_disable", "block")
    if fac == "PORT_SECURITY":
        return "port_security", "block"
    if fac == "DHCP_SNOOPING":
        return "dhcp_snooping", "deny"
    if fac == "SW_DAI":
        return "arp_inspection", "deny"
    if fac == "SW_MATM" and "MACFLAP" in mn:
        return "mac_flap", "change"
    if fac in ("LINK", "LINEPROTO") and "UPDOWN" in mn:
        return "link_state", "down" if t.rstrip(".").endswith("down") else "up"
    if fac in ("DOT1X", "MAB", "AUTHMGR", "SESSION_MGR") and ("FAIL" in mn or "fail" in t):
        return "nac_failed", "deny"
    if "rogue" in t or "ROGUE" in fac or "ROGUE" in mn:
        return "rogue_ap", "detected"
    if fac == "SYS" and mn in ("RESTART", "RELOAD"):
        return "device_restart", "restart"
    return "other", ""


def parse_cisco(line: str) -> dict | None:
    m = _CISCO.search(line)
    if not m:
        return None
    fac, sev, mn, text = m.group("fac"), int(m.group("sev")), m.group("mn"), redact(m.group("text").strip())
    kind, action = _cisco_kind(fac.upper(), mn.upper(), text)
    out = {"vendor": "cisco", "mnemonic": f"{fac}-{sev}-{mn}", "kind": kind, "action": action, "severity": CISCO_SEV[sev], "text": text,
           "iface": _first(_IFACE, text).rstrip(".,:;"), "src_ip": "", "dst_ip": "", "user": "", "mac": ""}
    if kind in ("login_failed", "login_success"):
        out["user"] = _first(r"\[user:\s*([^\]]+)\]", text) or _first(r"for user\s+'?([^\s']+)", text) or _first(r"user\s+(\S+)", text)
        out["src_ip"] = _first(r"\[source:\s*" + _IP, text) or _first(r"from\s+(?:host\s+)?" + _IP, text)
    elif kind == "config_change":
        out["user"] = _first(r"\bby\s+([^\s(]+)", text) or _first(r"User:\s*([^\s,]+)", text)
        out["src_ip"] = _first(r"\(" + _IP + r"\)", text) or _first(r"on\s+" + _IP, text) or _first(r"from\s+" + _IP, text)
    elif kind in ("ospf_adjacency", "bgp_adjacency", "eigrp_adjacency"):
        out["dst_ip"] = _first(r"(?:nbr|neighbor|neighbour)\s+" + _IP, text)
    elif kind in ("port_security", "dhcp_snooping", "arp_inspection", "mac_flap"):
        out["mac"] = _mac(_first(r"(?:mac(?: address| sa)?:?\s*|host\s+)" + _MAC_DOT, text) or _first(_MAC_DOT, text))
        out["src_ip"] = _first(r"/" + _IP + r"/", text) if kind == "arp_inspection" else ""
    return out


# ------------------------------------------------------------------ Ruckus ICX (FastIron)
_RUCKUS = re.compile(r"\b(?P<fac>Security|System|STP|DHCPC|DHCPS|DHCP|OSPF|BGP|PORT|MAC|SNOOP|DOT1X|MAC-AUTH|VRRP|VRRPE|LLDP|Stack|SYSLOG)\s*:\s*(?P<text>.*)$")


def _ruckus_kind(fac: str, t: str) -> tuple[str, str]:
    if "running-config was changed" in t or "startup-config was changed" in t or "config was changed" in t:
        return "config_change", "config"
    if "login" in t or "logged in" in t:
        if "fail" in t or "invalid" in t or "denied" in t:
            return "login_failed", "logon-fail"
        return "login_success", "logon"
    if fac == "OSPF" or "ospf" in t:
        if "nbr" in t or "neighbor" in t or "adjacency" in t:
            return "ospf_adjacency", "down" if "down" in t else "up"
    if fac == "BGP" or "bgp" in t:
        if "peer" in t or "neighbor" in t:
            return "bgp_adjacency", "down" if "down" in t else "up"
    if fac in ("VRRP", "VRRPE") or "vrrp" in t:
        return "fhrp_state", "active" if "master" in t else "standby" if "backup" in t else "change"
    if "bpdu" in t and ("guard" in t or "violation" in t):
        return "bpdu_guard", "block"
    if fac == "STP" or "spanning" in t or "rootbridge" in t or "root bridge" in t:
        return "stp_change", "change"
    if "dhcp" in t and ("snoop" in t or "untrusted" in t) and ("drop" in t or "untrusted" in t or "invalid" in t):
        return "dhcp_snooping", "deny"
    if "arp" in t and ("inspection" in t or "invalid" in t):
        return "arp_inspection", "deny"
    if "security violation" in t or "port security" in t or "port-security" in t:
        return "port_security", "block"
    if (fac in ("DOT1X", "MAC-AUTH") or "802.1x" in t or "mac-auth" in t) and "fail" in t:
        return "nac_failed", "deny"
    if re.search(r"interface .*state (up|down)", t) or re.search(r"port .* (up|down)\b", t):
        return "link_state", "down" if re.search(r"\bdown\b", t) else "up"
    if "cold start" in t or "warm start" in t or "reload" in t:
        return "device_restart", "restart"
    return "other", ""


def parse_ruckus(line: str) -> dict | None:
    m = _RUCKUS.search(line)
    if not m:
        return None
    fac, text = m.group("fac"), redact(m.group("text").strip())
    t = text.lower()
    kind, action = _ruckus_kind(fac.upper(), t)
    sev = {"login_failed": "medium", "port_security": "high", "dhcp_snooping": "high", "arp_inspection": "high", "bpdu_guard": "high",
           "config_change": "low", "ospf_adjacency": "medium" if action == "down" else "low", "bgp_adjacency": "medium" if action == "down" else "low",
           "fhrp_state": "medium", "nac_failed": "low", "link_state": "low" if action == "down" else "informational",
           "device_restart": "high"}.get(kind, "informational")
    out = {"vendor": "ruckus", "mnemonic": f"ICX-{fac.upper()}", "kind": kind, "action": action, "severity": sev, "text": text,
           "iface": _first(r"(?:ethernet|port|interface)\s+([0-9]+/[0-9]+/[0-9]+)", text), "src_ip": "", "dst_ip": "", "user": "", "mac": ""}
    if kind in ("login_failed", "login_success", "config_change"):
        out["user"] = _first(r"(?:user(?:name)?|by)\s+'?([A-Za-z0-9_.@\-]+)", text)
        out["src_ip"] = _first(r"(?:src ip|from(?: src ip)?|client)\s+" + _IP, text)
    elif kind in ("ospf_adjacency", "bgp_adjacency"):
        out["dst_ip"] = _first(r"(?:nbr|neighbor|peer)\s+" + _IP, text)
    elif kind in ("port_security", "dhcp_snooping", "arp_inspection"):
        out["mac"] = _mac(_first(_MAC_DOT, text))
        out["src_ip"] = _first(r"ip\s+" + _IP, text)
    return out


# ------------------------------------------------------------------ into the events table
def parse(line: str) -> dict | None:
    """Vendor-detect and parse one line; None when it is not a recognised network-device message."""
    return parse_cisco(line) or parse_ruckus(line)


def to_event(src: dict, line: str, p: dict, base) -> dict:
    """Build an `events` row from a parsed message (`base` is generic._base, passed in to avoid an import cycle)."""
    extra = {"type": "netdev", "subtype": p["kind"], "logid": p["mnemonic"], "srcip": p["src_ip"], "dstip": p["dst_ip"], "user": p["user"][:128],
             "srcintf": p["iface"][:64], "srcmac": p["mac"], "action": p["action"], "app": p["vendor"], "msg": p["text"][:1000],
             "srcname": header_host(line)[:128]}
    ev = base(src, None, extra, redact(line.strip()))
    ev.update({"category": "security" if p["kind"] in SECURITY_KINDS else "system", "event_type": "netdev", "event_subtype": p["kind"],
               "severity": p["severity"], "orig_severity": p["mnemonic"], "action": p["action"], "orig_action": p["action"]})
    return ev


__all__ = ["parse", "parse_cisco", "parse_ruckus", "to_event", "redact", "header_host"]
