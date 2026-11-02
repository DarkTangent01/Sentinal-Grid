"""Capability registry and canonical forms of the FortiGate resources the IaC module manages.

Every managed type has one canonical, vendor-neutral-ish dict shape used for desired state, observed state, diffs and
plans. Conversion to and from FortiOS cmdb objects happens only here, so a second vendor adds its own converters
without touching the diff / plan / workflow code.

Coverage is deliberately partial and explicit: fields outside a type's `fields` list are neither compared nor
written (the desired-state schema rejects them instead of silently dropping them), and types listed in
UNSUPPORTED are reported as such in imports and capability checks.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json

# managed types, in dependency order for create / update (deletes run in reverse)
TYPES: dict[str, dict] = {
    "address": {"path": "/api/v2/cmdb/firewall/address", "key": "name", "order": 10, "label": "Firewall address",
                "fields": ["type", "subnet", "start_ip", "end_ip", "fqdn", "macaddr", "interface", "comment"]},
    "service": {"path": "/api/v2/cmdb/firewall.service/custom", "key": "name", "order": 10, "label": "Service (custom)",
                "fields": ["protocol", "tcp", "udp", "udplite", "sctp", "protocol_number", "icmp_type", "comment"]},
    "address_group": {"path": "/api/v2/cmdb/firewall/addrgrp", "key": "name", "order": 20, "label": "Address group",
                      "fields": ["members", "comment"]},
    "service_group": {"path": "/api/v2/cmdb/firewall.service/group", "key": "name", "order": 20, "label": "Service group",
                      "fields": ["members", "comment"]},
    "static_route": {"path": "/api/v2/cmdb/router/static", "key": "seq-num", "order": 30, "label": "Static route",
                     "fields": ["dst", "gateway", "device", "sdwan_zone", "blackhole", "distance", "status", "comment"]},
    "policy": {"path": "/api/v2/cmdb/firewall/policy", "key": "policyid", "order": 40, "label": "Firewall policy",
               "fields": ["name", "srcintf", "dstintf", "srcaddr", "dstaddr", "service", "internet_service", "internet_service_name",
                          "internet_service_group", "internet_service_custom", "action", "schedule", "nat", "logtraffic", "status",
                          "comments"]},
    "system_global": {"path": "/api/v2/cmdb/system/global", "key": None, "order": 50, "label": "System global (selected settings)",
                      "fields": ["admintimeout", "admin-https-redirect", "strong-crypto", "admin-lockout-threshold",
                                 "admin-lockout-duration", "admin-telnet", "admin-sport", "admin-ssh-port"]},
    "syslog": {"path": "/api/v2/cmdb/log.syslogd/setting", "key": None, "order": 50, "label": "Syslog (log.syslogd setting)",
               "fields": ["status", "server", "port", "mode", "facility", "format"]},
}
# read only, to validate references
REFERENCE_ONLY = {"interface": "/api/v2/cmdb/system/interface", "zone": "/api/v2/cmdb/system/zone",
                  "schedule_onetime": "/api/v2/cmdb/firewall.schedule/onetime",
                  "schedule_recurring": "/api/v2/cmdb/firewall.schedule/recurring"}
UNSUPPORTED = {
    "vpn_ipsec": "IPsec phase 1/2 (pre-shared keys and certificates are secrets): drift is visible through VPN monitoring only",
    "sdwan": "SD-WAN members, health checks and rules: observed by the ISP module, not managed",
    "admin": "Administrator accounts: changes are audited (Identity / config drift), never written",
    "address6": "IPv6 addresses / groups and policies6: not yet supported",
    "vip": "Virtual IPs / DNAT: not yet supported",
    "security_profiles": "UTM profiles (web filter, IPS, AV, application control): not yet supported",
}
SINGLETONS = {t for t, d in TYPES.items() if d["key"] is None}
LIST_FIELDS = {"members", "tcp", "udp", "udplite", "sctp", "macaddr", "sdwan_zone", "srcintf", "dstintf", "srcaddr", "dstaddr", "service",
               "internet_service_name", "internet_service_group", "internet_service_custom"}
ISDB_FIELDS = (("internet_service_name", "internet-service-name"), ("internet_service_group", "internet-service-group"),
               ("internet_service_custom", "internet-service-custom"))
PORT_FIELDS = (("tcp", "tcp-portrange"), ("udp", "udp-portrange"), ("udplite", "udplite-portrange"), ("sctp", "sctp-portrange"))
PORT_PROTOCOLS = ("TCP/UDP/SCTP", "TCP/UDP/UDP-Lite/SCTP")
SECRET_WORDS = ("password", "passwd", "secret", "psk", "key", "token", "private", "passphrase")


def canonical_hash(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _names(v) -> list[str]:
    if isinstance(v, list):
        return sorted({(x.get("name") if isinstance(x, dict) else str(x)) for x in v if x not in (None, "")} - {None})
    if isinstance(v, str) and v:
        return sorted(set(v.split()))
    return []


def to_cidr(v: str) -> str:
    """'10.0.0.0 255.255.255.0' / '10.0.0.0/24' / '10.0.0.1' → '10.0.0.0/24' (raises ValueError)."""
    v = (v or "").strip()
    if " " in v:
        a, m = v.split()[:2]
        return str(ipaddress.ip_network(f"{a}/{m}", strict=False))
    return str(ipaddress.ip_network(v, strict=False))


def to_mask(cidr: str) -> str:
    n = ipaddress.ip_network(cidr, strict=False)
    return f"{n.network_address} {n.netmask}"


def _ports(v) -> list[str]:
    if isinstance(v, list):
        items = [str(x) for x in v]
    else:
        items = str(v or "").split()
    return sorted({x.strip() for x in items if x.strip() and x.strip() != "0"})


# ------------------------------------------------------------------ FortiOS cmdb -> canonical
def from_cmdb(rtype: str, o: dict) -> tuple[str, dict]:
    """(key, canonical) for one cmdb object. Unknown/secret fields are never copied."""
    g = o.get
    if rtype == "address":
        typ = g("type") or "ipmask"
        # interface-subnet addresses follow an interface ('interface'); others may be bound to one ('associated-interface')
        c = {"type": typ, "comment": g("comment") or "",
             "interface": (g("interface") if typ == "interface-subnet" else g("associated-interface")) or ""}
        if typ in ("ipmask", "interface-subnet"):
            try:
                c["subnet"] = to_cidr(g("subnet") or "0.0.0.0 0.0.0.0")
            except ValueError:
                c["subnet"] = g("subnet") or ""
        elif typ == "iprange":
            c["start_ip"], c["end_ip"] = g("start-ip") or "", g("end-ip") or ""
        elif typ == "fqdn":
            c["fqdn"] = g("fqdn") or ""
        elif typ == "mac":
            c["macaddr"] = sorted({(m.get("macaddr") if isinstance(m, dict) else str(m)).lower() for m in g("macaddr") or []} - {None, ""})
        # other types (dynamic, geography, wildcard, ...) keep only their type: the import skips them as unsupported
        return str(g("name")), _clean(c)
    if rtype == "service":
        proto = g("protocol") or "TCP/UDP/SCTP"
        c = {"protocol": proto, "comment": g("comment") or ""}
        if g("proxy") == "enable":
            c["proxy"] = "enable"  # explicit-proxy services are not managed; the import skips them
        if proto in PORT_PROTOCOLS:
            for k, f in PORT_FIELDS:
                p = _ports(g(f))
                if p:
                    c[k] = p
        elif proto == "IP":
            c["protocol_number"] = int(g("protocol-number") or 0)
        elif proto in ("ICMP", "ICMP6"):
            if g("icmptype") not in (None, "", 4294967295):
                c["icmp_type"] = int(g("icmptype"))
        return str(g("name")), _clean(c)
    if rtype in ("address_group", "service_group"):
        return str(g("name")), _clean({"members": _names(g("member")), "comment": g("comment") or ""})
    if rtype == "static_route":
        try:
            dst = to_cidr(g("dst") or "0.0.0.0 0.0.0.0")
        except ValueError:
            dst = g("dst") or ""
        c = {"dst": dst, "gateway": g("gateway") or "0.0.0.0", "device": g("device") or "", "sdwan_zone": _names(g("sdwan-zone")),
             "distance": int(g("distance") or 10), "status": g("status") or "enable", "comment": g("comment") or ""}
        if g("blackhole") == "enable":
            c["blackhole"] = "enable"
        for f in ("dstaddr", "internet-service"):  # route variants the canonical form cannot express; the import skips them
            if g(f) not in (None, "", 0, []):
                c["unsupported"] = f
        return str(g("seq-num")), _clean(c)
    if rtype == "policy":
        c = {"name": g("name") or "", "srcintf": _names(g("srcintf")), "dstintf": _names(g("dstintf")),
             "srcaddr": _names(g("srcaddr")), "dstaddr": _names(g("dstaddr")), "service": _names(g("service")),
             "action": g("action") or "deny", "schedule": g("schedule") or "always", "nat": g("nat") or "disable",
             "logtraffic": g("logtraffic") or "utm", "status": g("status") or "enable", "comments": g("comments") or ""}
        if g("internet-service") == "enable":
            c["internet_service"] = "enable"
            for k, f in ISDB_FIELDS:
                c[k] = _names(g(f))
        # match criteria the canonical form cannot express: recorded so the import skips the policy instead of
        # emitting a partial (and therefore wrong) copy of it
        extra = [f for f in ("internet-service-src", "internet-service-custom-group", "internet-service-fortiguard")
                 if g(f) not in (None, "", "disable", [])]
        extra += [f for f in ("srcaddr6", "dstaddr6") if g(f)]
        if extra:
            c["unsupported"] = ", ".join(extra)
        return str(g("policyid")), _clean(c)
    if rtype in SINGLETONS:
        return "", {k: o[k] for k in TYPES[rtype]["fields"] if k in o}
    raise KeyError(rtype)


def _clean(c: dict) -> dict:
    return {k: v for k, v in c.items() if v not in (None, "", []) or k in ("comment", "comments")}


# ------------------------------------------------------------------ canonical -> FortiOS cmdb body
def to_cmdb(rtype: str, key: str, c: dict) -> dict:
    if rtype == "address":
        b = {"name": key, "type": c.get("type", "ipmask"), "comment": c.get("comment", "")}
        if b["type"] in ("ipmask", "interface-subnet"):
            b["subnet"] = to_mask(c["subnet"])
        elif b["type"] == "iprange":
            b["start-ip"], b["end-ip"] = c["start_ip"], c["end_ip"]
        elif b["type"] == "fqdn":
            b["fqdn"] = c["fqdn"]
        elif b["type"] == "mac":
            b["macaddr"] = [{"macaddr": m} for m in c.get("macaddr", [])]
        if c.get("interface"):
            b["interface" if b["type"] == "interface-subnet" else "associated-interface"] = c["interface"]
        return b
    if rtype == "service":
        b = {"name": key, "protocol": c.get("protocol", "TCP/UDP/SCTP"), "comment": c.get("comment", "")}
        for k, f in PORT_FIELDS:
            if c.get(k):
                b[f] = " ".join(c[k])
        if "protocol_number" in c:
            b["protocol-number"] = c["protocol_number"]
        if "icmp_type" in c:
            b["icmptype"] = c["icmp_type"]
        return b
    if rtype in ("address_group", "service_group"):
        return {"name": key, "member": [{"name": m} for m in c.get("members", [])], "comment": c.get("comment", "")}
    if rtype == "static_route":
        b = {"seq-num": int(key), "dst": to_mask(c["dst"]), "gateway": c.get("gateway", "0.0.0.0"), "device": c.get("device", ""),
             "distance": c.get("distance", 10), "status": c.get("status", "enable"), "comment": c.get("comment", "")}
        # optional fields are sent only when used, so routes keep working on FortiOS versions without them
        if c.get("sdwan_zone"):
            b["sdwan-zone"] = [{"name": z} for z in c["sdwan_zone"]]
        if c.get("blackhole"):
            b["blackhole"] = c["blackhole"]
        return b
    if rtype == "policy":
        b = {"policyid": int(key), "name": c.get("name", ""), "action": c.get("action", "deny"), "schedule": c.get("schedule", "always"),
             "nat": c.get("nat", "disable"), "logtraffic": c.get("logtraffic", "utm"), "status": c.get("status", "enable"),
             "comments": c.get("comments", "")}
        for f in ("srcintf", "dstintf", "srcaddr", "dstaddr", "service"):
            b[f] = [{"name": n} for n in c.get(f, [])]
        b["internet-service"] = c.get("internet_service", "disable")
        if b["internet-service"] == "enable":
            for k, f in ISDB_FIELDS:
                b[f] = [{"name": n} for n in c.get(k, [])]
        return b
    if rtype in SINGLETONS:
        return {k: v for k, v in c.items() if k in TYPES[rtype]["fields"]}
    raise KeyError(rtype)


def redact(obj, _depth: int = 0):
    """Mask secret-looking keys and FortiOS 'ENC ...' values anywhere in a structure (logs, errors, stored bodies)."""
    if _depth > 20:
        return "…"
    if isinstance(obj, dict):
        return {k: ("***" if any(w in str(k).lower() for w in SECRET_WORDS) and not str(k).lower().endswith(("_keys", "keys"))
                    else redact(v, _depth + 1)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v, _depth + 1) for v in obj]
    if isinstance(obj, str):
        import re
        s = re.sub(r"ENC\s+[A-Za-z0-9+/=]{8,}", "ENC ***", obj)
        s = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._\-]{8,}", r"\1***", s)
        s = re.sub(r"(?i)((?:password|passwd|secret|token|psksecret|api[_-]?key)\s*[=:]\s*)\S+", r"\1***", s)
        return s
    return obj


def capability_matrix() -> list[dict]:
    rows = [{"type": t, "label": d["label"], "support": "managed", "fields": d["fields"],
             "note": "singleton: only the listed settings you declare are managed" if t in SINGLETONS else ""} for t, d in TYPES.items()]
    rows += [{"type": t, "label": t, "support": "reference only", "fields": [], "note": "read to validate references"} for t in REFERENCE_ONLY]
    rows += [{"type": t, "label": t, "support": "not supported", "fields": [], "note": n} for t, n in UNSUPPORTED.items()]
    return rows
