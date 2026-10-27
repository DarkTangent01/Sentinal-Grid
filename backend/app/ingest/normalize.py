"""Normalize FortiGate logs (from syslog or the REST log API) into the common event schema.

Rules:
* Never invent values. Missing fields stay empty/NULL.
* `url` is stored exactly as logged; url_is_full=1 only when the logged value includes a scheme.
* Timestamps are converted to UTC.
"""
import hashlib
import ipaddress
import json
from json.encoder import encode_basestring_ascii as _js
import math
from collections import Counter
from datetime import datetime, timedelta, timezone

PARSER_VERSION = "fgt-kv-1.0"

PROTO_NAMES = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE", 50: "ESP", 51: "AH",
               58: "ICMPv6", 89: "OSPF", 103: "PIM", 112: "VRRP", 132: "SCTP"}

LEVEL_SEVERITY = {
    "emergency": "critical", "alert": "critical", "critical": "critical",
    "error": "high", "warning": "medium", "notice": "low",
    "information": "informational", "informational": "informational", "debug": "informational",
}
DIRECT_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low",
                   "info": "informational", "information": "informational", "informational": "informational"}

ACTION_MAP = {
    "accept": "accept", "start": "accept", "close": "close", "timeout": "timeout",
    "client-rst": "reset", "server-rst": "reset", "deny": "deny", "ip-conn": "deny",
    "blocked": "block", "block": "block", "dropped": "block", "drop": "block", "reset": "block",
    "passthrough": "allow", "pass": "allow", "allow": "allow", "permit": "allow",
    "monitored": "monitor", "monitor": "monitor", "redirect": "block", "exempt": "allow",
}
ALLOWED_ACTIONS = ("accept", "close", "timeout", "reset", "allow", "monitor")
DENIED_ACTIONS = ("deny", "block")

SECURITY_SUBTYPES = {"ips", "virus", "app-ctrl", "anomaly", "dlp", "waf", "emailfilter", "ssl", "file-filter",
                     "voip", "icap", "cifs", "ssh", "casb", "virtual-patch"}

FINGERPRINT_FIELDS = ("devid", "devname", "vd", "eventtime", "date", "time", "logid", "sessionid", "srcip", "srcport",
                      "dstip", "dstport", "proto", "action", "sentbyte", "rcvdbyte", "duration", "qname", "qtype",
                      "hostname", "url", "attack", "virus", "msg", "user", "ui", "cfgpath", "cfgattr")


def _int(v, maxv: int | None = None):
    if v is None or v == "":
        return None
    try:
        n = int(str(v).strip())
    except ValueError:
        try:
            n = int(float(str(v)))
        except ValueError:
            return None
    if n < 0 or (maxv is not None and n > maxv):
        return None
    return n


def parse_event_time(f: dict) -> tuple[datetime, bool]:
    """Returns (utc_time, trusted). trusted=False when we had to fall back to ingest time."""
    et = str(f.get("eventtime", "")).strip()
    if et.isdigit():
        n = int(et)
        if n > 10**17:
            sec = n / 1e9
        elif n > 10**14:
            sec = n / 1e6
        elif n > 10**11:
            sec = n / 1e3
        else:
            sec = float(n)
        try:
            return datetime.fromtimestamp(sec, tz=timezone.utc), True
        except (OverflowError, OSError, ValueError):
            pass
    date, tm = f.get("date"), f.get("time")
    if date and tm:
        try:
            dt = datetime.strptime(f"{date} {tm}", "%Y-%m-%d %H:%M:%S")
            tz = str(f.get("tz", "")).strip()
            offset = timedelta(0)
            if len(tz) == 5 and tz[0] in "+-" and tz[1:].isdigit():
                offset = timedelta(hours=int(tz[1:3]), minutes=int(tz[3:5])) * (1 if tz[0] == "+" else -1)
            return (dt - offset).replace(tzinfo=timezone.utc), True
        except ValueError:
            pass
    return datetime.now(timezone.utc), False


def _country(v) -> str:
    v = (v or "").strip()
    return "" if v in ("", "Reserved", "N/A", "Unknown", "-") else v


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def subdomain_part(qname: str) -> str:
    labels = qname.rstrip(".").split(".")
    return ".".join(labels[:-2]) if len(labels) > 2 else ""


def _user(f: dict, sub: str) -> str:
    """The person behind the event. FortiOS IPsec logs put the peer id (usually an IP) in `user` and the authenticated
    FortiClient user in `xauthuser`; an IP or N/A there is not a user name."""
    if sub == "vpn":
        xu = f.get("xauthuser") or ""
        if xu and xu != "N/A":
            return xu
        u = f.get("user") or ""
        if u == "N/A" or _looks_ip(u):
            return ""
        return u
    return f.get("user") or f.get("srcuser") or ""


def _looks_ip(v: str) -> bool:
    if not v or not (v[0].isdigit() or ":" in v):
        return False
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def categorize(f: dict) -> str:
    typ = (f.get("type") or "").lower()
    sub = (f.get("subtype") or "").lower()
    if typ == "traffic":
        return "traffic"
    if sub == "dns" or typ == "dns":
        return "dns"
    if sub == "webfilter" or typ == "webfilter":
        return "web"
    if typ == "event":
        return "system"
    if typ in ("utm", "attack") or sub in SECURITY_SUBTYPES or typ in SECURITY_SUBTYPES:
        return "security"
    return "system"


_FP_SORTED = tuple(sorted(FINGERPRINT_FIELDS))


def fingerprint(f: dict) -> str:
    # byte-identical to json.dumps({k: str(v) ...}, sort_keys=True) so event ids stay stable across versions
    parts = [f"{_js(k)}: {_js(str(f[k]))}" for k in _FP_SORTED if k in f]
    if len(parts) < 3:  # too little identity: hash the whole record
        parts = [f"{_js(k)}: {_js(str(f[k]))}" for k in sorted(f)]
    return hashlib.sha256(("{" + ", ".join(parts) + "}").encode()).hexdigest()[:32]


def normalize(f: dict, *, source: str, raw: str | None = None, firewall: dict | None = None, all_str: bool = False) -> dict:
    fw = firewall or {}
    if not all_str:
        f = {k: v if isinstance(v, str) else ("" if v is None else str(v)) for k, v in f.items()}
    event_time, trusted = parse_event_time(f)
    category = categorize(f)
    typ = f.get("type", "")
    sub = f.get("subtype", "")

    level = (f.get("level") or "").lower()
    sev_field = (f.get("severity") or f.get("crlevel") or "").lower()
    severity = DIRECT_SEVERITY.get(sev_field) or LEVEL_SEVERITY.get(level) or "informational"
    orig_sev = f.get("severity") or f.get("level") or ""

    orig_action = f.get("action") or f.get("utmaction") or ""
    action = ACTION_MAP.get(orig_action.lower(), "other" if orig_action else "")
    if category == "web" and not action:
        et = (f.get("eventtype") or "").lower()
        action = "block" if "blk" in et or "block" in et else ""

    proto = _int(f.get("proto"), 255)
    url = f.get("url", "")
    hostname = f.get("hostname", "")
    qname = (f.get("qname") or "").rstrip(".").lower()
    sub_part = subdomain_part(qname) if qname else ""
    resolved = [ip.strip() for ip in (f.get("ipaddr") or "").split(",") if ip.strip()] if category == "dns" else []
    latency = f.get("latency") or f.get("dnslatency")
    try:
        latency_ms = float(latency) if latency not in (None, "") else None
    except ValueError:
        latency_ms = None

    rcode = f.get("rcode") or ""
    if not rcode and category == "dns":
        msg_l = (f.get("msg") or "").lower()
        if "nxdomain" in msg_l or "non-existent" in msg_l:
            rcode = "NXDOMAIN"

    threat = f.get("attack") or f.get("virus") or (f.get("app") if sub == "app-ctrl" else "") or ""
    if category == "web":
        threat = threat or f.get("catdesc", "")

    return {
        "event_id": fingerprint(f),
        "event_time": event_time,
        "ingest_time": datetime.now(timezone.utc),
        "category": category,
        "event_type": typ,
        "event_subtype": sub,
        "log_id": f.get("logid", ""),
        "firewall_id": int(fw.get("id") or 0),
        "firewall_name": fw.get("name") or f.get("devname", ""),
        "site": fw.get("site", ""),
        "devid": f.get("devid", ""),
        "vdom": f.get("vd", ""),
        "source": source,
        "parser_version": PARSER_VERSION + ("" if trusted else "+ingest-ts"),
        "severity": severity,
        "orig_severity": orig_sev,
        # VPN event logs carry the remote peer in remip rather than srcip
        "src_ip": f.get("srcip") or (f.get("remip", "") if sub == "vpn" else ""),
        "src_port": _int(f.get("srcport"), 65535),
        "dst_ip": f.get("dstip", ""),
        "dst_port": _int(f.get("dstport"), 65535),
        "proto": proto,
        "proto_name": PROTO_NAMES.get(proto, str(proto) if proto is not None else ""),
        "src_intf": f.get("srcintf", ""),
        "dst_intf": f.get("dstintf", ""),
        "policy_id": _int(f.get("policyid"), 2**32 - 1),
        "policy_name": f.get("policyname", ""),
        "action": action,
        "orig_action": orig_action,
        "session_id": _int(f.get("sessionid"), 2**64 - 1),
        "app": f.get("app", ""),
        "app_id": _int(f.get("appid"), 2**32 - 1),
        "app_cat": f.get("appcat", ""),
        "service": f.get("service", ""),
        "hostname": hostname,
        "url": url,
        "url_is_full": 1 if url.lower().startswith(("http://", "https://")) else 0,
        "http_method": f.get("httpmethod") or f.get("method") or "",
        "url_category": f.get("catdesc", "") if category in ("web", "dns") else "",
        # Interim traffic logs carry cumulative sentbyte plus sentdelta; use the delta when present so that
        # summing records never double-counts a long-lived session. Cumulative values remain in `raw`.
        "sent_bytes": (_int(f.get("sentdelta")) if f.get("sentdelta") not in (None, "") else _int(f.get("sentbyte"))) or 0,
        "rcvd_bytes": (_int(f.get("rcvddelta")) if f.get("rcvddelta") not in (None, "") else _int(f.get("rcvdbyte"))) or 0,
        "sent_pkts": _int(f.get("sentpkt")) or 0,
        "rcvd_pkts": _int(f.get("rcvdpkt")) or 0,
        "duration": _int(f.get("duration"), 2**32 - 1) or 0,
        "nat_src_ip": f.get("transip", ""),
        "nat_src_port": _int(f.get("transport"), 65535),
        "nat_dst_ip": f.get("tranip", ""),
        "nat_dst_port": _int(f.get("tranport"), 65535),
        "dns_qname": qname,
        "dns_qtype": f.get("qtype", ""),
        "dns_rcode": rcode.upper(),
        "dns_resolved": resolved,
        "dns_latency_ms": latency_ms,
        "dns_qname_len": min(len(qname), 65535),
        "dns_entropy": round(shannon_entropy(sub_part.replace(".", "")), 3),
        "threat": threat,
        "user": _user(f, sub),
        "msg": f.get("msg") or f.get("logdesc") or "",
        "raw": raw if raw is not None else json.dumps(f, sort_keys=True),
        "policy_uuid": f.get("poluuid", ""),
        # context logged by FortiGate itself (device identification, country DB); GeoIP/TI enrichment may add more
        "src_country": _country(f.get("srccountry")),
        "dst_country": _country(f.get("dstcountry")),
        "dst_asn": 0, "dst_as_org": "", "src_lat": None, "src_lon": None,
        "src_mac": (f.get("srcmac") or f.get("mastersrcmac") or "").lower(),
        "src_name": f.get("srcname") or f.get("srchostname") or "",
        "src_os": f.get("osname", ""),
        "ti_match": "", "ti_source": "", "ti_category": "",
        "vpn_tunnel": f.get("tunneltype", "") if sub == "vpn" else "",
    }
