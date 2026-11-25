"""Common schema view of a stored event.

Storage keeps the platform's own columns (every query, rollup and detection is written against them). This module is
the mapping layer on top: each column's Elastic Common Schema (ECS) field name, the OCSF class an event belongs to,
`to_ecs()` for the normalized view in the event explorer / exports, and ECS names as search aliases
(`source.ip:10.0.0.5` works like `src_ip:10.0.0.5`). ECS 8.x field names; OCSF 1.x class ids.
"""
from __future__ import annotations

from datetime import datetime

# column → ECS field
ECS: dict[str, str] = {
    "event_id": "event.id", "event_time": "@timestamp", "ingest_time": "event.ingested", "category": "event.dataset", "event_type": "event.module",
    "event_subtype": "event.type_detail", "log_id": "event.code", "firewall_name": "observer.name", "site": "observer.geo.name", "devid": "observer.serial_number",
    "vdom": "observer.zone", "source": "event.provider", "parser_version": "labels.parser_version", "severity": "log.level", "orig_severity": "event.severity_label",
    "src_ip": "source.ip", "src_port": "source.port", "dst_ip": "destination.ip", "dst_port": "destination.port", "proto_name": "network.transport",
    "proto": "network.iana_number", "src_intf": "observer.ingress.interface.name", "dst_intf": "observer.egress.interface.name", "policy_id": "rule.id",
    "policy_name": "rule.name", "policy_uuid": "rule.uuid", "action": "event.action", "orig_action": "event.action_original", "session_id": "network.session_id",
    "app": "network.application", "app_cat": "network.application_category", "service": "network.protocol", "hostname": "destination.domain", "url": "url.original",
    "http_method": "http.request.method", "url_category": "url.category", "sent_bytes": "source.bytes", "rcvd_bytes": "destination.bytes",
    "sent_pkts": "source.packets", "rcvd_pkts": "destination.packets", "duration": "event.duration_seconds", "nat_src_ip": "source.nat.ip",
    "nat_src_port": "source.nat.port", "nat_dst_ip": "destination.nat.ip", "nat_dst_port": "destination.nat.port", "dns_qname": "dns.question.name",
    "dns_qtype": "dns.question.type", "dns_rcode": "dns.response_code", "dns_resolved": "dns.resolved_ip", "threat": "threat.indicator.description",
    "user": "user.name", "msg": "message", "raw": "event.original", "src_country": "source.geo.country_iso_code", "dst_country": "destination.geo.country_iso_code",
    "dst_asn": "destination.as.number", "dst_as_org": "destination.as.organization.name", "src_mac": "source.mac", "src_name": "source.domain",
    "src_os": "host.os.name", "ti_match": "threat.indicator.name", "ti_source": "threat.indicator.provider", "ti_category": "threat.indicator.type",
    "vpn_tunnel": "network.tunnel.type",
}
# OCSF class per category (class_uid, class name, category name)
OCSF_CLASS: dict[str, tuple[int, str, str]] = {
    "traffic": (4001, "Network Activity", "Network Activity"), "dns": (4003, "DNS Activity", "Network Activity"),
    "web": (4002, "HTTP Activity", "Network Activity"), "security": (2004, "Detection Finding", "Findings"),
    "zeek": (4001, "Network Activity", "Network Activity"), "system": (1008, "Event Log Activity", "System Activity"),
}
_AUTH_ACTIONS = {"logon", "logon-fail", "logoff", "logon-explicit", "privileged-logon", "lockout", "kerberos-tgt", "kerberos-preauth-fail", "ntlm-validate"}
_OUTCOME_FAIL = {"deny", "block", "logon-fail", "sudo-fail", "lockout", "kerberos-preauth-fail", "failed", "timeout", "reset"}
_OUTCOME_OK = {"accept", "allow", "close", "logon", "sudo", "established", "monitor"}
_ZEEK_CLASS = {"dns": (4003, "DNS Activity"), "http": (4002, "HTTP Activity"), "ssh": (4007, "SSH Activity"), "dhcp": (4004, "DHCP Activity"),
               "files": (1001, "File System Activity"), "notice": (2004, "Detection Finding"), "weird": (2004, "Detection Finding")}


def ocsf_class(ev: dict) -> dict:
    cat, action = ev.get("category", ""), ev.get("action", "")
    uid, name, group = OCSF_CLASS.get(cat, (0, "Base Event", "Uncategorized"))
    if cat == "zeek" and ev.get("event_subtype") in _ZEEK_CLASS:
        uid, name = _ZEEK_CLASS[ev["event_subtype"]]
    elif action in _AUTH_ACTIONS:
        uid, name, group = 3002, "Authentication", "Identity & Access Management"
    elif action in ("user-created", "user-deleted", "user-enabled", "user-disabled", "password-change", "password-reset", "group-add"):
        uid, name, group = 3001, "Account Change", "Identity & Access Management"
    return {"class_uid": uid, "class_name": name, "category_name": group}


def outcome(ev: dict) -> str:
    a = ev.get("action", "")
    return "failure" if a in _OUTCOME_FAIL else "success" if a in _OUTCOME_OK else "unknown"


def _put(doc: dict, path: str, value) -> None:
    parts = path.split(".")
    for p in parts[:-1]:
        doc = doc.setdefault(p, {})
    doc[parts[-1]] = value


def to_ecs(ev: dict, include_raw: bool = False) -> dict:
    """Nested ECS-style document of one event; empty values are left out. `event.original` only with include_raw."""
    doc: dict = {}
    for col, path in ECS.items():
        v = ev.get(col)
        if v in (None, "", 0, []) or (col == "raw" and not include_raw):
            continue
        _put(doc, path, v.isoformat() if isinstance(v, datetime) else v)
    _put(doc, "event.outcome", outcome(ev))
    _put(doc, "event.kind", "alert" if ev.get("category") == "security" or ev.get("ti_match") else "event")
    _put(doc, "ocsf", ocsf_class(ev))
    return doc


# search aliases: ECS field → the query-language field it is the same as (analytics/ql.py FIELDS)
QL_ALIASES: dict[str, str] = {
    "source.ip": "src_ip", "destination.ip": "dst_ip", "source.port": "src_port", "destination.port": "dst_port", "network.transport": "proto",
    "user.name": "user", "event.action": "action", "event.dataset": "category", "event.module": "type", "log.level": "severity",
    "observer.name": "firewall", "url.original": "url", "dns.question.name": "qname", "dns.question.type": "qtype", "dns.response_code": "rcode",
    "destination.domain": "hostname", "network.application": "app", "network.protocol": "service", "source.mac": "mac", "source.domain": "name",
    "rule.id": "policy", "message": "msg", "event.original": "raw", "source.geo.country_iso_code": "src_country",
    "destination.geo.country_iso_code": "dst_country", "destination.as.number": "asn", "destination.as.organization.name": "as_org",
    "threat.indicator.name": "ti", "threat.indicator.type": "ti_category", "source.bytes": "sent", "destination.bytes": "rcvd",
    "observer.geo.name": "site", "host.os.name": "os",
}


def catalogue() -> list[dict]:
    """Field dictionary for the UI / API docs: column, ECS name, search alias."""
    rev = {v: k for k, v in QL_ALIASES.items()}
    return [{"column": col, "ecs": path, "search_alias": path if path in QL_ALIASES else None} for col, path in ECS.items()] + \
        [{"column": None, "ecs": e, "search_alias": e} for e in QL_ALIASES if e not in ECS.values() and e not in rev]
