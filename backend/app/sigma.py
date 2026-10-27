"""Sigma rule → pipeline query (network / firewall / DNS / proxy / authentication rules).

Supports: field maps (AND), lists of maps (OR), keyword lists, modifiers contains / startswith / endswith / all /
cidr / re / gt / gte / lt / lte, wildcards * and ?, null, and conditions with and / or / not / parentheses /
"1 of x*" / "all of x*" / "them", plus the legacy aggregation "| count([field]) [by field] > N".
Anything that cannot be translated faithfully is rejected with a reason rather than silently approximated."""
from __future__ import annotations

import re

import yaml

from .alerts.rules import TACTICS

FIELD_MAP = {
    "src_ip": "src_ip", "sourceip": "src_ip", "source.ip": "src_ip", "src": "src_ip", "c-ip": "src_ip", "clientip": "src_ip",
    "dst_ip": "dst_ip", "destinationip": "dst_ip", "destination.ip": "dst_ip", "dst": "dst_ip", "dest_ip": "dst_ip",
    "src_port": "src_port", "sourceport": "src_port", "source.port": "src_port",
    "dst_port": "dst_port", "destinationport": "dst_port", "destination.port": "dst_port", "dest_port": "dst_port",
    "action": "action", "event.action": "action", "proto": "proto_name", "protocol": "proto_name", "network.transport": "proto_name",
    "destinationhostname": "hostname", "dest_domain": "hostname", "cs-host": "hostname", "url.domain": "hostname", "hostname": "hostname",
    "c-uri": "url", "url": "url", "url.original": "url", "c-uri-query": "url", "cs-method": "http_method", "http_method": "http_method",
    "queryname": "dns_qname", "query": "dns_qname", "dns.question.name": "dns_qname", "r-dns": "dns_qname", "dns_query": "dns_qname",
    "querytype": "dns_qtype", "dns.question.type": "dns_qtype", "record_type": "dns_qtype", "answer": "dns_resolved",
    "user": "user", "username": "user", "targetusername": "user", "subjectusername": "user", "user.name": "user",
    "application": "app", "app": "app", "service": "service", "category": "url_category", "threat": "threat",
    "eventid": "event_subtype", "event_id": "event_subtype", "message": "msg", "msg": "msg",
    "ipaddress": "src_ip", "workstationname": "src_name", "logontype": "logon_type",
    "sent_bytes": "sent_bytes", "rcvd_bytes": "rcvd_bytes", "bytes_out": "sent_bytes", "bytes_in": "rcvd_bytes", "duration": "duration",
}
LOGSOURCE = {"firewall": "category:traffic", "dns": "category:dns", "proxy": "category:web", "webserver": "category:web",
             "network_connection": "category:traffic"}
LEVEL = {"informational": "informational", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}
TACTIC_BY_NAME = {v.lower().replace(" ", "_").replace("-", "_"): k for k, v in TACTICS.items()}
NUMERIC = {"src_port", "dst_port", "sent_bytes", "rcvd_bytes", "duration"}


class SigmaError(ValueError):
    pass


def _q(v) -> str:
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _field(name: str) -> str:
    f = FIELD_MAP.get(name.lower())
    if not f:
        raise SigmaError(f"field '{name}' has no equivalent in FortiGate logs")
    if f == "logon_type":
        raise SigmaError("LogonType is not available in this SIEM's Windows event mapping")
    return f


def _value_expr(field: str, mods: list[str], v) -> str:
    if v is None:
        return f"isnull({field})"
    if "cidr" in mods:
        return f"cidrmatch({_q(v)}, {field})"
    if "re" in mods:
        return f"match({field}, {_q(v)})"
    for m, op in (("gt", ">"), ("gte", ">="), ("lt", "<"), ("lte", "<=")):
        if m in mods:
            return f"{field} {op} {float(v) if '.' in str(v) else int(v)}"
    if isinstance(v, bool):
        v = str(v).lower()
    if isinstance(v, (int, float)) and field in NUMERIC:
        return f"{field} = {v}"
    s = str(v)
    if "contains" in mods:
        s = f"*{s}*"
    elif "startswith" in mods:
        s = f"{s}*"
    elif "endswith" in mods:
        s = f"*{s}"
    if field in NUMERIC and s.isdigit():
        return f"{field} = {s}"
    if "*" in s or "?" in s:
        return f"lower(tostring({field})) LIKE {_q(s.replace('?', '*').lower())}"
    return f"lower(tostring({field})) = {_q(s.lower())}"


def _map(sel: dict) -> str:
    parts = []
    for key, val in sel.items():
        name, *mods = str(key).split("|")
        unsupported = set(mods) - {"contains", "startswith", "endswith", "all", "cidr", "re", "gt", "gte", "lt", "lte"}
        if unsupported:
            raise SigmaError(f"modifier(s) {sorted(unsupported)} are not supported")
        f = _field(name)
        vals = val if isinstance(val, list) else [val]
        exprs = [_value_expr(f, mods, v) for v in vals]
        joiner = " AND " if "all" in mods else " OR "
        parts.append(exprs[0] if len(exprs) == 1 else "(" + joiner.join(exprs) + ")")
    return "(" + " AND ".join(parts) + ")" if len(parts) > 1 else parts[0]


def _selection(sel) -> str:
    if isinstance(sel, dict):
        return _map(sel)
    if isinstance(sel, list):
        if all(isinstance(x, dict) for x in sel):
            exprs = [_map(x) for x in sel]
        else:  # keywords: free-text match on the raw log
            exprs = [f"contains(raw, {_q(str(x).strip('*'))})" for x in sel]
        return exprs[0] if len(exprs) == 1 else "(" + " OR ".join(exprs) + ")"
    if isinstance(sel, str):
        return f"contains(raw, {_q(sel.strip('*'))})"
    raise SigmaError("unsupported selection format")


_COND_TOK = re.compile(r"\s*(\(|\)|\band\b|\bor\b|\bnot\b|\d+ of [\w*]+|all of [\w*]+|[\w*]+)", re.I)


def _condition(cond: str, sels: dict[str, str]) -> str:
    toks = []
    pos = 0
    while pos < len(cond):
        m = _COND_TOK.match(cond, pos)
        if not m:
            if cond[pos:].strip():
                raise SigmaError(f"cannot parse condition near '{cond[pos:pos + 20]}'")
            break
        toks.append(m.group(1))
        pos = m.end()
    out = []
    for t in toks:
        low = t.lower()
        if low in ("and", "or"):
            out.append(low.upper())
        elif low == "not":
            out.append("NOT")
        elif t in ("(", ")"):
            out.append(t)
        else:
            m = re.fullmatch(r"(\d+|all) of ([\w*]+)", t, re.I)
            if m:
                pat = m.group(2)
                names = list(sels) if pat == "them" else [n for n in sels if re.fullmatch(pat.replace("*", ".*"), n)]
                if not names:
                    raise SigmaError(f"'{t}' matches no selection")
                if m.group(1).lower() == "all":
                    out.append("(" + " AND ".join(sels[n] for n in names) + ")")
                elif m.group(1) == "1":
                    out.append("(" + " OR ".join(sels[n] for n in names) + ")")
                else:
                    raise SigmaError("only '1 of' and 'all of' are supported")
            elif t in sels:
                out.append(sels[t])
            else:
                raise SigmaError(f"condition references unknown selection '{t}'")
    return " ".join(out)


def convert(text: str) -> dict:
    try:
        docs = [d for d in yaml.safe_load_all(text) if d]
    except yaml.YAMLError as e:
        raise SigmaError(f"invalid YAML: {e}") from None
    if not docs or not isinstance(docs[0], dict):
        raise SigmaError("no Sigma rule found")
    if len(docs) > 1:
        raise SigmaError("multi-document (collection / correlation) rules are not supported; import one rule at a time")
    r = docs[0]
    det = r.get("detection")
    if not isinstance(det, dict) or "condition" not in det:
        raise SigmaError("the rule has no detection.condition")
    warnings = []
    ls = r.get("logsource") or {}
    prefix = LOGSOURCE.get(str(ls.get("category", "")).lower(), "")
    if ls.get("product") == "windows":
        prefix = "type:windows"
        warnings.append("Windows rule: matches events received from Windows log sources (Log sources page).")
    elif not prefix:
        warnings.append(f"logsource {ls} has no direct equivalent; the query runs over all categories.")
    sels = {k: _selection(v) for k, v in det.items() if k not in ("condition", "timeframe")}
    cond = det["condition"]
    if isinstance(cond, list):
        if len(cond) != 1:
            raise SigmaError("multiple conditions are not supported")
        cond = cond[0]
    agg = ""
    if "|" in cond:
        cond, aggpart = cond.split("|", 1)
        m = re.fullmatch(r"\s*count\(\s*(\w*)\s*\)\s*(?:by\s+(\w+))?\s*(>=|>|<=|<|==|=)\s*(\d+)\s*", aggpart)
        if not m:
            raise SigmaError(f"unsupported aggregation '{aggpart.strip()}'")
        fld, by, op, n = m.groups()
        cnt = f"dc({_field(fld)}) as count" if fld else "count"
        agg = f" | stats {cnt} by {_field(by)}" if by else f" | stats {cnt}"
        agg += f" | where count {'=' if op == '==' else op} {n}"
        if det.get("timeframe"):
            warnings.append(f"timeframe {det['timeframe']}: set the detection look-back to match.")
    where = _condition(cond.strip(), sels)
    query = f"{prefix} | where {where}{agg}".strip()
    tags = [str(t).lower() for t in r.get("tags") or []]
    techniques = sorted({t.split(".", 1)[1].upper() for t in tags if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)})
    tactic = next((TACTIC_BY_NAME[t.split(".", 1)[1]] for t in tags if t.startswith("attack.") and t.split(".", 1)[1] in TACTIC_BY_NAME), "")
    return {"name": str(r.get("title") or "Sigma rule")[:128], "description": str(r.get("description") or "")[:2000],
            "severity": LEVEL.get(str(r.get("level", "medium")).lower(), "medium"), "query": query, "tactic": tactic,
            "techniques": techniques[:10], "grouping": "per_row" if agg else "single", "warnings": warnings,
            "sigma_id": r.get("id"), "references": r.get("references") or []}
