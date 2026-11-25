"""Threat-intelligence connectors: STIX 2.1 bundles, TAXII 2.1 collections, MISP and AlienVault OTX.

Each connector turns a source's answer into indicator rows:
    {"indicator", "type", "confidence", "threat", "first_seen", "last_seen", "expires_at"}
type: ip | cidr | domain | url | sha256 | sha1 | md5 | email | asn. Content is parsed as data, never executed.
Only what the source says is stored: a missing confidence stays empty (the feed's default applies when matching).

Requests go through the same guard as every outbound call (https only, no private destinations unless the host is in
OUTBOUND_ALLOWED_HOSTS, which is how an internal MISP / OpenCTI server is reached). The API key is sent in the feed's
auth header and never logged. Sources that sell lookups rather than feeds (VirusTotal) are not connectors: nothing
here sends your indicators or events to a third party.
"""
from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone

import httpx

TYPES = ("ip", "cidr", "domain", "url", "sha256", "sha1", "md5", "email", "asn")
CONNECTOR_KINDS = ("stix", "taxii", "misp", "otx")
DEFAULT_HEADER = {"misp": "Authorization", "otx": "X-OTX-API-KEY", "taxii": "Authorization", "stix": "Authorization"}
_HASH_LEN = {64: "sha256", 40: "sha1", 32: "md5"}
_DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9_-]{1,63}\.)+[a-z]{2,63}$")
_EMAIL = re.compile(r"^[^@\s]{1,64}@([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")
_STIX_CMP = re.compile(r"([a-z0-9-]+):([A-Za-z0-9_.'\-]+)\s*=\s*'((?:[^'\\]|\\.)*)'")


def _dt(v) -> datetime | None:
    if v in (None, "", 0, "0"):
        return None
    try:
        if isinstance(v, (int, float)) or str(v).isdigit():
            return datetime.fromtimestamp(float(v), timezone.utc)
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


def normalize(value: str, hint: str = "") -> tuple[str, str] | None:
    """(indicator, type) in canonical form, or None when the value is not a usable indicator.
    Private, loopback and reserved addresses are refused: listing them would flag internal traffic."""
    v = str(value or "").strip()
    if not v:
        return None
    h = hint.lower()
    if h in ("url", "uri") or v.lower().startswith(("http://", "https://")):
        v = re.sub(r"^[a-z]+://", "", v, flags=re.I).rstrip("/")
        return (v[:255], "url") if "." in v.split("/")[0] else None
    if h in ("asn", "as", "autonomous-system") or re.fullmatch(r"(?i)as\d{1,10}", v):
        n = re.sub(r"(?i)^as", "", v)
        return (n, "asn") if n.isdigit() and 0 < int(n) < 2**32 else None
    if h in ("email", "email-src", "email-dst", "email-addr") or ("@" in v and "/" not in v):
        v = v.lower()
        return (v, "email") if _EMAIL.match(v) else None
    if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", v):
        return v.lower(), _HASH_LEN[len(v)]
    try:
        if "/" in v:
            net = ipaddress.ip_network(v, strict=False)
            if not net.is_global or net.prefixlen < 8:
                return None
            return (str(net.network_address), "ip") if net.prefixlen == net.max_prefixlen else (str(net), "cidr")
        ip = ipaddress.ip_address(v.split("|")[0])
        return (str(ip), "ip") if ip.is_global else None
    except ValueError:
        pass
    d = v.lower().rstrip(".")
    return (d, "domain") if _DOMAIN.match(d) else None


def _row(value, hint="", confidence=None, threat="", first=None, last=None, expires=None) -> dict | None:
    n = normalize(value, hint)
    if not n:
        return None
    try:
        conf = None if confidence in (None, "") else max(0, min(100, int(float(confidence))))
    except (TypeError, ValueError):
        conf = None
    return {"indicator": n[0], "type": n[1], "confidence": conf, "threat": str(threat or "")[:96], "first_seen": _dt(first), "last_seen": _dt(last),
            "expires_at": _dt(expires)}


def dedupe(rows: list[dict | None]) -> list[dict]:
    """One row per indicator: highest confidence, widest first / last seen, latest expiry."""
    out: dict[str, dict] = {}
    for r in rows:
        if not r:
            continue
        cur = out.get(r["indicator"])
        if cur is None:
            out[r["indicator"]] = r
            continue
        if r["confidence"] is not None and (cur["confidence"] is None or r["confidence"] > cur["confidence"]):
            cur["confidence"] = r["confidence"]
        cur["threat"] = cur["threat"] or r["threat"]
        for k, pick in (("first_seen", min), ("last_seen", max), ("expires_at", max)):
            vals = [x for x in (cur[k], r[k]) if x]
            cur[k] = pick(vals) if vals else None
    return list(out.values())


# ------------------------------------------------------------------ STIX 2.1
def parse_stix(bundle: dict | list) -> list[dict]:
    objs = bundle if isinstance(bundle, list) else bundle.get("objects", [])
    rows = []
    for o in objs:
        if not isinstance(o, dict) or o.get("type") != "indicator" or o.get("revoked") or o.get("pattern_type", "stix") != "stix":
            continue
        threat = ", ".join((o.get("indicator_types") or o.get("labels") or [])[:3]) or str(o.get("name", ""))[:96]
        for obj, prop, val in _STIX_CMP.findall(o.get("pattern", "")):
            val = val.replace("\\'", "'").replace("\\\\", "\\")
            hint = {"url": "url", "email-addr": "email", "autonomous-system": "asn"}.get(obj, "")
            if obj == "file" and "hashes" not in prop:
                continue
            if obj not in ("ipv4-addr", "ipv6-addr", "domain-name", "url", "file", "email-addr", "autonomous-system"):
                continue
            rows.append(_row(val, hint, o.get("confidence"), threat, o.get("valid_from") or o.get("created"), o.get("modified"), o.get("valid_until")))
    return dedupe(rows)


# ------------------------------------------------------------------ MISP
_MISP_HINT = {"url": "url", "uri": "url", "email-src": "email", "email-dst": "email", "email": "email", "AS": "asn"}
_MISP_TYPES = ["ip-src", "ip-dst", "domain", "hostname", "url", "sha256", "sha1", "md5", "email-src", "email-dst", "AS", "ip-dst|port", "ip-src|port"]
_MISP_LEVEL = {"1": 90, "2": 70, "3": 50}       # event threat level: high / medium / low (4 = undefined → no confidence)


def parse_misp(data: dict) -> list[dict]:
    attrs = (data.get("response") or {}).get("Attribute") or data.get("Attribute") or []
    rows = []
    for a in attrs:
        if not isinstance(a, dict) or a.get("to_ids") in (False, "0", 0):
            continue
        ev = a.get("Event") or {}
        rows.append(_row(str(a.get("value", "")).split("|")[0], _MISP_HINT.get(a.get("type", ""), ""), _MISP_LEVEL.get(str(ev.get("threat_level_id", ""))),
                         a.get("category") or ev.get("info", ""), a.get("first_seen") or a.get("timestamp"), a.get("last_seen") or a.get("timestamp")))
    return dedupe(rows)


# ------------------------------------------------------------------ AlienVault OTX
_OTX_HINT = {"URL": "url", "URI": "url", "email": "email"}


def parse_otx(data: dict) -> list[dict]:
    rows = []
    for pulse in data.get("results") or []:
        threat = ", ".join((pulse.get("tags") or [])[:3]) or str(pulse.get("name", ""))[:96]
        for i in pulse.get("indicators") or []:
            if i.get("is_active") in (0, False):
                continue
            rows.append(_row(i.get("indicator"), _OTX_HINT.get(i.get("type", ""), ""), None, i.get("role") or threat, i.get("created") or pulse.get("created"),
                             pulse.get("modified"), i.get("expiration")))
    return dedupe(rows)


# ------------------------------------------------------------------ fetching
async def _read(r: httpx.Response, budget: list[int]) -> bytes:
    chunks = []
    async for ch in r.aiter_bytes():
        budget[0] -= len(ch)
        if budget[0] < 0:
            raise ValueError("response larger than the feed size limit")
        chunks.append(ch)
    return b"".join(chunks)


async def fetch(kind: str, url: str, client: httpx.AsyncClient, max_bytes: int, max_pages: int = 20) -> list[dict]:
    """Query one source and return its indicator rows. `client` already carries the auth header and the guard."""
    budget = [max_bytes]
    if kind == "stix":
        async with client.stream("GET", url) as r:
            r.raise_for_status()
            return parse_stix(json.loads(await _read(r, budget)))
    if kind == "misp":
        body = {"returnFormat": "json", "to_ids": True, "type": _MISP_TYPES, "last": "90d", "limit": 100000, "includeEventTags": False}
        async with client.stream("POST", url.rstrip("/") + "/attributes/restSearch", json=body, headers={"Accept": "application/json"}) as r:
            r.raise_for_status()
            return parse_misp(json.loads(await _read(r, budget)))
    rows: list[dict] = []
    if kind == "otx":
        nxt = url.rstrip("/") + "/api/v1/pulses/subscribed?limit=50"
        for _ in range(max_pages):
            async with client.stream("GET", nxt) as r:
                r.raise_for_status()
                data = json.loads(await _read(r, budget))
            rows += parse_otx(data)
            nxt = data.get("next")
            if not nxt or not str(nxt).startswith(url.rstrip("/")):   # never follow a "next" link to another host
                break
        return dedupe(rows)
    if kind == "taxii":   # url = the collection: https://server/api/collections/<id>
        base, params = url.rstrip("/") + "/objects/", {"match[type]": "indicator", "limit": "2000"}
        for _ in range(max_pages):
            async with client.stream("GET", base, params=params, headers={"Accept": "application/taxii+json;version=2.1"}) as r:
                r.raise_for_status()
                data = json.loads(await _read(r, budget))
            rows += parse_stix(data)
            if not data.get("more") or not data.get("next"):
                break
            params = {**params, "next": str(data["next"])}
        return dedupe(rows)
    raise ValueError(f"unknown connector {kind!r}")
