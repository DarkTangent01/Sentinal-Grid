"""Normalize FortiGate firewall policy objects (/api/v2/cmdb/firewall/policy) into a stable dict."""
import hashlib
import json

from .objects import _names

# policy attributes that restrict matching in ways the static analyzer cannot model
IDENTITY_FIELDS = ("users", "groups", "fsso-groups", "ztna-ems-tag", "ztna-geo-tag", "src-vendor-mac")
ISDB_FIELDS = ("internet-service", "internet-service-src", "internet-service6", "internet-service6-src")
PROFILE_FIELDS = ("webfilter-profile", "application-list", "ips-sensor", "av-profile", "dnsfilter-profile",
                  "ssl-ssh-profile", "file-filter-profile", "dlp-profile", "emailfilter-profile")


def normalize_policy(raw: dict, seq: int) -> dict:
    g = raw.get
    identity = [f for f in IDENTITY_FIELDS if _names(g(f))]
    isdb = [f for f in ISDB_FIELDS if g(f) == "enable"]
    return {
        "policyid": int(g("policyid")),
        "uuid": g("uuid") or "",
        "seq": seq,
        "name": g("name") or "",
        "type": "firewall",
        "status": g("status") or "enable",
        "action": g("action") or "deny",
        "srcintf": _names(g("srcintf")),
        "dstintf": _names(g("dstintf")),
        "srcaddr": _names(g("srcaddr")) + _names(g("srcaddr6")),
        "dstaddr": _names(g("dstaddr")) + _names(g("dstaddr6")),
        "service": _names(g("service")),
        "schedule": g("schedule") or "always",
        "nat": g("nat") or "disable",
        "logtraffic": g("logtraffic") or "utm",
        "utm_status": g("utm-status") or "disable",
        "inspection_mode": g("inspection-mode") or "",
        "profiles": {f: g(f) for f in PROFILE_FIELDS if g(f)},
        "negate": {k: g(f) == "enable" for k, f in (("src", "srcaddr-negate"), ("dst", "dstaddr-negate"), ("service", "service-negate"))},
        "identity": identity,
        "isdb": isdb,
        "comments": g("comments") or "",
    }


def config_hash(p: dict) -> str:
    keep = {k: v for k, v in p.items() if k not in ("seq",)}
    return hashlib.sha256(json.dumps(keep, sort_keys=True).encode()).hexdigest()[:24]
