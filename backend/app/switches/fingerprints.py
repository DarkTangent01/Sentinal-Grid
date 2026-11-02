"""Device fingerprint registry: sysObjectID / sysDescr → vendor, product family, device type, OS, version, model.

Identification order (most reliable first):
  1. sysObjectID subtree rules (an exact product subtree, e.g. FortiGate products under FORTINET-FORTIGATE-MIB fgModel).
  2. Enterprise number in sysObjectID (1.3.6.1.4.1.<n>.…) → vendor. Reliable for the vendor, not for the family.
  3. sysDescr patterns, only to refine the family / OS / version within the vendor already known, or — with low confidence —
     when sysObjectID is missing or belongs to a generic agent (net-snmp).
  4. Unknown → vendor "generic": baseline standard-MIB monitoring still applies.

Confidence: "exact" (sysObjectID product subtree), "family" (vendor from sysObjectID + family from sysDescr / model),
"vendor" (vendor only), "descr" (sysDescr only, no sysObjectID evidence), "unknown".
Administrators can override vendor and family per device (Switch.vendor_override / family_override); the poller then
reports when the device's own answers contradict the override (profile compatibility).

New vendors register an EnterpriseRule / OidRule / DescrRule here and an adapter in collect.ADAPTERS; the engine
does not change.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

DEVICE_TYPES = ("switch", "router", "firewall", "wlc", "ap", "server", "other")
VENDORS = ("cisco", "fortinet", "juniper", "ruckus", "generic")


@dataclass(frozen=True)
class EnterpriseRule:
    enterprise: int
    vendor: str
    note: str = ""


@dataclass(frozen=True)
class OidRule:
    prefix: str             # sysObjectID subtree
    vendor: str
    family: str
    device_type: str
    source: str             # MIB that defines the subtree


@dataclass(frozen=True)
class DescrRule:
    vendor: str
    pattern: str            # regex on sysDescr
    family: str
    device_type: str
    os: str = ""


ENTERPRISES = [
    EnterpriseRule(9, "cisco", "ciscoProducts (CISCO-SMI)"),
    EnterpriseRule(12356, "fortinet", "fortinet (FORTINET-CORE-MIB)"),
    EnterpriseRule(2636, "juniper", "juniperMIB (JUNIPER-SMI)"),
    EnterpriseRule(1991, "ruckus", "foundry (FOUNDRY-SN-ROOT-MIB): Ruckus ICX / FastIron"),
    EnterpriseRule(25053, "ruckus", "ruckusRootMIB (RUCKUS-ROOT-MIB): Ruckus wireless (SmartZone / standalone AP)"),
]
ENTERPRISE = {e.enterprise: e for e in ENTERPRISES}

OID_RULES = [
    OidRule("1.3.6.1.4.1.12356.101.1", "fortinet", "FortiGate", "firewall", "FORTINET-FORTIGATE-MIB fgModel"),
    OidRule("1.3.6.1.4.1.12356.106.1", "fortinet", "FortiSwitch", "switch", "FORTINET-FORTISWITCH-MIB fsModel"),
    OidRule("1.3.6.1.4.1.2636.1.1.1", "juniper", "", "", "JUNIPER-CHASSIS-DEFINES-MIB jnxProductName (family from sysDescr)"),
]

DESCR_RULES = [
    # Cisco
    DescrRule("cisco", r"C9800|Catalyst\s+9800|C9800-CL", "Catalyst 9800 WLC", "wlc", "IOS-XE"),
    DescrRule("cisco", r"NX-OS|Nexus", "Nexus", "switch", "NX-OS"),
    DescrRule("cisco", r"Adaptive Security Appliance|Firepower", "ASA / Firepower", "firewall", "ASA"),
    DescrRule("cisco", r"\b(ISR|ASR|C8[0-9]{3})\b|Cisco IOS Software.*(ISR|ASR)", "ISR / ASR router", "router", "IOS-XE"),
    DescrRule("cisco", r"Catalyst|C9[0-9]{3}|C[23][0-9]{3}|IE-[0-9]{4}|Cisco IOS", "Catalyst", "switch", "IOS"),
    # Fortinet (when sysObjectID is not a product subtree)
    DescrRule("fortinet", r"FortiSwitch|FS-?[0-9]{3}", "FortiSwitch", "switch", "FortiSwitchOS"),
    DescrRule("fortinet", r"FortiGate|FGT|FortiOS", "FortiGate", "firewall", "FortiOS"),
    # Juniper: "Juniper Networks, Inc. ex4300-48p Ethernet Switch, kernel JUNOS 21.4R3-S4 ..."
    DescrRule("juniper", r"\bex[0-9]{4}", "EX", "switch", "Junos"),
    DescrRule("juniper", r"\bqfx[0-9]{4,5}", "QFX", "switch", "Junos"),
    DescrRule("juniper", r"\bsrx[0-9]{3,4}", "SRX", "firewall", "Junos"),
    DescrRule("juniper", r"\bmx[0-9]{2,4}", "MX", "router", "Junos"),
    # Ruckus
    DescrRule("ruckus", r"\bICX\s?[0-9]{4}", "ICX", "switch", "FastIron"),
    DescrRule("ruckus", r"SmartZone|vSZ|SZ-?[0-9]{3}", "SmartZone", "wlc", "SmartZone"),
    DescrRule("ruckus", r"Ruckus.*(R[0-9]{3}|T[0-9]{3}|ZoneFlex|Unleashed)", "Ruckus AP", "ap", "Ruckus AP"),
]

VERSION_PATTERNS = {
    "cisco": r"Version\s+([0-9][0-9A-Za-z.()]*)",
    "fortinet": r"\bv([0-9]+\.[0-9]+\.[0-9]+)",
    "juniper": r"JUNOS\s+([0-9][0-9A-Za-z.\-]*)",
    "ruckus": r"Version\s+([0-9]{2}\.[0-9]+\.[0-9]+[0-9A-Za-z]*)",
}
MODEL_PATTERNS = {
    "cisco": r"\b((?:WS-)?C\d{4}[A-Z]?(?:-[A-Z0-9+]+)*|C9\d{3}[A-Z]*(?:-[A-Z0-9+]+)*|IE-\d{4}[-A-Z0-9]*|N[3579]K-[A-Z0-9-]+)\b",
    "fortinet": r"\b(FortiGate-[0-9A-Z]+|FGT[0-9A-Z]+|FortiSwitch-[0-9A-Z-]+|FS-?[0-9]{3}[A-Z0-9-]*)\b",
    "juniper": r"\b((?:ex|qfx|srx|mx)[0-9][0-9a-z\-]*)",
    "ruckus": r"\b(ICX\s?\d{4}[A-Z0-9-]*)",
}


def enterprise_of(oid: str) -> int | None:
    m = re.match(r"^\.?1\.3\.6\.1\.4\.1\.(\d+)(?:\.|$)", oid or "")
    return int(m.group(1)) if m else None


def identify(sys_object_id: str, sys_descr: str, *, vendor_override: str = "", family_override: str = "") -> dict:
    oid, d = (sys_object_id or "").lstrip("."), sys_descr or ""
    out = {"vendor": "generic", "family": "", "device_type": "other", "model": "", "firmware": "", "os": "", "confidence": "unknown",
           "matched_by": "", "enterprise": enterprise_of(oid)}
    ent = ENTERPRISE.get(out["enterprise"] or -1)
    if ent:
        out.update(vendor=ent.vendor, confidence="vendor", matched_by=f"sysObjectID enterprise {ent.enterprise} ({ent.note})")
    rule = next((r for r in OID_RULES if oid == r.prefix or oid.startswith(r.prefix + ".")), None)
    if rule:
        out.update(vendor=rule.vendor, confidence="exact" if rule.family else out["confidence"] if ent else "vendor",
                   matched_by=f"sysObjectID {rule.prefix} ({rule.source})")
        if rule.family:
            out.update(family=rule.family, device_type=rule.device_type)
    if not out["family"]:
        cands = [r for r in DESCR_RULES if (out["vendor"] == "generic" or r.vendor == out["vendor"]) and re.search(r.pattern, d, re.I)]
        if cands:
            r = cands[0]
            if out["vendor"] == "generic":
                out.update(vendor=r.vendor, confidence="descr", matched_by=f"sysDescr /{r.pattern}/ (no vendor sysObjectID)")
            else:
                out.update(confidence="family", matched_by=out["matched_by"] + f"; family from sysDescr /{r.pattern}/")
            out.update(family=r.family, device_type=r.device_type, os=r.os)
    if not out["os"]:
        out["os"] = next((r.os for r in DESCR_RULES if r.vendor == out["vendor"] and r.family == out["family"] and r.os), "")
    if out["vendor"] == "cisco" and out["family"] in ("Catalyst", "Catalyst 9800 WLC", "ISR / ASR router"):
        out["os"] = "IOS-XE" if re.search(r"IOS[ -]XE|IOSXE", d) else out["os"] or "IOS"
    vp = VERSION_PATTERNS.get(out["vendor"])
    if vp and (m := re.search(vp, d, re.I)):
        out["firmware"] = m.group(1).rstrip(",")
    mp = MODEL_PATTERNS.get(out["vendor"])
    if mp and (m := re.search(mp, d, re.I)):
        out["model"] = m.group(1).replace(" ", "")
    if vendor_override:
        if vendor_override != out["vendor"] and out["vendor"] != "generic":
            out["override_conflict"] = f"device identifies as {out['vendor']}, overridden to {vendor_override}"
        out.update(vendor=vendor_override, confidence="override", matched_by="administrator override")
    if family_override:
        out.update(family=family_override, confidence="override", matched_by="administrator override")
    return out


def catalogue() -> dict:
    return {"enterprises": [e.__dict__ for e in ENTERPRISES], "oid_rules": [r.__dict__ for r in OID_RULES],
            "descr_rules": [r.__dict__ for r in DESCR_RULES], "vendors": list(VENDORS), "device_types": list(DEVICE_TYPES)}
