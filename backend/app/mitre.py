"""MITRE ATT&CK (Enterprise): technique catalogue, rule and alert coverage.

Catalogue. BUILTIN below is a curated subset: the techniques that network, authentication and network-device telemetry
can show (the data this platform collects), with names as published in ATT&CK Enterprise v16. It is not the whole
matrix: techniques that need endpoint telemetry (process, file, registry) are left out on purpose, so "coverage"
is measured against what is observable here, not against 600+ techniques nothing here could ever see.

Controlled update. To use the complete official catalogue (or a newer version), an administrator runs
    python -m app.mitre import enterprise-attack.json [out.json]
on the official STIX bundle (https://github.com/mitre-attack/attack-stix-data) and sets ATTACK_CATALOG_FILE to the
result. Nothing is downloaded automatically: the version in use is the file the administrator reviewed.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from functools import lru_cache

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .alerts.rules import TACTICS
from .db.models import Alert, AlertRule

log = logging.getLogger("mitre")
BUILTIN_VERSION = "16.1 (curated subset for network, identity and device telemetry)"
_SHORT = {"reconnaissance": "TA0043", "resource-development": "TA0042", "initial-access": "TA0001", "execution": "TA0002", "persistence": "TA0003",
          "privilege-escalation": "TA0004", "defense-evasion": "TA0005", "credential-access": "TA0006", "discovery": "TA0007",
          "lateral-movement": "TA0008", "collection": "TA0009", "command-and-control": "TA0011", "exfiltration": "TA0010", "impact": "TA0040"}

# id: (name, tactics, data sources that can show it here)
BUILTIN: dict[str, tuple[str, tuple[str, ...], str]] = {
    "T1595": ("Active Scanning", ("TA0043",), "firewall traffic, Zeek conn"),
    "T1190": ("Exploit Public-Facing Application", ("TA0001",), "IPS, firewall traffic, web logs"),
    "T1133": ("External Remote Services", ("TA0001", "TA0003"), "VPN logs, firewall traffic"),
    "T1078": ("Valid Accounts", ("TA0001", "TA0003", "TA0004", "TA0005"), "authentication logs, VPN logs"),
    "T1189": ("Drive-by Compromise", ("TA0001",), "web filter, Zeek http / files"),
    "T1566": ("Phishing", ("TA0001",), "web filter, DNS, mail gateway logs"),
    "T1200": ("Hardware Additions", ("TA0001",), "switch port security, DHCP, 802.1X"),
    "T1204": ("User Execution", ("TA0002",), "web filter, Zeek files"),
    "T1204.002": ("User Execution: Malicious File", ("TA0002",), "Zeek files, antivirus logs"),
    "T1053": ("Scheduled Task/Job", ("TA0002", "TA0003", "TA0004"), "Windows Security events"),
    "T1098": ("Account Manipulation", ("TA0003", "TA0004"), "Windows / Linux account events, firewall admin events"),
    "T1136": ("Create Account", ("TA0003",), "Windows / Linux account events"),
    "T1543": ("Create or Modify System Process", ("TA0003", "TA0004"), "Windows service events"),
    "T1543.003": ("Create or Modify System Process: Windows Service", ("TA0003", "TA0004"), "Windows events 4697 / 7045"),
    "T1548": ("Abuse Elevation Control Mechanism", ("TA0004", "TA0005"), "Linux sudo logs"),
    "T1548.003": ("Abuse Elevation Control Mechanism: Sudo and Sudo Caching", ("TA0004", "TA0005"), "Linux sudo logs"),
    "T1562": ("Impair Defenses", ("TA0005",), "firewall / device configuration changes"),
    "T1562.004": ("Impair Defenses: Disable or Modify System Firewall", ("TA0005",), "firewall configuration changes"),
    "T1562.006": ("Impair Defenses: Indicator Blocking", ("TA0005",), "log feed gaps"),
    "T1070": ("Indicator Removal", ("TA0005",), "Windows log-cleared events"),
    "T1070.001": ("Indicator Removal: Clear Windows Event Logs", ("TA0005",), "Windows events 1102 / 104"),
    "T1599": ("Network Boundary Bridging", ("TA0005",), "firewall configuration, routing changes"),
    "T1601": ("Modify System Image", ("TA0005",), "network device firmware inventory"),
    "T1556": ("Modify Authentication Process", ("TA0003", "TA0005", "TA0006"), "AAA configuration changes"),
    "T1110": ("Brute Force", ("TA0006",), "authentication logs, VPN logs"),
    "T1110.001": ("Brute Force: Password Guessing", ("TA0006",), "authentication logs"),
    "T1110.003": ("Brute Force: Password Spraying", ("TA0006",), "authentication logs"),
    "T1110.004": ("Brute Force: Credential Stuffing", ("TA0006",), "authentication logs"),
    "T1557": ("Adversary-in-the-Middle", ("TA0006", "TA0009"), "ARP inspection, DHCP snooping"),
    "T1557.002": ("Adversary-in-the-Middle: ARP Cache Poisoning", ("TA0006", "TA0009"), "dynamic ARP inspection logs"),
    "T1557.003": ("Adversary-in-the-Middle: DHCP Spoofing", ("TA0006", "TA0009"), "DHCP snooping logs, Zeek dhcp"),
    "T1558": ("Steal or Forge Kerberos Tickets", ("TA0006",), "Windows Kerberos events"),
    "T1040": ("Network Sniffing", ("TA0006", "TA0007"), "switch port mirroring / SPAN configuration"),
    "T1046": ("Network Service Discovery", ("TA0007",), "firewall traffic, Zeek conn, flows"),
    "T1018": ("Remote System Discovery", ("TA0007",), "firewall traffic, Zeek conn, flows"),
    "T1087": ("Account Discovery", ("TA0007",), "directory / authentication logs"),
    "T1135": ("Network Share Discovery", ("TA0007",), "Zeek conn (SMB), Windows events"),
    "T1021": ("Remote Services", ("TA0008",), "firewall traffic, Zeek conn, authentication logs"),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", ("TA0008",), "traffic on 3389, Windows logon type 10"),
    "T1021.002": ("Remote Services: SMB/Windows Admin Shares", ("TA0008",), "traffic on 445, Windows events"),
    "T1021.004": ("Remote Services: SSH", ("TA0008",), "Zeek ssh, Linux sshd logs"),
    "T1210": ("Exploitation of Remote Services", ("TA0008",), "IPS, Zeek notices"),
    "T1570": ("Lateral Tool Transfer", ("TA0008",), "Zeek files, SMB traffic"),
    "T1602": ("Data from Configuration Repository", ("TA0009",), "SNMP / device management access logs"),
    "T1071": ("Application Layer Protocol", ("TA0011",), "firewall traffic, DNS, web logs, threat intelligence"),
    "T1071.001": ("Application Layer Protocol: Web Protocols", ("TA0011",), "web filter, Zeek http / ssl"),
    "T1071.004": ("Application Layer Protocol: DNS", ("TA0011",), "DNS logs, Zeek dns"),
    "T1568": ("Dynamic Resolution", ("TA0011",), "DNS logs"),
    "T1568.002": ("Dynamic Resolution: Domain Generation Algorithms", ("TA0011",), "DNS logs (NXDOMAIN bursts, entropy)"),
    "T1571": ("Non-Standard Port", ("TA0011",), "firewall traffic, Zeek conn with protocol detection"),
    "T1572": ("Protocol Tunneling", ("TA0011",), "DNS logs, Zeek"),
    "T1573": ("Encrypted Channel", ("TA0011",), "Zeek ssl / x509, traffic periodicity"),
    "T1090": ("Proxy", ("TA0011",), "firewall traffic, web filter"),
    "T1095": ("Non-Application Layer Protocol", ("TA0011",), "firewall traffic (ICMP, raw protocols)"),
    "T1105": ("Ingress Tool Transfer", ("TA0011",), "web filter, Zeek files"),
    "T1219": ("Remote Access Software", ("TA0011",), "application control, DNS"),
    "T1102": ("Web Service", ("TA0011",), "web filter, DNS"),
    "T1041": ("Exfiltration Over C2 Channel", ("TA0010",), "firewall traffic volumes"),
    "T1048": ("Exfiltration Over Alternative Protocol", ("TA0010",), "firewall traffic volumes, DNS"),
    "T1567": ("Exfiltration Over Web Service", ("TA0010",), "web filter, application control"),
    "T1029": ("Scheduled Transfer", ("TA0010",), "traffic volumes outside business hours"),
    "T1030": ("Data Transfer Size Limits", ("TA0010",), "traffic volumes"),
    "T1565": ("Data Manipulation", ("TA0040",), "BGP route monitoring"),
    "T1498": ("Network Denial of Service", ("TA0040",), "firewall anomaly logs, flows"),
    "T1499": ("Endpoint Denial of Service", ("TA0040",), "firewall anomaly logs"),
    "T1531": ("Account Access Removal", ("TA0040",), "Windows / Linux account events"),
}


@lru_cache(maxsize=1)
def catalogue() -> dict:
    """{"version", "source", "techniques": {id: {name, tactics, data_sources}}}: the imported file when configured, else BUILTIN."""
    path = os.environ.get("ATTACK_CATALOG_FILE", "")
    if path:
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data.get("techniques"), dict) and data["techniques"]:
                return {"version": str(data.get("version", "?")), "source": f"imported file {os.path.basename(path)}", "techniques": data["techniques"]}
            log.error("ATTACK_CATALOG_FILE %s has no techniques: using the built-in catalogue", path)
        except (OSError, ValueError) as e:
            log.error("ATTACK_CATALOG_FILE %s unreadable (%s): using the built-in catalogue", path, e)
    return {"version": BUILTIN_VERSION, "source": "built-in",
            "techniques": {k: {"name": n, "tactics": list(t), "data_sources": d} for k, (n, t, d) in BUILTIN.items()}}


def technique(tid: str) -> dict:
    t = catalogue()["techniques"].get(tid)
    if t:
        return {"id": tid, **t, "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"}
    parent = catalogue()["techniques"].get(tid.split(".")[0])
    return {"id": tid, "name": (parent["name"] + " (sub-technique)") if parent else tid, "tactics": parent["tactics"] if parent else [],
            "data_sources": parent["data_sources"] if parent else "", "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
            "unknown": parent is None}


def import_stix(bundle: dict) -> dict:
    """Official ATT&CK STIX 2.1 bundle → catalogue file content (active Enterprise techniques only)."""
    version, techs = "?", {}
    for o in bundle.get("objects", []):
        if o.get("type") == "x-mitre-collection":
            version = o.get("x_mitre_version", version)
        if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        tid = next((r.get("external_id") for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if not tid:
            continue
        tactics = [_SHORT[p["phase_name"]] for p in o.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack" and p.get("phase_name") in _SHORT]
        techs[tid] = {"name": o.get("name", tid), "tactics": tactics, "data_sources": ", ".join(o.get("x_mitre_data_sources", [])[:6])}
    for tid, t in techs.items():   # sub-technique names as "Parent: Sub"
        if "." in tid and tid.split(".")[0] in techs and ":" not in t["name"]:
            t["name"] = f"{techs[tid.split('.')[0]]['name']}: {t['name']}"
    return {"version": version, "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"), "techniques": dict(sorted(techs.items()))}


def rule_techniques(m: dict | None) -> list[str]:
    return [t for t in ((m or {}).get("techniques") or []) if isinstance(t, str)]


async def coverage(s: AsyncSession, product_filter=None, days: int = 30) -> dict:
    """Which techniques have an enabled rule, which fired, how reliable those alerts were, and what is not covered."""
    cat = catalogue()
    rules = [r for r in (await s.execute(select(AlertRule))).scalars() if product_filter is None or product_filter(r.key)]
    since = datetime.now(timezone.utc) - timedelta(days=days)
    alerts = (await s.execute(select(Alert.rule_key, Alert.mitre, Alert.disposition, Alert.severity).where(Alert.last_seen >= since))).all()
    by_tech: dict[str, dict] = defaultdict(lambda: {"rules": [], "enabled": 0, "alerts": 0, "tp": 0, "fp": 0})
    for r in rules:
        for t in rule_techniques(r.mitre):
            d = by_tech[t]
            d["rules"].append({"key": r.key, "name": r.name, "enabled": r.enabled, "severity": r.severity})
            d["enabled"] += bool(r.enabled)
    tactic_alerts: Counter = Counter()
    known = {r.key for r in rules}
    for key, m, disp, _sev in alerts:
        if key not in known:
            continue
        if (m or {}).get("tactic"):
            tactic_alerts[m["tactic"]] += 1
        for t in rule_techniques(m):
            d = by_tech[t]
            d["alerts"] += 1
            d["tp"] += disp == "true_positive"
            d["fp"] += disp in ("false_positive", "benign")
    ids = sorted(set(cat["techniques"]) | set(by_tech))
    techs = []
    for tid in ids:
        info, d = technique(tid), by_tech.get(tid, {"rules": [], "enabled": 0, "alerts": 0, "tp": 0, "fp": 0})
        judged = d["tp"] + d["fp"]
        techs.append({**info, "rules": d["rules"], "rules_enabled": d["enabled"], "alerts": d["alerts"],
                      "status": "covered" if d["enabled"] else "disabled" if d["rules"] else "gap",
                      "precision": round(100.0 * d["tp"] / judged, 1) if judged else None, "judged": judged})
    # a parent technique counts as covered when one of its sub-techniques is (and the other way round for display only)
    covered = {t["id"] for t in techs if t["status"] == "covered"}
    for t in techs:
        if t["status"] != "covered" and ("." not in t["id"]) and any(c.startswith(t["id"] + ".") for c in covered):
            t["status"], t["via"] = "covered", "sub-technique"
    tactics = []
    for ta, name in TACTICS.items():
        mine = [t for t in techs if ta in t["tactics"]]
        tactics.append({"id": ta, "name": name, "techniques": len(mine), "covered": sum(1 for t in mine if t["status"] == "covered"),
                        "alerts": tactic_alerts.get(ta, 0)})
    total = len(techs)
    cov = sum(1 for t in techs if t["status"] == "covered")
    unmapped = [{"key": r.key, "name": r.name} for r in rules if r.enabled and not rule_techniques(r.mitre)]
    return {"catalog": {"version": cat["version"], "source": cat["source"], "techniques": len(cat["techniques"])}, "days": days,
            "summary": {"techniques": total, "covered": cov, "gaps": sum(1 for t in techs if t["status"] == "gap"),
                        "coverage_pct": round(100.0 * cov / total, 1) if total else None, "rules_mapped": sum(1 for r in rules if rule_techniques(r.mitre)),
                        "rules_unmapped": len(unmapped)},
            "tactics": tactics, "techniques": techs, "unmapped_rules": unmapped[:100]}


if __name__ == "__main__":   # python -m app.mitre import enterprise-attack.json [out.json]
    if len(sys.argv) < 3 or sys.argv[1] != "import":
        sys.exit(__doc__)
    with open(sys.argv[2], encoding="utf-8") as fh:
        out = import_stix(json.load(fh))
    dest = sys.argv[3] if len(sys.argv) > 3 else "attack-catalog.json"
    with open(dest, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)
    print(f"ATT&CK {out['version']}: {len(out['techniques'])} techniques → {dest}. Review it, then set ATTACK_CATALOG_FILE to its path.")
