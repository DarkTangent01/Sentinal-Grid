"""MIB / OID profile manager: custom read-only OID items, built-in metric switches, MIB module import and OID tests
(docs/SNMP.md).

* MIB import is a text parser: it reads OBJECT-TYPE / OBJECT IDENTIFIER / NOTIFICATION-TYPE / MODULE-IDENTITY / OBJECT-IDENTITY
  assignments (`name ... ::= { parent n }`) and resolves them against a built-in root table plus previously imported
  modules. Nothing in an uploaded file is ever executed, compiled or imported. Definitions whose parent cannot be
  resolved are listed as unresolved, not guessed.
* A MIB definition says nothing about what a device implements: support is only ever shown from device answers
  (capability registry, OID test).
* Custom OIDs are GET (scalar) or GETBULK walk (one table column) only, validated as numeric dotted OIDs.
"""
from __future__ import annotations

import hashlib
import re

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .db.models import SnmpCustomOid, SnmpMetricSetting, SnmpMibModule, Switch

MAX_MIB_BYTES = 2 * 1024 * 1024
OID_RE = re.compile(r"^1(\.(0|[1-9][0-9]{0,9})){3,127}$")
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.\-]{0,63}$")

# well-known roots (SNMPv2-SMI / RFC 1155 / common enterprise subtrees) used to anchor imported definitions
ROOTS = {
    "iso": "1", "org": "1.3", "dod": "1.3.6", "internet": "1.3.6.1", "directory": "1.3.6.1.1", "mgmt": "1.3.6.1.2", "mib-2": "1.3.6.1.2.1",
    "transmission": "1.3.6.1.2.1.10", "experimental": "1.3.6.1.3", "private": "1.3.6.1.4", "enterprises": "1.3.6.1.4.1",
    "security": "1.3.6.1.5", "snmpV2": "1.3.6.1.6", "snmpDomains": "1.3.6.1.6.1", "snmpProxys": "1.3.6.1.6.2", "snmpModules": "1.3.6.1.6.3",
    "zeroDotZero": "0.0", "system": "1.3.6.1.2.1.1", "interfaces": "1.3.6.1.2.1.2", "ip": "1.3.6.1.2.1.4", "snmp": "1.3.6.1.2.1.11",
    "ifMIB": "1.3.6.1.2.1.31", "entityMIB": "1.3.6.1.2.1.47", "host": "1.3.6.1.2.1.25",
    "cisco": "1.3.6.1.4.1.9", "ciscoMgmt": "1.3.6.1.4.1.9.9", "ciscoProducts": "1.3.6.1.4.1.9.1", "ciscoExperiment": "1.3.6.1.4.1.9.10",
    "fortinet": "1.3.6.1.4.1.12356", "fnFortiGateMib": "1.3.6.1.4.1.12356.101", "fnFortiSwitchMib": "1.3.6.1.4.1.12356.106",
    "juniperMIB": "1.3.6.1.4.1.2636", "jnxProducts": "1.3.6.1.4.1.2636.1", "jnxMibs": "1.3.6.1.4.1.2636.3", "jnxTraps": "1.3.6.1.4.1.2636.4",
    "foundry": "1.3.6.1.4.1.1991", "products": "1.3.6.1.4.1.1991.1", "ruckusRootMIB": "1.3.6.1.4.1.25053",
}

_ASSIGN = re.compile(
    r"(?P<name>[a-z][A-Za-z0-9\-]*)\s+(?P<kind>OBJECT-TYPE|OBJECT\s+IDENTIFIER|NOTIFICATION-TYPE|TRAP-TYPE|MODULE-IDENTITY|OBJECT-IDENTITY|OBJECT-GROUP|"
    r"NOTIFICATION-GROUP|MODULE-COMPLIANCE)(?P<body>(?:(?!::=).){0,20000}?)::=\s*\{\s*(?P<parent>[A-Za-z][A-Za-z0-9\-]*)(?P<path>(?:\s+(?:[A-Za-z][A-Za-z0-9\-]*\(\d+\)|\d+))+)\s*\}",
    re.S)
_TRAP_TYPE = re.compile(r"(?P<name>[a-z][A-Za-z0-9\-]*)\s+TRAP-TYPE.*?ENTERPRISE\s+(?P<ent>[A-Za-z][A-Za-z0-9\-]*).*?::=\s*(?P<n>\d+)", re.S)


def strip_comments(src: str) -> str:
    """ASN.1 comments: "--" to end of line or to the next "--"."""
    out = []
    for line in src.splitlines():
        parts = line.split("--")
        out.append("".join(parts[0::2]))
    return "\n".join(out)


def parse_mib(src: str, known: dict[str, str] | None = None) -> dict:
    """Parse one MIB module (text) → {module, imports, objects, unresolved}. `known` = name → OID from other modules."""
    if len(src.encode("utf-8", "replace")) > MAX_MIB_BYTES:
        raise ValueError("MIB file larger than 2 MB")
    if "\x00" in src:
        raise ValueError("binary content is not a MIB module")
    text = strip_comments(src)
    m = re.search(r"([A-Z][A-Za-z0-9\-]*)\s+DEFINITIONS\s*::=\s*BEGIN", text)
    if not m:
        raise ValueError("not a MIB module: no '<NAME> DEFINITIONS ::= BEGIN' header")
    module = m.group(1)
    if not re.search(r"\bEND\b\s*$", text.strip()):
        raise ValueError(f"{module}: missing END")
    imports = []
    im = re.search(r"\bIMPORTS\b(.*?);", text, re.S)
    if im:
        imports = sorted(set(re.findall(r"FROM\s+([A-Z][A-Za-z0-9\-]*)", im.group(1))))
    names = dict(ROOTS)
    names.update(known or {})
    pending = []
    for a in _ASSIGN.finditer(text):
        path = []
        for tok in a.group("path").split():
            n = re.search(r"\((\d+)\)", tok)
            path.append(n.group(1) if n else tok)
        if not all(p.isdigit() for p in path):
            continue
        body = a.group("body")
        pending.append({"name": a.group("name"), "kind": re.sub(r"\s+", " ", a.group("kind")), "parent": a.group("parent"), "path": path,
                        "syntax": _field(body, "SYNTAX"), "access": _field(body, "MAX-ACCESS") or _field(body, "ACCESS"),
                        "status": _field(body, "STATUS"), "description": _desc(body)})
    objects: dict[str, dict] = {}
    for _ in range(64):            # resolve parents defined later in the file
        progressed = False
        for p in pending:
            if p["name"] in objects or p["parent"] not in names:
                continue
            oid = ".".join([names[p["parent"]], *p["path"]])
            if not re.fullmatch(r"[0-9]+(\.[0-9]+)*", oid):
                continue
            names[p["name"]] = oid
            objects[p["name"]] = {"oid": oid, "kind": p["kind"], "syntax": p["syntax"], "access": p["access"], "status": p["status"],
                                  "description": p["description"]}
            progressed = True
        if not progressed:
            break
    for t in _TRAP_TYPE.finditer(text):   # SMIv1 traps: enterprise.0.specific (RFC 3584)
        if t.group("ent") in names and t.group("name") not in objects:
            objects[t.group("name")] = {"oid": f"{names[t.group('ent')]}.0.{t.group('n')}", "kind": "TRAP-TYPE", "syntax": "", "access": "",
                                        "status": "", "description": ""}
    unresolved = sorted({p["parent"] for p in pending if p["name"] not in objects})
    if not objects:
        raise ValueError(f"{module}: no object definitions could be resolved (missing imported modules: {', '.join(unresolved[:10]) or '—'})")
    return {"module": module, "imports": imports, "objects": objects, "unresolved": unresolved}


def _field(body: str, key: str) -> str:
    m = re.search(rf"\b{key}\s+([^\n]+)", body)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200] if m else ""


def _desc(body: str) -> str:
    m = re.search(r'DESCRIPTION\s+"(.*?)"', body, re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:1000] if m else ""


def sha256(src: str) -> str:
    return hashlib.sha256(src.encode("utf-8", "replace")).hexdigest()


async def known_names(s: AsyncSession, exclude: str | None = None) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in (await s.execute(select(SnmpMibModule).where(SnmpMibModule.enabled.is_(True)))).scalars():
        if m.name != exclude:
            out.update({k: v["oid"] for k, v in (m.objects or {}).items()})
    return out


async def oid_names(s: AsyncSession) -> dict[str, str]:
    """OID → "MODULE::name" for every imported definition plus the built-in registry (for naming trap varbinds)."""
    out: dict[str, str] = {}
    for m in (await s.execute(select(SnmpMibModule).where(SnmpMibModule.enabled.is_(True)))).scalars():
        for k, v in (m.objects or {}).items():
            out.setdefault(v["oid"], f"{m.name}::{k}")
    from .snmp_traps import TRAP_NAMES
    for oid, n in TRAP_NAMES.items():
        out.setdefault(oid, n)
    return out


def name_oid(oid: str, names: dict[str, str]) -> str:
    """Longest-prefix name: 1.3.6.1.2.1.2.2.1.8.12 → IF-MIB::ifOperStatus.12."""
    parts = oid.split(".")
    for i in range(len(parts), 0, -1):
        n = names.get(".".join(parts[:i]))
        if n:
            rest = ".".join(parts[i:])
            return n + (f".{rest}" if rest else "")
    return oid


def validate_oid(oid: str) -> str:
    oid = (oid or "").strip().lstrip(".")
    if not OID_RE.fullmatch(oid):
        raise ValueError("an OID must be numeric dotted notation starting with 1 (e.g. 1.3.6.1.2.1.1.3.0)")
    return oid


# ------------------------------------------------------------------ custom OIDs and metric switches
def applies(c: SnmpCustomOid, sw: Switch) -> bool:
    if not c.enabled:
        return False
    if c.switch_ids and sw.id not in c.switch_ids:
        return False
    if c.vendor and c.vendor != (sw.vendor_override or sw.vendor):
        return False
    if c.product_line and c.product_line.lower() != (sw.family_override or sw.product_line or "").lower():
        return False
    return True


async def custom_items_for(s: AsyncSession, sw: Switch) -> list[dict]:
    rows = (await s.execute(select(SnmpCustomOid).where(SnmpCustomOid.enabled.is_(True)))).scalars().all()
    return [{"name": c.name, "oid": c.oid, "method": c.method, "value_type": c.value_type, "unit": c.unit, "scale": c.scale}
            for c in rows if applies(c, sw)][:100]


async def disabled_metrics(s: AsyncSession) -> set[str]:
    return {r.key for r in (await s.execute(select(SnmpMetricSetting).where(SnmpMetricSetting.enabled.is_(False)))).scalars()}


def custom_row(c: SnmpCustomOid) -> dict:
    return {"id": c.id, "name": c.name, "oid": c.oid, "method": c.method, "value_type": c.value_type, "unit": c.unit, "scale": c.scale,
            "vendor": c.vendor, "product_line": c.product_line, "switch_ids": c.switch_ids or [], "description": c.description,
            "enabled": c.enabled, "version": c.version, "created_by": c.created_by, "updated_at": c.updated_at.isoformat() if c.updated_at else None}


async def test_oid(client, oid: str, method: str, max_rows: int = 200) -> dict:
    """Read-only test of one OID against a device: GET or walk; raw and parsed values."""
    from .switches.collect import num, text
    from .switches.snmp import MISSING
    if method == "get":
        r = await client.get([oid])
        pairs = [(oid, r.get(oid))]
    else:
        pairs = await client.walk(oid, max_rows=max_rows)
    rows = []
    for o, v in pairs:
        if v is MISSING or v is None:
            rows.append({"oid": o, "type": "missing", "raw": None, "value": None})
            continue
        typ = "bytes" if isinstance(v, bytes) else "oid" if isinstance(v, str) and re.fullmatch(r"[0-9.]+", v) else type(v).__name__
        printable = isinstance(v, bytes) and all(32 <= b < 127 or b in (9, 10, 13) for b in v)
        raw = (v.decode("ascii") if printable else v.hex(":")) if isinstance(v, bytes) else v
        rows.append({"oid": o, "type": typ, "raw": raw, "value": num(v) if not isinstance(v, bytes) else (text(v) if printable else None)})
    return {"oid": oid, "method": method, "rows": rows, "answered": any(r["type"] != "missing" for r in rows), "truncated": len(pairs) >= max_rows}
