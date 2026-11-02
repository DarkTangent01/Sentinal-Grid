"""SNMP collection and normalisation per metric group, with separate Cisco and Ruckus ICX adapters.

Every collector reads (GET / GETBULK only), records per-metric outcomes in an `Outcome` (ok / missing / error /
not_configured) and returns normalised data in one vendor-neutral shape. Vendor-specific OIDs are only requested from
that vendor's switches: CiscoAdapter never asks a Ruckus switch for a Cisco MIB and vice versa. Standard MIBs (IF-MIB,
EtherLike, ENTITY, BRIDGE, Q-BRIDGE, POWER-ETHERNET, IEEE8023-LAG, IP, OSPF, BGP4) are shared.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .registry import METRICS, Outcome
from .snmp import MISSING, SnmpError

SYS = "1.3.6.1.2.1.1"
SNMP_ENGINE_ID = "1.3.6.1.6.3.10.2.1.1.0"   # SNMP-FRAMEWORK-MIB snmpEngineID (needed to authenticate the device's SNMPv3 traps)
IF = "1.3.6.1.2.1.2.2.1"
IFX = "1.3.6.1.2.1.31.1.1.1"
DOT3 = "1.3.6.1.2.1.10.7.2.1"
ENT = "1.3.6.1.2.1.47.1.1.1.1"
BRIDGE = "1.3.6.1.2.1.17"
BASE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"
STP = "1.3.6.1.2.1.17.2"
STP_PORT = "1.3.6.1.2.1.17.2.15.1"
QVLAN_STATIC = "1.3.6.1.2.1.17.7.1.4.3.1"
QVLAN_CURRENT = "1.3.6.1.2.1.17.7.1.4.2.1"
QPVID = "1.3.6.1.2.1.17.7.1.4.5.1.1"
QFDB = "1.3.6.1.2.1.17.7.1.2.2.1"
DFDB = "1.3.6.1.2.1.17.4.3.1"
PETH_PORT = "1.3.6.1.2.1.105.1.1.1"
PETH_MAIN = "1.3.6.1.2.1.105.1.3.1.1"
LAG_PORT = "1.2.840.10006.300.43.1.2.1.1"
IPADDR = "1.3.6.1.2.1.4.20.1"
OSPF_NBR = "1.3.6.1.2.1.14.10.1"
BGP_PEER = "1.3.6.1.2.1.15.3.1"
LLDP_LOC_PORT = "1.0.8802.1.1.2.1.3.7.1"
LLDP_REM = "1.0.8802.1.1.2.1.4.1.1"
LLDP_REM_MAN = "1.0.8802.1.1.2.1.4.2.1"
LLDP_LOC_SYSNAME = "1.0.8802.1.1.2.1.3.3.0"
# Cisco
C_CDP = "1.3.6.1.4.1.9.9.23.1.2.1.1"
C_CPU = "1.3.6.1.4.1.9.9.109.1.1.1.1"
C_MEMPOOL = "1.3.6.1.4.1.9.9.48.1.1.1"
C_EMEMPOOL = "1.3.6.1.4.1.9.9.221.1.1.1.1"
C_ENV = "1.3.6.1.4.1.9.9.13.1"
C_SENSOR = "1.3.6.1.4.1.9.9.91.1.1.1.1"
C_STACK = "1.3.6.1.4.1.9.9.500.1.2.1.1"
C_STACKPORT = "1.3.6.1.4.1.9.9.500.1.2.2.1.1"
C_RING = "1.3.6.1.4.1.9.9.500.1.1.3.0"
C_POE_EXT = "1.3.6.1.4.1.9.9.402.1.2.1"
C_VTP_VLAN = "1.3.6.1.4.1.9.9.46.1.3.1.1"
C_TRUNK = "1.3.6.1.4.1.9.9.46.1.6.1.1"
C_VMVLAN = "1.3.6.1.4.1.9.9.68.1.2.2.1.2"
C_STP_TYPE = "1.3.6.1.4.1.9.9.82.1.6.1.0"
C_LIF = "1.3.6.1.4.1.9.2.2.1.1"
C_PAGP = "1.3.6.1.4.1.9.9.98.1.1.1.1.8"
# Ruckus / Foundry (enterprise 1991)
R_GBL = "1.3.6.1.4.1.1991.1.1.2.1"
R_CPU = "1.3.6.1.4.1.1991.1.1.2.11.1.1"
R_CHAS = "1.3.6.1.4.1.1991.1.1.1.1"
R_PSU = "1.3.6.1.4.1.1991.1.1.1.2.1.1"
R_PSU2 = "1.3.6.1.4.1.1991.1.1.1.2.2.1"
R_FAN = "1.3.6.1.4.1.1991.1.1.1.3.1.1"
R_FAN2 = "1.3.6.1.4.1.1991.1.1.1.3.2.1"
R_TEMP = "1.3.6.1.4.1.1991.1.1.2.13.1.1"
R_TEMP2 = "1.3.6.1.4.1.1991.1.1.2.13.3.1"
R_STACK = "1.3.6.1.4.1.1991.1.1.3.31.2.2.1"
R_UNIT = "1.3.6.1.4.1.1991.1.1.1.4.1.1"
R_POE_GBL = "1.3.6.1.4.1.1991.1.1.2.14.1"
R_POE_PORT = "1.3.6.1.4.1.1991.1.1.2.14.2.2.1"
R_POE_UNIT = "1.3.6.1.4.1.1991.1.1.2.14.4.1.1"

ENV_STATE = {1: "ok", 2: "warning", 3: "critical", 4: "shutdown", 5: "absent", 6: "failed"}
R_STATE = {1: "unknown", 2: "ok", 3: "failed"}
STP_STATE = {1: "disabled", 2: "blocking", 3: "listening", 4: "learning", 5: "forwarding", 6: "broken"}
LACP_BITS = ("activity", "timeout", "aggregation", "synchronization", "collecting", "distributing", "defaulted", "expired")
PETH_DETECT = {1: "disabled", 2: "searching", 3: "delivering", 4: "fault", 5: "test", 6: "other_fault"}
# Standard host and sensor MIBs: the Generic adapter's only source (routers, servers, appliances, UPSs, any SNMP device)
# and the fallback when a vendor MIB returns nothing.
HR_PROC = "1.3.6.1.2.1.25.3.3.1"          # HOST-RESOURCES-MIB hrProcessorTable (.2 hrProcessorLoad)
HR_STORAGE = "1.3.6.1.2.1.25.2.3.1"       # hrStorageTable (.2 type .3 descr .4 allocation units .5 size .6 used)
HR_TYPE = "1.3.6.1.2.1.25.2.1"            # hrStorageTypes: .2 RAM .3 virtual .4 fixed disk .5 removable .9 flash .10 network disk
UCD_MEM = "1.3.6.1.4.1.2021.4"            # UCD-SNMP-MIB memory (kB): .5 total .6 available .14 buffers .15 cached
UCD_LOAD = "1.3.6.1.4.1.2021.10.1.3"      # laLoad.1/.2/.3 (1 / 5 / 15 minute, DisplayString)
UCD_CPU_IDLE = "1.3.6.1.4.1.2021.11.11.0"  # ssCpuIdle (%)
ENT_SENSOR = "1.3.6.1.2.1.99.1.1.1"       # ENTITY-SENSOR-MIB entPhySensorTable (.1 type .2 scale .3 precision .4 value .5 status)
STORAGE_KINDS = {"2": "ram", "3": "virtual", "4": "disk", "5": "removable", "9": "flash", "10": "network_disk"}
SENSOR_KINDS = {3: ("voltage", "V AC"), 4: ("voltage", "V DC"), 5: ("current", "A"), 6: ("power", "W"), 7: ("frequency", "Hz"),
                8: ("temperature", "°C"), 9: ("humidity", "%RH"), 10: ("fan", "rpm"), 11: ("airflow", "CMM")}


# ------------------------------------------------------------------ value helpers
def text(v) -> str:
    if v is MISSING or v is None:
        return ""
    if isinstance(v, bytes):
        return v.replace(b"\x00", b"").decode("utf-8", "replace").strip()
    return str(v).strip()


def mac(v) -> str:
    if isinstance(v, bytes) and len(v) == 6:
        return ":".join(f"{b:02x}" for b in v)
    if isinstance(v, str) and re.fullmatch(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", v):
        return v.lower().replace("-", ":")
    return ""


def num(v):
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def portlist(v) -> list[int]:
    """BRIDGE-MIB PortList: bit 1 is the most significant bit of the first octet."""
    if not isinstance(v, bytes):
        return []
    return [i * 8 + b + 1 for i, octet in enumerate(v) for b in range(8) if octet & (0x80 >> b)]


def bits(v, names=LACP_BITS) -> dict[str, bool]:
    b = v[0] if isinstance(v, bytes) and v else 0
    return {n: bool(b & (0x80 >> i)) for i, n in enumerate(names)}


def bridge_id(v) -> str:
    """8-octet bridge id → 'priority/mac'."""
    if isinstance(v, bytes) and len(v) == 8:
        return f"{int.from_bytes(v[:2], 'big')}/{mac(v[2:])}"
    return ""


def suffix(oid: str, base: str) -> str:
    return oid[len(base) + 1:]


def column(rows, base: str) -> dict[str, object]:
    return {suffix(o, base): v for o, v in rows}


# ------------------------------------------------------------------ identification
def identify(sys_object_id: str, sys_descr: str, *, vendor_override: str = "", family_override: str = "") -> dict:
    """Fingerprint registry (fingerprints.py) plus the model-level family used across the UI ("Catalyst 9300", "ICX 7150").
    `product_line` is the registry's family (Catalyst, Nexus, FortiGate, EX, ICX …) and selects the monitoring profile."""
    from .fingerprints import identify as fingerprint
    out = fingerprint(sys_object_id, sys_descr, vendor_override=vendor_override, family_override=family_override)
    out["product_line"] = out["family"]
    if not family_override:
        out["family"] = family_of(out["vendor"], out["model"]) or out["product_line"]
    return out


def family_of(vendor: str, model: str) -> str:
    if vendor == "cisco":
        m = re.match(r"(?:WS-)?C(\d{4})([A-Z]?)", model or "")
        if m:
            return f"Catalyst {m.group(1)}{m.group(2) if m.group(2) in ('L', 'X', 'V') else ''}"
        if (model or "").startswith("IE-"):
            return "Industrial Ethernet " + model.split("-")[1]
        return "Catalyst" if model else ""
    if vendor == "ruckus":
        m = re.match(r"ICX(\d{4})", model or "")
        return f"ICX {m.group(1)}" if m else "ICX" if not model or model.upper().startswith("ICX") else ""
    if vendor == "juniper":
        m = re.match(r"(ex|qfx|srx|mx)(\d+)", (model or "").lower())
        return f"{m.group(1).upper()} {m.group(2)}" if m else ""
    if vendor == "fortinet":
        m = re.match(r"(?:FortiGate-|FGT)(\d+[A-Z]?)", model or "", re.I)
        if m:
            return f"FortiGate {m.group(1)}"
        m = re.match(r"(?:FortiSwitch-|FS-?)(\d+[A-Z]?)", model or "", re.I)
        return f"FortiSwitch {m.group(1)}" if m else ""
    return ""


# ------------------------------------------------------------------ context
@dataclass
class Ctx:
    client: object
    vendor: str
    outcome: Outcome
    snmp_version: str = "v3"
    prev: dict = field(default_factory=dict)      # previous normalised data (interface names, VLANs, entity names)
    max_vlan_contexts: int = 64
    max_macs: int = 50000
    vendor_override: str = ""                     # administrator profile overrides (fingerprints.identify)
    family_override: str = ""
    product_line: str = ""                        # set after the system group (fingerprint family)
    custom_oids: list = field(default_factory=list)   # SnmpCustomOid rows applicable to this device
    disabled: set = field(default_factory=set)    # registry metric keys an administrator disabled

    def vlan_context(self, vid: int) -> str:
        return f"vlan-{vid}" if self.snmp_version == "v3" else str(vid)


async def _cols(ctx: Ctx, table: str, cols: dict[str, int], context: str | None = None, max_rows: int | None = None) -> dict[str, dict]:
    """Walk several columns of one table → {index: {name: value}}."""
    bases = {f"{table}.{n}": name for name, n in cols.items()}
    res = await ctx.client.walk_multi(list(bases), context=context, max_rows=max_rows)
    rows: dict[str, dict] = {}
    for b, name in bases.items():
        for o, v in res.get(b, []):
            rows.setdefault(suffix(o, b), {})[name] = v
    return rows


# ------------------------------------------------------------------ standard groups
async def collect_system(ctx: Ctx) -> dict:
    r = await ctx.client.get([f"{SYS}.1.0", f"{SYS}.2.0", f"{SYS}.3.0", f"{SYS}.4.0", f"{SYS}.5.0", f"{SYS}.6.0", SNMP_ENGINE_ID])
    up = num(r.get(f"{SYS}.3.0"))
    descr = text(r.get(f"{SYS}.1.0"))
    if up is None and not descr:
        raise SnmpError("protocol", "the switch answered but returned neither sysUpTime nor sysDescr")
    ctx.outcome.ok("switch_up")
    (ctx.outcome.ok if up is not None else ctx.outcome.missing)("switch_uptime_seconds")
    ctx.outcome.ok("switch_system_info")
    oid = r.get(f"{SYS}.2.0")
    return {"sys_descr": descr, "sys_object_id": oid if isinstance(oid, str) else "", "uptime_ticks": up,
            "uptime_s": up / 100 if up is not None else None, "contact": text(r.get(f"{SYS}.4.0")),
            "sys_name": text(r.get(f"{SYS}.5.0")), "location": text(r.get(f"{SYS}.6.0")),
            "engine_id": r.get(SNMP_ENGINE_ID).hex() if isinstance(r.get(SNMP_ENGINE_ID), bytes) else ""}


async def collect_interfaces(ctx: Ctx) -> dict:
    o = ctx.outcome
    base = await _cols(ctx, IF, {"descr": 2, "type": 3, "mtu": 4, "speed": 5, "phys": 6, "admin": 7, "oper": 8, "last_change": 9,
                                 "in_octets32": 10, "in_ucast32": 11, "in_discards": 13, "in_errors": 14,
                                 "out_octets32": 16, "out_ucast32": 17, "out_discards": 19, "out_errors": 20})
    if not base:
        o.missing("switch_interface_status")
        return {"interfaces": {}}
    x = await _cols(ctx, IFX, {"name": 1, "in_mc32": 2, "in_bc32": 3, "out_mc32": 4, "out_bc32": 5, "hc_in": 6, "hc_in_ucast": 7,
                               "hc_in_mc": 8, "hc_in_bc": 9, "hc_out": 10, "hc_out_ucast": 11, "hc_out_mc": 12, "hc_out_bc": 13,
                               "high_speed": 15, "alias": 18, "disc": 19})
    dot3: dict = {}
    try:
        dot3 = await _cols(ctx, DOT3, {"fcs": 3, "duplex": 19})
    except SnmpError as e:
        o.error("switch_interface_duplex", e.message)
        o.error("switch_interface_fcs_errors", e.message)
    lif: dict = {}
    if ctx.vendor == "cisco":
        try:
            lif = await _cols(ctx, C_LIF, {"crc": 12, "resets": 17, "carrier": 21})
        except SnmpError as e:
            for k in ("switch_interface_crc_errors", "switch_interface_resets", "switch_interface_carrier_transitions"):
                o.error(k, e.message)
    ifaces = {}
    any_hc = any_alias = any_disc = False
    for idx, b in base.items():
        if not idx.isdigit():
            continue
        e = x.get(idx, {})
        hc = isinstance(e.get("hc_in"), int) and isinstance(e.get("hc_out"), int)
        any_hc |= hc
        if hc:
            c = {"in_octets": e["hc_in"], "out_octets": e["hc_out"],
                 "in_pkts": _sum(e, "hc_in_ucast", "hc_in_mc", "hc_in_bc"), "out_pkts": _sum(e, "hc_out_ucast", "hc_out_mc", "hc_out_bc"),
                 "in_ucast": num(e.get("hc_in_ucast")), "in_mcast": num(e.get("hc_in_mc")), "in_bcast": num(e.get("hc_in_bc")),
                 "out_ucast": num(e.get("hc_out_ucast")), "out_mcast": num(e.get("hc_out_mc")), "out_bcast": num(e.get("hc_out_bc"))}
        else:
            c = {"in_octets": num(b.get("in_octets32")), "out_octets": num(b.get("out_octets32")),
                 "in_pkts": _sum({**b, **e}, "in_ucast32", "in_mc32", "in_bc32"), "out_pkts": _sum({**b, **e}, "out_ucast32", "out_mc32", "out_bc32"),
                 "in_ucast": num(b.get("in_ucast32")), "out_ucast": num(b.get("out_ucast32")),
                 "in_mcast": num(e.get("in_mc32")), "in_bcast": num(e.get("in_bc32")), "out_mcast": num(e.get("out_mc32")), "out_bcast": num(e.get("out_bc32"))}
        for k in ("in_errors", "out_errors", "in_discards", "out_discards"):
            c[k] = num(b.get(k))
        d3, lf = dot3.get(idx, {}), lif.get(idx, {})
        c["crc"] = num(lf.get("crc")) if num(lf.get("crc")) is not None else num(d3.get("fcs"))
        c["resets"], c["carrier"] = num(lf.get("resets")), num(lf.get("carrier"))
        alias = text(e.get("alias"))
        any_alias |= "alias" in e
        any_disc |= isinstance(e.get("disc"), int)
        duplex = {1: "unknown", 2: "half", 3: "full"}.get(num(d3.get("duplex")) or 0, "")
        ifaces[int(idx)] = {"ifindex": int(idx), "name": text(e.get("name")) or text(b.get("descr")), "descr": text(b.get("descr")), "alias": alias,
                            "type": num(b.get("type")), "mtu": num(b.get("mtu")), "if_speed": num(b.get("speed")),
                            "high_speed": num(e.get("high_speed")), "mac": mac(b.get("phys")),
                            "admin": {1: "up", 2: "down", 3: "testing"}.get(num(b.get("admin")) or 0, "unknown"),
                            "oper": {1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant", 6: "not_present", 7: "lower_layer_down"}.get(num(b.get("oper")) or 0, "unknown"),
                            "last_change_ticks": num(b.get("last_change")), "duplex": duplex, "hc": hc,
                            "disc": num(e.get("disc")), "c": c}
    o.ok("switch_interface_status", len(ifaces))
    (o.ok if any_hc else o.missing)("switch_interface_octets_hc", sum(1 for i in ifaces.values() if i["hc"]) or 1)
    if any(not i["hc"] and i["c"]["in_octets"] is not None for i in ifaces.values()):
        o.ok("switch_interface_octets_32")
    elif ifaces and all(i["hc"] for i in ifaces.values()):
        o.not_configured("switch_interface_octets_32", "not needed: every interface has 64-bit counters")
    else:
        o.missing("switch_interface_octets_32")
    (o.ok if any(i["c"]["in_pkts"] is not None for i in ifaces.values()) else o.missing)("switch_interface_packets")
    (o.ok if any(i["c"]["in_errors"] is not None for i in ifaces.values()) else o.missing)("switch_interface_errors")
    (o.ok if any(i["c"]["in_discards"] is not None for i in ifaces.values()) else o.missing)("switch_interface_discards")
    (o.ok if any(i["high_speed"] or i["if_speed"] for i in ifaces.values()) else o.missing)("switch_interface_speed")
    (o.ok if any_alias else o.missing)("switch_interface_alias")
    (o.ok if any_disc else o.missing)("switch_interface_counter_discontinuity")
    (o.ok if any(i["duplex"] for i in ifaces.values()) else o.missing)("switch_interface_duplex")
    (o.ok if any(num(v.get("fcs")) is not None for v in dot3.values()) else o.missing)("switch_interface_fcs_errors")
    if ctx.vendor == "cisco":
        for k, f in (("switch_interface_crc_errors", "crc"), ("switch_interface_resets", "resets"), ("switch_interface_carrier_transitions", "carrier")):
            (o.ok if any(num(v.get(f)) is not None for v in lif.values()) else o.missing)(k)
    return {"interfaces": ifaces}


def _sum(d: dict, *keys):
    vals = [d.get(k) for k in keys]
    vals = [v for v in vals if isinstance(v, int)]
    return sum(vals) if vals else None


async def collect_inventory(ctx: Ctx) -> dict:
    rows = await _cols(ctx, ENT, {"descr": 2, "class": 5, "name": 7, "hw": 8, "sw": 10, "serial": 11, "model": 13}, max_rows=3000)
    cls = {1: "other", 2: "unknown", 3: "chassis", 4: "backplane", 5: "container", 6: "power_supply", 7: "fan", 8: "sensor",
           9: "module", 10: "port", 11: "stack", 12: "cpu"}
    items = []
    for idx, r in rows.items():
        c = cls.get(num(r.get("class")) or 0, "unknown")
        if c in ("port", "container", "sensor") and not text(r.get("serial")):
            continue
        items.append({"index": int(idx) if idx.isdigit() else idx, "class": c, "name": text(r.get("name")), "descr": text(r.get("descr")),
                      "model": text(r.get("model")), "serial": text(r.get("serial")), "hw": text(r.get("hw")), "sw": text(r.get("sw"))})
    names = {int(i): text(r.get("name")) for i, r in rows.items() if i.isdigit() and text(r.get("name"))}
    chassis = [i for i in items if i["class"] == "chassis"]
    ident = {"model": next((c["model"] for c in chassis if c["model"]), ""), "serial": next((c["serial"] for c in chassis if c["serial"]), ""),
             "serials": [c["serial"] for c in chassis if c["serial"]]}
    ctx.outcome.ok("switch_inventory", len(items)) if items else ctx.outcome.missing("switch_inventory")
    fw = ""
    if ctx.vendor == "ruckus":
        r = await ctx.client.get([f"{R_GBL}.11.0", f"{R_CHAS}.2.0"])
        fw = text(r.get(f"{R_GBL}.11.0"))
        ident["serial"] = ident["serial"] or text(r.get(f"{R_CHAS}.2.0"))
        units = await _cols(ctx, R_UNIT, {"serial": 2})
        if units:
            ident["serials"] = [text(u.get("serial")) for _, u in sorted(units.items()) if text(u.get("serial"))] or ident["serials"]
        ctx.outcome.ok("switch_firmware_version") if fw else ctx.outcome.missing("switch_firmware_version")
    else:
        fw_items = [c["sw"] for c in chassis if c["sw"]]
        fw = fw_items[0] if fw_items else ""
        ctx.outcome.ok("switch_firmware_version") if fw or ctx.prev.get("firmware") else ctx.outcome.missing("switch_firmware_version")
    return {"inventory": items[:2000], "entity_names": names, "identity": {**ident, "firmware": fw}}


async def collect_poe(ctx: Ctx) -> dict:
    o = ctx.outcome
    main = await _cols(ctx, PETH_MAIN, {"power": 2, "oper": 3, "used": 4})
    ports = await _cols(ctx, PETH_PORT, {"admin": 3, "detect": 6, "priority": 7, "class": 10})
    units = []
    for g, r in sorted(main.items()):
        units.append({"unit": g, "budget_w": num(r.get("power")), "used_w": num(r.get("used")),
                      "status": {1: "on", 2: "off", 3: "faulty"}.get(num(r.get("oper")) or 0, "unknown"), "source": "POWER-ETHERNET-MIB"})
    port_rows: dict[str, dict] = {}
    for idx, r in ports.items():
        port_rows[idx] = {"key": idx, "admin": "enabled" if num(r.get("admin")) == 1 else "disabled",
                          "status": PETH_DETECT.get(num(r.get("detect")) or 0, "unknown"),
                          "class": (num(r.get("class")) - 1) if num(r.get("class")) else None,
                          "priority": {1: "critical", 2: "high", 3: "low"}.get(num(r.get("priority")) or 0, ""), "ifindex": None,
                          "power_w": None, "allocated_w": None}
    if ctx.vendor == "cisco":
        try:
            ext = await _cols(ctx, C_POE_EXT, {"allocated": 7, "consumed": 9})
        except SnmpError as e:
            ext = {}
            o.error("switch_poe_port_power_watts", e.message)
        names = {i["name"]: i["ifindex"] for i in (ctx.prev.get("interfaces") or {}).values()}
        for idx, r in ext.items():
            p = port_rows.setdefault(idx, {"key": idx, "admin": "", "status": "unknown", "class": None, "priority": "", "ifindex": None})
            p["power_w"] = num(r.get("consumed")) / 1000 if num(r.get("consumed")) is not None else None
            p["allocated_w"] = num(r.get("allocated")) / 1000 if num(r.get("allocated")) is not None else None
        for p in port_rows.values():
            p["ifindex"] = _cisco_poe_ifindex(p["key"], names)
        (o.ok if ext else o.missing)("switch_poe_port_power_watts", len(ext) or 1, "CISCO-POWER-ETHERNET-EXT-MIB")
    elif ctx.vendor == "ruckus":
        rp = await _cols(ctx, R_POE_PORT, {"control": 2, "wattage": 3, "class": 4, "consumed": 6})
        ru = await _cols(ctx, R_POE_UNIT, {"total": 2, "free": 3})
        g = await ctx.client.get([f"{R_POE_GBL}.1.0", f"{R_POE_GBL}.2.0"])
        for idx, r in rp.items():
            if not idx.isdigit():
                continue
            p = port_rows.setdefault(f"if{idx}", {"key": f"if{idx}", "status": "unknown", "priority": ""})
            p.update(ifindex=int(idx), power_w=num(r.get("consumed")) / 1000 if num(r.get("consumed")) is not None else None,
                     allocated_w=num(r.get("wattage")) / 1000 if num(r.get("wattage")) is not None else None,
                     admin="enabled" if num(r.get("control")) in (3, 4, 5, 6) else "disabled" if num(r.get("control")) == 2 else "",
                     **({"class": num(r.get("class"))} if num(r.get("class")) is not None else {}))
            if p.get("status") == "unknown" and p.get("power_w"):
                p["status"] = "delivering"
        if ru:
            units = [{"unit": u, "budget_w": num(r.get("total")) / 1000 if num(r.get("total")) is not None else None,
                      "used_w": (num(r.get("total")) - num(r.get("free"))) / 1000 if num(r.get("total")) is not None and num(r.get("free")) is not None else None,
                      "status": "on", "source": "FOUNDRY-SN-AGENT-MIB snAgentPoeUnitTable"} for u, r in sorted(ru.items())]
        elif num(g.get(f"{R_POE_GBL}.1.0")) is not None and not units:
            tot, free = num(g.get(f"{R_POE_GBL}.1.0")), num(g.get(f"{R_POE_GBL}.2.0"))
            units = [{"unit": "1", "budget_w": tot / 1000, "used_w": (tot - free) / 1000 if free is not None else None, "status": "on",
                      "source": "FOUNDRY-SN-AGENT-MIB snAgentPoeGbl"}]
        if rp:  # the vendor table is keyed by ifIndex; drop the RFC 3621 rows so ports are not listed twice
            port_rows = {k: v for k, v in port_rows.items() if str(k).startswith("if")}
        (o.ok if rp else o.missing)("switch_poe_port_power_watts", len(rp) or 1)
        (o.ok if (ru or num(g.get(f"{R_POE_GBL}.1.0")) is not None) else o.missing)("switch_poe_unit_budget")
    budget = [u["budget_w"] for u in units if u.get("budget_w") is not None]
    used = [u["used_w"] for u in units if u.get("used_w") is not None]
    (o.ok if budget else o.missing)("switch_poe_budget_watts", len(units) or 1)
    (o.ok if ports or ctx.vendor == "ruckus" and port_rows else o.missing)("switch_poe_port_status", len(port_rows) or 1)
    if not units and not port_rows:
        return {"poe": None}
    return {"poe": {"units": units, "budget_w": sum(budget) if budget else None, "used_w": sum(used) if used else None,
                    "ports": sorted(port_rows.values(), key=lambda p: (p.get("ifindex") or 10 ** 9, str(p["key"])))}}


def _cisco_poe_ifindex(key: str, names: dict[str, int]) -> int | None:
    """RFC 3621 port index (group.port) → interface by name: group = switch / module number, port = last number
    (Gi1/0/12 ↔ 1.12). Only a unique match is used; otherwise the port stays unmapped."""
    try:
        g, p = (int(x) for x in key.split(".")[:2])
    except ValueError:
        return None
    for pattern in (r"[A-Za-z]+(\d+)/0/(\d+)", r"[A-Za-z]+(\d+)/(\d+)"):  # front-panel module 0 first, then 2-part names
        hits = [ix for n, ix in names.items() if (m := re.fullmatch(pattern, n)) and int(m.group(1)) == g and int(m.group(2)) == p]
        if len(hits) == 1:
            return hits[0]
    return None


async def collect_lacp(ctx: Ctx) -> dict:
    o = ctx.outcome
    rows = await _cols(ctx, LAG_PORT, {"selected": 12, "attached": 13, "actor": 21, "partner": 23})
    members: dict[int, dict] = {}
    for idx, r in rows.items():
        if not idx.isdigit():
            continue
        a, p = bits(r.get("actor")), bits(r.get("partner"))
        members[int(idx)] = {"ifindex": int(idx), "selected": num(r.get("selected")), "attached": num(r.get("attached")),
                             "actor": a, "partner": p, "protocol": "lacp",
                             "in_bundle": bool(a["synchronization"] and a["collecting"] and a["distributing"] and num(r.get("attached")))}
    (o.ok if rows else o.missing)("switch_lacp_member_state", len(members) or 1)
    if ctx.vendor == "cisco":
        pg = column(await ctx.client.walk(C_PAGP), C_PAGP)
        for idx, ch in pg.items():
            if idx.isdigit() and num(ch):
                m = members.setdefault(int(idx), {"ifindex": int(idx), "selected": ch, "attached": ch, "actor": {}, "partner": {},
                                                  "protocol": "static/pagp", "in_bundle": None})
                m["channel"] = num(ch)
        (o.ok if pg else o.missing)("switch_channel_membership", len(pg) or 1)
    lags: dict[int, dict] = {}
    for m in members.values():
        agg = m.get("channel") or m.get("attached") or m.get("selected")
        if agg and agg != m["ifindex"]:
            lags.setdefault(int(agg), {"ifindex": int(agg), "members": []})["members"].append(m)
    return {"lacp": {"lags": lags, "members": members} if members else None}


async def _stp_instance(ctx: Ctx, context: str | None) -> dict | None:
    s = await ctx.client.get([f"{STP}.1.0", f"{STP}.2.0", f"{STP}.3.0", f"{STP}.4.0", f"{STP}.5.0", f"{STP}.6.0", f"{STP}.7.0",
                              f"{BRIDGE}.1.1.0", f"{STP}.16.0"], context=context)
    if s.get(f"{STP}.5.0") is MISSING and s.get(f"{STP}.4.0") is MISSING:
        return None
    pm = column(await ctx.client.walk(BASE_PORT_IFINDEX, context=context), BASE_PORT_IFINDEX)
    pr = await _cols(ctx, STP_PORT, {"state": 3, "enable": 4, "dbridge": 8, "fwd": 10}, context=context)
    own_mac = mac(s.get(f"{BRIDGE}.1.1.0"))
    prio = num(s.get(f"{STP}.2.0"))
    root = bridge_id(s.get(f"{STP}.5.0"))
    root_port = num(s.get(f"{STP}.7.0"))
    own = f"{prio}/{own_mac}" if prio is not None else ""
    ports = {}
    for bp, r in pr.items():
        if not bp.isdigit():
            continue
        ifx = num(pm.get(bp))
        state = STP_STATE.get(num(r.get("state")) or 0, "unknown")
        db = bridge_id(r.get("dbridge"))
        if num(r.get("enable")) == 2 or state == "disabled":
            role = "disabled"
        elif root_port and int(bp) == root_port:
            role = "root"
        elif db and own_mac and db.endswith(own_mac):
            role = "designated"
        elif state in ("blocking", "listening", "discarding"):
            role = "alternate/backup"
        else:
            role = "designated" if state == "forwarding" else "unknown"
        ports[ifx or -int(bp)] = {"bridge_port": int(bp), "ifindex": ifx, "state": state, "role": role,
                                  "forward_transitions": num(r.get("fwd"))}
    tsc = num(s.get(f"{STP}.3.0"))
    return {"root": root, "root_cost": num(s.get(f"{STP}.6.0")), "root_port": root_port,
            "root_port_ifindex": num(pm.get(str(root_port))) if root_port else None, "bridge": own,
            "is_root": bool(root and own_mac and root.endswith(own_mac)), "topology_changes": num(s.get(f"{STP}.4.0")),
            "since_topology_change_s": tsc / 100 if tsc is not None else None, "priority": prio,
            "version": {0: "stp", 2: "rstp", 3: "mstp"}.get(num(s.get(f"{STP}.16.0")) if num(s.get(f"{STP}.16.0")) is not None else -1, ""),
            "ports": ports}


async def collect_stp(ctx: Ctx) -> dict:
    o = ctx.outcome
    base = await _stp_instance(ctx, None)
    if base is None:
        o.missing("switch_stp_bridge")
        o.missing("switch_stp_ports")
        o.missing("switch_stp_mode")
        return {"stp": None}
    o.ok("switch_stp_bridge")
    (o.ok if base["ports"] else o.missing)("switch_stp_ports", len(base["ports"]) or 1)
    mode = base["version"]
    instances = {"default": base}
    if ctx.vendor == "cisco":
        t = num((await ctx.client.get([C_STP_TYPE])).get(C_STP_TYPE))
        mode = {1: "pvst+", 2: "mistp", 3: "mistp-pvst+", 4: "mst", 5: "rapid-pvst+"}.get(t or 0, mode)
        (o.ok if t else o.missing)("switch_stp_mode")
        if mode in ("pvst+", "rapid-pvst+"):
            vlans = sorted(int(v) for v in (ctx.prev.get("vlans") or {}) if int(v) not in (1002, 1003, 1004, 1005))[: ctx.max_vlan_contexts]
            done = 0
            for vid in vlans:
                try:
                    inst = await _stp_instance(ctx, ctx.vlan_context(vid))
                except SnmpError as e:
                    o.not_configured("switch_stp_per_vlan", f"per-VLAN SNMP context {ctx.vlan_context(vid)} not readable ({e.kind}): "
                                     "on SNMPv3 add 'context vlan- match prefix' to the SNMP group")
                    break
                if inst:
                    instances[f"vlan{vid}"] = inst
                    done += 1
            if done:
                o.ok("switch_stp_per_vlan", done)
            elif not vlans:
                o.not_configured("switch_stp_per_vlan", "no VLAN list yet (collected by the VLAN group)")
            else:
                o.missing("switch_stp_per_vlan")
    else:
        (o.ok if mode else o.missing)("switch_stp_mode")
    tc = [i["topology_changes"] for i in instances.values() if i.get("topology_changes") is not None]
    return {"stp": {"mode": mode, "instances": instances, "topology_changes": sum(tc) if tc else None,
                    "root": base["root"], "is_root": base["is_root"], "root_port_ifindex": base["root_port_ifindex"]}}


async def collect_vlans(ctx: Ctx) -> dict:
    o = ctx.outcome
    vlans: dict[int, dict] = {}
    port_vlans: dict[int, dict] = {}
    if ctx.vendor == "cisco":
        rows = await _cols(ctx, C_VTP_VLAN, {"state": 2, "type": 3, "name": 4})
        for idx, r in rows.items():
            vid = int(idx.split(".")[-1])
            if num(r.get("type")) not in (None, 1) or vid in (1002, 1003, 1004, 1005):
                continue
            vlans[vid] = {"vlan_id": vid, "name": text(r.get("name")), "state": {1: "active", 2: "suspended", 3: "mtu_too_big", 4: "mtu_too_big"}.get(num(r.get("state")) or 0, "unknown"),
                          "tagged": [], "untagged": []}
        (o.ok if vlans else o.missing)("switch_vlan_info", len(vlans) or 1, "CISCO-VTP-MIB")
        access = column(await ctx.client.walk(C_VMVLAN), C_VMVLAN)
        trunk = await _cols(ctx, C_TRUNK, {"enabled": 4, "native": 5, "dyn": 14, "e2k": 17, "e3k": 18, "e4k": 19})
        for ifx, vid in access.items():
            if ifx.isdigit() and num(vid):
                port_vlans[int(ifx)] = {"mode": "access", "access_vlan": num(vid)}
                if num(vid) in vlans:
                    vlans[num(vid)]["untagged"].append(int(ifx))
        for ifx, r in trunk.items():
            if not ifx.isdigit() or num(r.get("dyn")) != 1:
                continue
            allowed = set()
            for k, off in (("enabled", 0), ("e2k", 1024), ("e3k", 2048), ("e4k", 3072)):
                allowed |= {p - 1 + off for p in portlist(r.get(k))}
            native = num(r.get("native"))
            port_vlans[int(ifx)] = {"mode": "trunk", "native_vlan": native, "allowed": len(allowed)}
            for vid, v in vlans.items():
                if vid == native:
                    v["untagged"].append(int(ifx))
                elif vid in allowed:
                    v["tagged"].append(int(ifx))
        (o.ok if (access or trunk) else o.missing)("switch_vlan_membership", len(port_vlans) or 1, "CISCO-VLAN-MEMBERSHIP-MIB / CISCO-VTP-MIB")
    else:
        bp = column(await ctx.client.walk(BASE_PORT_IFINDEX), BASE_PORT_IFINDEX)
        rows = await _cols(ctx, QVLAN_STATIC, {"name": 1, "egress": 2, "untagged": 4})
        source = "Q-BRIDGE-MIB dot1qVlanStaticTable"
        if not rows:
            cur = await _cols(ctx, QVLAN_CURRENT, {"egress": 4, "untagged": 5})
            rows = {idx.split(".")[-1]: r for idx, r in cur.items()}
            source = "Q-BRIDGE-MIB dot1qVlanCurrentTable"
        for vid_s, r in rows.items():
            if not vid_s.isdigit():
                continue
            egress = {num(bp.get(str(p))) or p for p in portlist(r.get("egress"))}
            untag = {num(bp.get(str(p))) or p for p in portlist(r.get("untagged"))}
            vlans[int(vid_s)] = {"vlan_id": int(vid_s), "name": text(r.get("name")), "state": "active",
                                 "tagged": sorted(egress - untag), "untagged": sorted(untag)}
        (o.ok if vlans else o.missing)("switch_vlan_info", len(vlans) or 1, source)
        pvid = column(await ctx.client.walk(QPVID), QPVID)
        for p, vid in pvid.items():
            ifx = num(bp.get(p)) or (int(p) if p.isdigit() else None)
            if ifx is None or not num(vid):
                continue
            tagged_in = [v for v, d in vlans.items() if ifx in d["tagged"]]
            port_vlans[ifx] = {"mode": "trunk" if tagged_in else "access", "access_vlan": None if tagged_in else num(vid),
                               "native_vlan": num(vid) if tagged_in else None, "allowed": len(tagged_in) + 1 if tagged_in else None}
        (o.ok if (vlans and any(d["tagged"] or d["untagged"] for d in vlans.values())) or pvid else o.missing)("switch_vlan_membership",
                                                                                                             len(port_vlans) or 1)
    return {"vlans": vlans, "port_vlans": port_vlans}


async def _fdb_bridge(ctx: Ctx, context: str | None, vlan: int, limit: int) -> list[dict]:
    pm = column(await ctx.client.walk(BASE_PORT_IFINDEX, context=context), BASE_PORT_IFINDEX)
    rows = await _cols(ctx, DFDB, {"port": 2, "status": 3}, context=context, max_rows=limit)
    out = []
    for idx, r in rows.items():
        parts = idx.split(".")
        if len(parts) != 6 or num(r.get("status")) == 4:
            continue
        out.append({"mac": ":".join(f"{int(x):02x}" for x in parts), "vlan": vlan, "ifindex": num(pm.get(str(num(r.get("port"))))),
                    "bridge_port": num(r.get("port")), "status": {3: "dynamic", 5: "static", 1: "other"}.get(num(r.get("status")) or 0, "unknown")})
    return out


async def collect_mac_table(ctx: Ctx) -> dict:
    o = ctx.outcome
    macs: list[dict] = []
    if ctx.vendor == "cisco":
        vlans = sorted(int(v) for v in (ctx.prev.get("vlans") or {}) if int(v) not in (1002, 1003, 1004, 1005))[: ctx.max_vlan_contexts]
        if not vlans:
            o.not_configured("switch_mac_table", "no VLAN list yet (collected by the VLAN group)")
            return {"macs": None}
        for vid in vlans:
            try:
                macs += await _fdb_bridge(ctx, ctx.vlan_context(vid), vid, ctx.max_macs - len(macs))
            except SnmpError as e:
                if not macs:
                    o.not_configured("switch_mac_table", f"per-VLAN SNMP context {ctx.vlan_context(vid)} not readable ({e.kind}): "
                                     "on SNMPv3 add 'context vlan- match prefix' to the SNMP group")
                    return {"macs": None}
                o.error("switch_mac_table", f"VLAN {vid}: {e.message}")
                break
            if len(macs) >= ctx.max_macs:
                break
        (o.ok if macs else o.missing)("switch_mac_table", len(macs) or 1, "BRIDGE-MIB per VLAN context")
        return {"macs": macs, "mac_truncated": len(macs) >= ctx.max_macs}
    pm = column(await ctx.client.walk(BASE_PORT_IFINDEX), BASE_PORT_IFINDEX)
    rows = await _cols(ctx, QFDB, {"port": 2, "status": 3}, max_rows=ctx.max_macs)
    fdb_vlan: dict[int, int] = {}
    if rows:
        cur = column(await ctx.client.walk(f"{QVLAN_CURRENT}.3"), f"{QVLAN_CURRENT}.3")
        for idx, fid in cur.items():
            if num(fid) is not None:
                fdb_vlan[num(fid)] = int(idx.split(".")[-1])
    for idx, r in rows.items():
        parts = idx.split(".")
        if len(parts) != 7 or num(r.get("status")) == 4:
            continue
        fid = int(parts[0])
        macs.append({"mac": ":".join(f"{int(x):02x}" for x in parts[1:]), "vlan": fdb_vlan.get(fid, fid),
                     "ifindex": num(pm.get(str(num(r.get("port"))))) or num(r.get("port")), "bridge_port": num(r.get("port")),
                     "status": {3: "dynamic", 5: "static", 1: "other"}.get(num(r.get("status")) or 0, "unknown")})
    source = "Q-BRIDGE-MIB dot1qTpFdbTable"
    if not rows:
        macs = await _fdb_bridge(ctx, None, 0, ctx.max_macs)
        source = "BRIDGE-MIB dot1dTpFdbTable (VLAN not reported)"
    (o.ok if macs else o.missing)("switch_mac_table", len(macs) or 1, source)
    return {"macs": macs if macs else None, "mac_truncated": len(macs) >= ctx.max_macs}


async def collect_routing(ctx: Ctx) -> dict:
    o = ctx.outcome
    ips = await _cols(ctx, IPADDR, {"ifindex": 2, "mask": 3})
    addrs = [{"ip": ip, "ifindex": num(r.get("ifindex")), "mask": r.get("mask") if isinstance(r.get("mask"), str) else ""}
             for ip, r in ips.items() if not ip.startswith("127.")]
    (o.ok if addrs else o.missing)("switch_ip_interfaces", len(addrs) or 1)
    rc = await ctx.client.get(["1.3.6.1.2.1.4.24.6.0", "1.3.6.1.2.1.4.24.3.0"])
    routes = num(rc.get("1.3.6.1.2.1.4.24.6.0"))
    if routes is None:
        routes = num(rc.get("1.3.6.1.2.1.4.24.3.0"))
    (o.ok if routes is not None else o.missing)("switch_route_count")
    on = await _cols(ctx, OSPF_NBR, {"rtr": 3, "state": 6, "events": 7})
    ospf = [{"neighbor": ".".join(idx.split(".")[:4]), "router_id": r.get("rtr") if isinstance(r.get("rtr"), str) else "",
             "state": {1: "down", 2: "attempt", 3: "init", 4: "two-way", 5: "exchange-start", 6: "exchange", 7: "loading", 8: "full"}.get(num(r.get("state")) or 0, "unknown"),
             "events": num(r.get("events"))} for idx, r in on.items()]
    (o.ok if ospf else o.missing)("switch_ospf_neighbors", len(ospf) or 1)
    bp = await _cols(ctx, BGP_PEER, {"state": 2, "remote_as": 9, "established": 16})
    bgp = [{"peer": idx, "remote_as": num(r.get("remote_as")),
            "state": {1: "idle", 2: "connect", 3: "active", 4: "opensent", 5: "openconfirm", 6: "established"}.get(num(r.get("state")) or 0, "unknown"),
            "established_s": num(r.get("established"))} for idx, r in bp.items()]
    (o.ok if bgp else o.missing)("switch_bgp_peers", len(bgp) or 1)
    return {"routing": {"ip_interfaces": addrs[:500], "route_count": routes, "ospf": ospf, "bgp": bgp}}


LLDP_CAPS = ("other", "repeater", "bridge", "wlan_ap", "router", "telephone", "docsis", "station")
CDP_CAPS = ((0x01, "router"), (0x02, "bridge"), (0x04, "bridge"), (0x08, "bridge"), (0x10, "station"), (0x40, "repeater"), (0x80, "telephone"),
            (0x200, "wlan_ap"))
_ABBR = (("hundredgige", "hu"), ("fortygigabitethernet", "fo"), ("twentyfivegige", "twe"), ("tengigabitethernet", "te"), ("gigabitethernet", "gi"),
         ("fastethernet", "fa"), ("port-channel", "po"), ("ethernet", "eth"), ("vlan", "vl"))


def port_key(name: str) -> str:
    """Normalise interface names so LLDP / CDP port ids match local names: 'GigabitEthernet1/0/1' == 'Gi1/0/1'."""
    n = re.sub(r"\s+", "", (name or "").lower())
    for long, short in _ABBR:
        if n.startswith(long):
            return short + n[len(long):]
    m = re.match(r"([a-z]+)(\d.*)", n)
    if m and len(m.group(1)) > 2:
        for long, short in _ABBR:
            if long.startswith(m.group(1)):
                return short + m.group(2)
    return n


def _chassis(subtype, v) -> str:
    if subtype == 4 and isinstance(v, bytes) and len(v) == 6:
        return mac(v)
    if subtype == 5 and isinstance(v, bytes) and len(v) >= 5 and v[0] == 1:  # networkAddress: IANA family 1 = IPv4
        return ".".join(str(b) for b in v[1:5])
    t = text(v)
    return t if t.isprintable() else (v.hex() if isinstance(v, bytes) else t)


async def collect_neighbors(ctx: Ctx) -> dict:
    """LLDP-MIB (IEEE 802.1AB) neighbors on every vendor, plus CISCO-CDP-MIB on Cisco. Local ports are mapped to
    ifIndex through lldpLocPortTable (port id = interface name or MAC), falling back to lldpRemLocalPortNum = ifIndex."""
    o = ctx.outcome
    ifs = ctx.prev.get("interfaces") or {}
    by_name = {port_key(i.get("name", "")): ix for ix, i in ifs.items() if i.get("name")}
    by_name.update({port_key(i.get("descr", "")): ix for ix, i in ifs.items() if i.get("descr") and port_key(i.get("descr", "")) not in by_name})
    by_mac = {i.get("mac"): ix for ix, i in ifs.items() if i.get("mac")}
    loc = await _cols(ctx, LLDP_LOC_PORT, {"subtype": 2, "id": 3, "desc": 4})
    local_map: dict[int, int] = {}
    for pn, r in loc.items():
        if not pn.isdigit():
            continue
        sub, pid = num(r.get("subtype")), r.get("id")
        ix = None
        if sub == 3 and isinstance(pid, bytes) and len(pid) == 6:
            ix = by_mac.get(mac(pid))
        if ix is None:
            ix = by_name.get(port_key(text(pid))) or by_name.get(port_key(text(r.get("desc"))))
        if ix is not None:
            local_map[int(pn)] = ix
    rem = await _cols(ctx, LLDP_REM, {"chassis_sub": 4, "chassis": 5, "port_sub": 6, "port": 7, "port_desc": 8, "sys_name": 9, "sys_desc": 10, "caps": 12})
    man = column(await ctx.client.walk(f"{LLDP_REM_MAN}.3"), f"{LLDP_REM_MAN}.3")
    mgmt: dict[tuple, str] = {}
    for idx in man:
        p = idx.split(".")
        if len(p) >= 9 and p[3] == "1" and p[4] == "4":  # IPv4 management address carried in the index
            mgmt.setdefault((p[1], p[2]), ".".join(p[5:9]))
    out: dict[tuple, dict] = {}
    for idx, r in rem.items():
        p = idx.split(".")
        if len(p) != 3:
            continue
        lp = int(p[1])
        ix = local_map.get(lp) or (lp if lp in ifs else None)
        port_sub = num(r.get("port_sub"))
        port_id = mac(r.get("port")) if port_sub == 3 else text(r.get("port"))
        caps = [n for n, on in bits(r.get("caps"), LLDP_CAPS).items() if on] if isinstance(r.get("caps"), bytes) else []
        nb = {"protocol": "lldp", "local_ifindex": ix, "local_port": (ifs.get(ix) or {}).get("name") or f"LLDP port {lp}",
              "chassis_id": _chassis(num(r.get("chassis_sub")), r.get("chassis")), "sys_name": text(r.get("sys_name")),
              "port_id": port_id, "port_desc": text(r.get("port_desc")), "sys_desc": text(r.get("sys_desc"))[:300], "caps": caps,
              "mgmt_ip": mgmt.get((p[1], p[2]), "")}
        out[(ix or -lp, (nb["sys_name"] or nb["chassis_id"]).lower())] = nb
    (o.ok if rem else o.missing)("switch_lldp_neighbors", len(rem) or 1)
    if ctx.vendor == "cisco":
        try:
            cdp = await _cols(ctx, C_CDP, {"addr_type": 3, "addr": 4, "device": 6, "port": 7, "platform": 8, "caps": 9})
        except SnmpError as e:
            cdp = {}
            o.error("switch_cdp_neighbors", e.message)
        for idx, r in cdp.items():
            p = idx.split(".")
            if len(p) != 2 or not p[0].isdigit():
                continue
            ix = int(p[0])
            a = r.get("addr")
            ip = ".".join(str(b) for b in a) if num(r.get("addr_type")) == 1 and isinstance(a, bytes) and len(a) == 4 else ""
            cv = int.from_bytes(r["caps"], "big") if isinstance(r.get("caps"), bytes) and r["caps"] else 0
            name = text(r.get("device"))
            short = name.split(".")[0].split("(")[0].lower()
            nb = {"protocol": "cdp", "local_ifindex": ix if ix in ifs else None, "local_port": (ifs.get(ix) or {}).get("name") or f"ifIndex {ix}",
                  "chassis_id": "", "sys_name": name, "port_id": text(r.get("port")), "port_desc": "", "sys_desc": text(r.get("platform"))[:300],
                  "caps": sorted({n for b, n in CDP_CAPS if cv & b}), "mgmt_ip": ip}
            dup = next((k for k, v in out.items() if k[0] == (nb["local_ifindex"] or -ix)
                        and (v["sys_name"] or "").split(".")[0].lower() == short), None)
            if dup:  # same neighbor seen by LLDP: fill gaps only
                for k in ("mgmt_ip", "sys_desc", "port_id"):
                    out[dup][k] = out[dup][k] or nb[k]
                out[dup]["protocol"] = "lldp+cdp"
            else:
                out[(nb["local_ifindex"] or -ix, name.lower())] = nb
        (o.ok if cdp else o.missing)("switch_cdp_neighbors", len(cdp) or 1)
    sysname = text((await ctx.client.get([LLDP_LOC_SYSNAME])).get(LLDP_LOC_SYSNAME))
    return {"neighbors": list(out.values()), "lldp_sys_name": sysname}


# ------------------------------------------------------------------ standard host / sensor MIBs
def _storage_type(v) -> str:
    o = v if isinstance(v, str) else ""
    return STORAGE_KINDS.get(o[len(HR_TYPE) + 1:], "other") if o.startswith(HR_TYPE + ".") else "other"


async def _hr_storage(ctx: Ctx) -> list[dict]:
    rows = await _cols(ctx, HR_STORAGE, {"type": 2, "descr": 3, "units": 4, "size": 5, "used": 6})
    out = []
    for idx, r in sorted(rows.items(), key=lambda kv: int(kv[0]) if kv[0].isdigit() else 0):
        units, size, used = num(r.get("units")), num(r.get("size")), num(r.get("used"))
        if not units or size is None or used is None:
            continue
        size, used = size % 2 ** 32, used % 2 ** 32  # Integer32 wraps negative on agents with large volumes
        if size <= 0:
            continue
        out.append({"index": idx, "name": text(r.get("descr")) or f"storage {idx}", "kind": _storage_type(r.get("type")),
                    "size_bytes": size * units, "used_bytes": used * units, "pct": round(100.0 * used / size, 2)})
    return out


async def std_cpu_memory(ctx: Ctx) -> dict:
    """CPU from hrProcessorLoad (average over processors, as LibreNMS does) or 100 - ssCpuIdle; memory from UCD-SNMP
    (available = avail + buffers + cached) or the hrStorage RAM entry; load average from UCD laLoad."""
    o = ctx.outcome
    names = ctx.prev.get("entity_names") or {}
    procs = await _cols(ctx, HR_PROC, {"device": 1, "load": 2})
    cpus = [{"id": idx, "name": names.get(int(idx)) if idx.isdigit() and names.get(int(idx)) else f"CPU {idx}", "pct_1m": num(r.get("load")),
             "pct_5s": None, "pct_5m": None} for idx, r in sorted(procs.items()) if num(r.get("load")) is not None]
    src = "HOST-RESOURCES-MIB hrProcessorLoad"
    pct = round(sum(c["pct_1m"] for c in cpus) / len(cpus), 1) if cpus else None
    g = await ctx.client.get([UCD_CPU_IDLE, f"{UCD_MEM}.5.0", f"{UCD_MEM}.6.0", f"{UCD_MEM}.14.0", f"{UCD_MEM}.15.0",
                              f"{UCD_LOAD}.1", f"{UCD_LOAD}.2", f"{UCD_LOAD}.3"])
    if pct is None and num(g.get(UCD_CPU_IDLE)) is not None:
        pct = float(100 - num(g.get(UCD_CPU_IDLE)))
        cpus = [{"id": "all", "name": "CPU (all cores)", "pct_1m": pct, "pct_5s": None, "pct_5m": None}]
        src = "UCD-SNMP-MIB ssCpuIdle"
    (o.ok if cpus else o.missing)("switch_cpu_utilization_percent", len(cpus) or 1, src)
    load = {}
    for i, k in ((1, "1m"), (2, "5m"), (3, "15m")):
        try:
            load[k] = float(text(g.get(f"{UCD_LOAD}.{i}")))
        except ValueError:
            pass
    (o.ok if load else o.missing)("switch_load_average", 1, "UCD-SNMP-MIB laLoad")
    mem = None
    total, avail = num(g.get(f"{UCD_MEM}.5.0")), num(g.get(f"{UCD_MEM}.6.0"))
    if total and avail is not None:
        free = avail + (num(g.get(f"{UCD_MEM}.14.0")) or 0) + (num(g.get(f"{UCD_MEM}.15.0")) or 0)
        free = min(free, total)
        mem = {"total_bytes": total * 1024, "free_bytes": free * 1024, "used_bytes": (total - free) * 1024,
               "pct": round(100.0 * (total - free) / total, 2), "source": "UCD-SNMP-MIB memTotalReal / memAvailReal + buffers + cached"}
    else:
        ram = [x for x in await _hr_storage(ctx) if x["kind"] == "ram"]
        if ram:
            r = ram[0]
            mem = {"total_bytes": r["size_bytes"], "used_bytes": r["used_bytes"], "free_bytes": r["size_bytes"] - r["used_bytes"],
                   "pct": r["pct"], "source": "HOST-RESOURCES-MIB hrStorageRam"}
    (o.ok if mem else o.missing)("switch_memory_utilization_percent", 1, mem["source"] if mem else "")
    return {"cpu": {"pct": pct, "cpus": cpus, "load": load or None, "source": src} if cpus else ({"pct": None, "cpus": [], "load": load} if load else None),
            "memory": mem}


async def std_sensors(ctx: Ctx) -> dict:
    """ENTITY-SENSOR-MIB (RFC 3433): temperatures go to the shared temperature list, every other sensor (voltage,
    current, power, fan speed, humidity) to `sensors`. Values are scaled by entPhySensorScale and Precision."""
    o = ctx.outcome
    names = ctx.prev.get("entity_names") or {}
    rows = await _cols(ctx, ENT_SENSOR, {"type": 1, "scale": 2, "precision": 3, "value": 4, "status": 5})
    temps, sensors = [], []
    for idx, r in sorted(rows.items(), key=lambda kv: int(kv[0]) if kv[0].isdigit() else 0):
        kind = SENSOR_KINDS.get(num(r.get("type")) or 0)
        v = num(r.get("value"))
        if not kind or v is None:
            continue
        scale = 10 ** (3 * ((num(r.get("scale")) or 9) - 9))
        val = round(v * scale / (10 ** (num(r.get("precision")) or 0)), 3)
        state = {1: "ok", 2: "unavailable", 3: "failed"}.get(num(r.get("status")) or 0, "unknown")
        name = (names.get(int(idx)) if idx.isdigit() else "") or f"sensor {idx}"
        if kind[0] == "temperature":
            temps.append({"name": name, "celsius": round(val, 1), "threshold": None, "state": state})
        else:
            sensors.append({"name": name, "kind": kind[0], "unit": kind[1], "value": val, "state": state})
    (o.ok if temps else o.missing)("switch_temperature_celsius", len(temps) or 1, "ENTITY-SENSOR-MIB entPhySensorTable")
    (o.ok if sensors else o.missing)("switch_sensor_value", len(sensors) or 1, "ENTITY-SENSOR-MIB entPhySensorTable")
    return {"temperatures": temps, "sensors": sensors}


async def collect_storage(ctx: Ctx) -> dict:
    """Disks, flash and file systems (hrStorageTable). RAM and virtual memory belong to cpu_memory, not here."""
    vols = [x for x in await _hr_storage(ctx) if x["kind"] in ("disk", "flash", "network_disk", "removable")]
    (ctx.outcome.ok if vols else ctx.outcome.missing)("switch_storage_used_percent", len(vols) or 1)
    return {"storage": vols}


def _empty_env(env: dict | None) -> bool:
    return not env or not (env.get("temperatures") or env.get("fans") or env.get("psus"))


# ------------------------------------------------------------------ vendor adapters
class CiscoAdapter:
    vendor = "cisco"

    async def cpu_memory(self, ctx: Ctx) -> dict:
        o = ctx.outcome
        rows = await _cols(ctx, C_CPU, {"phys": 2, "p5s": 6, "p1m": 7, "p5m": 8, "mem_used_kb": 12, "mem_free_kb": 13,
                                        "hc_used_kb": 17, "hc_free_kb": 19})
        names = ctx.prev.get("entity_names") or {}
        cpus = []
        used = free = None
        for idx, r in sorted(rows.items()):
            if num(r.get("p1m")) is None and num(r.get("p5m")) is None:
                continue
            ph = num(r.get("phys"))
            cpus.append({"id": idx, "name": names.get(ph) or (f"CPU {idx}" if not ph else f"entity {ph}"),
                         "pct_5s": num(r.get("p5s")), "pct_1m": num(r.get("p1m")), "pct_5m": num(r.get("p5m"))})
            u = num(r.get("hc_used_kb")) if num(r.get("hc_used_kb")) else num(r.get("mem_used_kb"))
            f = num(r.get("hc_free_kb")) if num(r.get("hc_free_kb")) is not None and num(r.get("hc_used_kb")) else num(r.get("mem_free_kb"))
            if u and f is not None:
                used, free = (used or 0) + u * 1024, (free or 0) + f * 1024
        mem_src = "CISCO-PROCESS-MIB cpmCPUMemory"
        if used is None:
            ep = await _cols(ctx, C_EMEMPOOL, {"name": 3, "used": 7, "free": 8, "hc_used": 18, "hc_free": 20})
            for r in ep.values():
                if text(r.get("name")).lower().startswith("processor"):
                    u = num(r.get("hc_used")) if num(r.get("hc_used")) else num(r.get("used"))
                    f = num(r.get("hc_free")) if num(r.get("hc_used")) else num(r.get("free"))
                    if u is not None and f is not None:
                        used, free = (used or 0) + u, (free or 0) + f
            mem_src = "CISCO-ENHANCED-MEMPOOL-MIB"
        if used is None:
            mp = await _cols(ctx, C_MEMPOOL, {"name": 2, "used": 5, "free": 6})
            for r in mp.values():
                if text(r.get("name")).lower().startswith("processor") and num(r.get("used")) is not None:
                    used, free = num(r.get("used")), num(r.get("free"))
            mem_src = "CISCO-MEMORY-POOL-MIB"
        cpu_pct = max((c["pct_1m"] if c["pct_1m"] is not None else c["pct_5m"]) for c in cpus) if cpus else None
        (o.ok if cpus else o.missing)("switch_cpu_utilization_percent", len(cpus) or 1, "CISCO-PROCESS-MIB cpmCPUTotal1minRev")
        mem = None
        if used is not None and free is not None and used + free > 0:
            mem = {"used_bytes": used, "free_bytes": free, "total_bytes": used + free, "pct": round(100.0 * used / (used + free), 2), "source": mem_src}
            o.ok("switch_memory_utilization_percent", 1, mem_src)
        else:
            o.missing("switch_memory_utilization_percent")
        return {"cpu": {"pct": cpu_pct, "cpus": cpus} if cpus else None, "memory": mem}

    async def environment(self, ctx: Ctx) -> dict:
        o = ctx.outcome
        temps, fans, psus = [], [], []
        t = await _cols(ctx, f"{C_ENV}.3.1", {"descr": 2, "value": 3, "threshold": 4, "state": 6})
        for idx, r in sorted(t.items()):
            temps.append({"name": text(r.get("descr")) or f"sensor {idx}", "celsius": num(r.get("value")), "threshold": num(r.get("threshold")),
                          "state": ENV_STATE.get(num(r.get("state")) or 0, "unknown")})
        src = "CISCO-ENVMON-MIB"
        if not temps:
            s = await _cols(ctx, C_SENSOR, {"type": 1, "scale": 2, "precision": 3, "value": 4, "status": 5})
            names = ctx.prev.get("entity_names") or {}
            for idx, r in sorted(s.items()):
                if num(r.get("type")) != 8 or num(r.get("value")) is None:
                    continue
                scale = {8: 1e-3, 9: 1, 10: 1e3}.get(num(r.get("scale")) or 9, 1)
                prec = num(r.get("precision")) or 0
                v = num(r.get("value")) * scale / (10 ** prec)
                temps.append({"name": (names.get(int(idx)) if idx.isdigit() else "") or f"sensor {idx}", "celsius": round(v, 1), "threshold": None,
                              "state": {1: "ok", 2: "unavailable", 3: "failed"}.get(num(r.get("status")) or 0, "unknown")})
            src = "CISCO-ENTITY-SENSOR-MIB"
        f = await _cols(ctx, f"{C_ENV}.4.1", {"descr": 2, "state": 3})
        fans = [{"name": text(r.get("descr")) or f"fan {i}", "state": ENV_STATE.get(num(r.get("state")) or 0, "unknown")} for i, r in sorted(f.items())]
        p = await _cols(ctx, f"{C_ENV}.5.1", {"descr": 2, "state": 3})
        psus = [{"name": text(r.get("descr")) or f"PSU {i}", "state": ENV_STATE.get(num(r.get("state")) or 0, "unknown")} for i, r in sorted(p.items())]
        (o.ok if temps else o.missing)("switch_temperature_celsius", len(temps) or 1, src)
        (o.ok if fans else o.missing)("switch_fan_status", len(fans) or 1)
        (o.ok if psus else o.missing)("switch_psu_status", len(psus) or 1)
        return {"environment": {"temperatures": temps, "fans": fans, "psus": psus}}

    async def stack(self, ctx: Ctx) -> dict:
        o = ctx.outcome
        rows = await _cols(ctx, C_STACK, {"num": 1, "role": 3, "priority": 4, "state": 6, "mac": 7})
        if not rows:
            o.missing("switch_stack_members")
            o.missing("switch_stack_ring")
            return {"stack": None}
        st = {1: "waiting", 2: "progressing", 3: "added", 4: "ready", 5: "sdm_mismatch", 6: "version_mismatch", 7: "feature_mismatch",
              8: "new_master_init", 9: "provisioned", 10: "invalid", 11: "removed"}
        members = []
        for idx, r in sorted(rows.items(), key=lambda kv: num(kv[1].get("num")) or 0):
            state = st.get(num(r.get("state")) or 0, "unknown")
            members.append({"unit": num(r.get("num")), "role": {1: "active", 2: "member", 3: "not_member", 4: "standby"}.get(num(r.get("role")) or 0, "unknown"),
                            "state": state, "healthy": state == "ready", "priority": num(r.get("priority")), "mac": mac(r.get("mac")),
                            "entity": int(idx) if idx.isdigit() else idx})
        ring = (await ctx.client.get([C_RING])).get(C_RING)
        ports = column(await ctx.client.walk(C_STACKPORT), C_STACKPORT)
        port_states = [{1: "up", 2: "down", 3: "forced_down"}.get(num(v) or 0, "unknown") for v in ports.values()]
        o.ok("switch_stack_members", len(members))
        (o.ok if num(ring) is not None or ports else o.missing)("switch_stack_ring")
        return {"stack": {"members": members, "topology": "ring" if num(ring) == 1 else "chain" if num(ring) == 2 else "",
                          "ring_redundant": True if num(ring) == 1 else False if num(ring) == 2 else None,
                          "stack_ports_down": sum(1 for s in port_states if s != "up") if port_states else None}}


class RuckusAdapter:
    vendor = "ruckus"

    async def cpu_memory(self, ctx: Ctx) -> dict:
        o = ctx.outcome
        rows = await _cols(ctx, R_CPU, {"pct": 5, "pct100": 6})
        cpus = []
        for idx, r in sorted(rows.items()):
            parts = idx.split(".")
            if len(parts) != 3 or parts[2] != "60":  # index slot.cpu.interval; keep the 1-minute average
                continue
            pct = num(r.get("pct"))
            if pct is None and num(r.get("pct100")) is not None:
                pct = num(r.get("pct100")) / 100
            if pct is not None:
                cpus.append({"id": f"{parts[0]}.{parts[1]}", "name": f"slot {parts[0]} CPU {parts[1]}", "pct_1m": pct, "pct_5s": None, "pct_5m": None})
        g = await ctx.client.get([f"{R_GBL}.52.0", f"{R_GBL}.53.0", f"{R_GBL}.54.0", f"{R_GBL}.55.0"])
        src = "FOUNDRY-SN-AGENT-MIB snAgentCpuUtilPercent"
        if not cpus and num(g.get(f"{R_GBL}.52.0")) is not None:
            cpus = [{"id": "global", "name": "CPU (1-min average)", "pct_1m": num(g.get(f"{R_GBL}.52.0")), "pct_5s": None, "pct_5m": None}]
            src = "FOUNDRY-SN-AGENT-MIB snAgGblCpuUtil1MinAvg"
        (o.ok if cpus else o.missing)("switch_cpu_utilization_percent", len(cpus) or 1, src)
        util, total, free = num(g.get(f"{R_GBL}.53.0")), num(g.get(f"{R_GBL}.54.0")), num(g.get(f"{R_GBL}.55.0"))
        mem = None
        if util is not None or (total and free is not None):
            pct = float(util) if util is not None else round(100.0 * (total - free) / total, 2)
            mem = {"pct": pct, "total_bytes": total, "free_bytes": free, "used_bytes": (total - free) if total and free is not None else None,
                   "source": "FOUNDRY-SN-AGENT-MIB snAgGblDynMem"}
            o.ok("switch_memory_utilization_percent")
        else:
            o.missing("switch_memory_utilization_percent")
        return {"cpu": {"pct": max(c["pct_1m"] for c in cpus), "cpus": cpus} if cpus else None, "memory": mem}

    async def environment(self, ctx: Ctx) -> dict:
        o = ctx.outcome
        temps = []
        t2 = await _cols(ctx, R_TEMP2, {"descr": 4, "value": 5})
        for idx, r in sorted(t2.items()):
            if num(r.get("value")) is not None:
                unit = idx.split(".")[0]
                temps.append({"name": f"unit {unit}: {text(r.get('descr')) or 'sensor ' + idx}", "celsius": num(r.get("value")) / 2, "threshold": None, "state": "ok"})
        src = "FOUNDRY-SN-AGENT-MIB snAgentTemp2Table"
        if not temps:
            t1 = await _cols(ctx, R_TEMP, {"descr": 3, "value": 4})
            temps = [{"name": text(r.get("descr")) or f"sensor {i}", "celsius": num(r.get("value")) / 2, "threshold": None, "state": "ok"}
                     for i, r in sorted(t1.items()) if num(r.get("value")) is not None]
            src = "FOUNDRY-SN-AGENT-MIB snAgentTempTable"
        g = await ctx.client.get([f"{R_CHAS}.18.0", f"{R_CHAS}.19.0", f"{R_CHAS}.20.0"])
        warn = num(g.get(f"{R_CHAS}.19.0"))
        if not temps and num(g.get(f"{R_CHAS}.18.0")) is not None:
            temps = [{"name": "chassis", "celsius": num(g.get(f"{R_CHAS}.18.0")) / 2, "threshold": warn / 2 if warn else None, "state": "ok"}]
            src = "FOUNDRY-SN-AGENT-MIB snChasActualTemperature"
        for x in temps:
            if x["threshold"] is None and warn:
                x["threshold"] = warn / 2
            if x["threshold"] and x["celsius"] is not None and x["celsius"] >= x["threshold"]:
                x["state"] = "warning"
        fans = [{"name": f"unit {i.split('.')[0]}: {text(r.get('descr')) or 'fan ' + i}", "state": R_STATE.get(num(r.get("state")) or 0, "unknown")}
                for i, r in sorted((await _cols(ctx, R_FAN2, {"descr": 3, "state": 4})).items())]
        if not fans:
            fans = [{"name": text(r.get("descr")) or f"fan {i}", "state": R_STATE.get(num(r.get("state")) or 0, "unknown")}
                    for i, r in sorted((await _cols(ctx, R_FAN, {"descr": 2, "state": 3})).items())]
        psus = [{"name": f"unit {i.split('.')[0]}: {text(r.get('descr')) or 'PSU ' + i}", "state": R_STATE.get(num(r.get("state")) or 0, "unknown")}
                for i, r in sorted((await _cols(ctx, R_PSU2, {"descr": 3, "state": 4})).items())]
        if not psus:
            psus = [{"name": text(r.get("descr")) or f"PSU {i}", "state": R_STATE.get(num(r.get("state")) or 0, "unknown")}
                    for i, r in sorted((await _cols(ctx, R_PSU, {"descr": 2, "state": 3})).items())]
        (o.ok if temps else o.missing)("switch_temperature_celsius", len(temps) or 1, src)
        (o.ok if fans else o.missing)("switch_fan_status", len(fans) or 1)
        (o.ok if psus else o.missing)("switch_psu_status", len(psus) or 1)
        return {"environment": {"temperatures": temps, "fans": fans, "psus": psus}}

    async def stack(self, ctx: Ctx) -> dict:
        o = ctx.outcome
        rows = await _cols(ctx, R_STACK, {"role": 2, "mac": 3, "priority": 4, "state": 5, "descr": 6, "p1": 8, "p2": 10, "img": 14})
        if not rows:
            o.missing("switch_stack_members")
            return {"stack": None}
        ps = {1: "unknown", 2: "up", 3: "down"}
        members = []
        for idx, r in sorted(rows.items(), key=lambda kv: int(kv[0]) if kv[0].isdigit() else 0):
            state = {1: "local", 2: "remote", 3: "reserved", 4: "empty"}.get(num(r.get("state")) or 0, "unknown")
            role = {1: "unknown", 2: "active", 3: "standby", 4: "member", 5: "standalone"}.get(num(r.get("role")) or 0, "unknown")
            members.append({"unit": int(idx) if idx.isdigit() else idx, "role": role, "state": state, "healthy": state in ("local", "remote"),
                            "priority": num(r.get("priority")), "mac": mac(r.get("mac")), "model": text(r.get("descr")),
                            "firmware": text(r.get("img")), "stack_port1": ps.get(num(r.get("p1")) or 0, ""),
                            "stack_port2": ps.get(num(r.get("p2")) or 0, "")})
        present = [m for m in members if m["healthy"]]
        ports = [p for m in present for p in (m["stack_port1"], m["stack_port2"]) if p]
        topology = "standalone" if len(present) <= 1 else ("ring" if ports and all(p == "up" for p in ports) else "chain")
        o.ok("switch_stack_members", len(members))
        return {"stack": {"members": members, "topology": topology, "topology_source": "derived from stack-port states",
                          "ring_redundant": topology == "ring" if len(present) > 1 else None,
                          "stack_ports_down": sum(1 for p in ports if p == "down") if ports else None}}


class GenericAdapter:
    """Any SNMP device: standard host and sensor MIBs only (no vendor MIB is ever requested)."""
    vendor = "generic"

    async def cpu_memory(self, ctx: Ctx) -> dict:
        return await std_cpu_memory(ctx)

    async def environment(self, ctx: Ctx) -> dict:
        s = await std_sensors(ctx)
        ctx.outcome.missing("switch_fan_status")
        ctx.outcome.missing("switch_psu_status")
        if not s["temperatures"] and not s["sensors"]:
            return {"environment": None}
        return {"environment": {"temperatures": s["temperatures"], "fans": [], "psus": [], "sensors": s["sensors"]}}

    async def stack(self, ctx: Ctx) -> dict:
        return {"stack": None}


ADAPTERS = {"cisco": CiscoAdapter(), "ruckus": RuckusAdapter(), "generic": GenericAdapter()}


def _with_standard(a) -> tuple:
    """Vendor adapter first; standard MIBs fill whatever the vendor MIB left empty (e.g. NX-OS / ASA without the
    Catalyst process MIB, an ICX image without snAgentTemp)."""
    if a.vendor == "generic":
        return a.cpu_memory, a.environment

    async def cpu_memory(ctx: Ctx) -> dict:
        out = await a.cpu_memory(ctx)
        if out.get("cpu") is None or out.get("memory") is None:
            std = await std_cpu_memory(ctx)
            out = {"cpu": out.get("cpu") or std["cpu"], "memory": out.get("memory") or std["memory"]}
        return out

    async def environment(ctx: Ctx) -> dict:
        out = await a.environment(ctx)
        env = out.get("environment")
        if _empty_env(env) or not (env or {}).get("temperatures"):
            std = await std_sensors(ctx)
            if std["temperatures"] or std["sensors"]:
                env = dict(env or {"fans": [], "psus": []})
                env["temperatures"] = env.get("temperatures") or std["temperatures"]
                env["sensors"] = std["sensors"]
                out = {"environment": env}
        return out
    return cpu_memory, environment


def collectors(vendor: str) -> dict:
    _adapters()
    a = ADAPTERS.get(vendor, ADAPTERS["generic"])
    cpu_memory, environment = _with_standard(a)
    return {"system": collect_system, "interfaces": collect_interfaces, "cpu_memory": cpu_memory, "environment": environment,
            "stack": a.stack, "poe": collect_poe, "lacp": collect_lacp, "stp": collect_stp, "vlans": collect_vlans,
            "mac_table": collect_mac_table, "routing": collect_routing, "inventory": collect_inventory, "neighbors": collect_neighbors,
            "storage": collect_storage, "vendor_health": _adapters().collect_vendor_health, "custom": _adapters().collect_custom}


def _adapters():
    from . import adapters  # registers the Fortinet / Juniper adapters on first use (adapters imports this module)
    return adapters


GROUP_METRICS: dict[str, list[str]] = {}
for _m in METRICS:
    if _m.key not in GROUP_METRICS.setdefault(_m.group, []):
        GROUP_METRICS[_m.group].append(_m.key)
