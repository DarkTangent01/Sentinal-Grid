"""Sanitized, synthetic SNMP responses for a Cisco Catalyst 9300 stack (IOS-XE 17.9) and a Ruckus ICX 7150 stack
(FastIron 08.0.95). OIDs and value encodings follow the public MIB definitions; all names, addresses, serials and MACs
are fictional (RFC 5737 / locally administered MACs).

Each builder takes `step` (poll number) so tests can advance counters and change state between polls."""
from __future__ import annotations

C64, C32, G32, TT, OID, IP = "c64", "c32", "g32", "tt", "oid", "ip"


def vlan_bitmap(vlans, size=128) -> bytes:
    b = bytearray(size)
    for v in vlans:
        if v < size * 8:
            b[v // 8] |= 0x80 >> (v % 8)
    return bytes(b)


def portlist(ports, size=8) -> bytes:
    b = bytearray(size)
    for p in ports:
        b[(p - 1) // 8] |= 0x80 >> ((p - 1) % 8)
    return bytes(b)


def _iface(t: dict, ifx: int, name: str, descr: str, typ: int, speed_mbps: int, oper: int, *, alias="", in_oct=0, out_oct=0,
           in_pkts=0, out_pkts=0, in_err=0, out_err=0, in_disc=0, out_disc=0, hc=True, last_change=100, admin=1, mac=b"\x02\x00\x00\x00\x00\x01"):
    IF, X = "1.3.6.1.2.1.2.2.1", "1.3.6.1.2.1.31.1.1.1"
    t.update({f"{IF}.1.{ifx}": ifx, f"{IF}.2.{ifx}": descr, f"{IF}.3.{ifx}": typ, f"{IF}.4.{ifx}": 1500,
              f"{IF}.5.{ifx}": (G32, min(speed_mbps * 1_000_000, 4294967295)), f"{IF}.6.{ifx}": mac, f"{IF}.7.{ifx}": admin, f"{IF}.8.{ifx}": oper,
              f"{IF}.9.{ifx}": (TT, last_change), f"{IF}.10.{ifx}": (C32, in_oct % 2 ** 32), f"{IF}.11.{ifx}": (C32, in_pkts % 2 ** 32),
              f"{IF}.13.{ifx}": (C32, in_disc), f"{IF}.14.{ifx}": (C32, in_err), f"{IF}.16.{ifx}": (C32, out_oct % 2 ** 32),
              f"{IF}.17.{ifx}": (C32, out_pkts % 2 ** 32), f"{IF}.19.{ifx}": (C32, out_disc), f"{IF}.20.{ifx}": (C32, out_err),
              f"{X}.1.{ifx}": name, f"{X}.15.{ifx}": (G32, speed_mbps), f"{X}.18.{ifx}": alias})
    if hc:
        t.update({f"{X}.6.{ifx}": (C64, in_oct), f"{X}.7.{ifx}": (C64, in_pkts), f"{X}.8.{ifx}": (C64, 0), f"{X}.9.{ifx}": (C64, 0),
                  f"{X}.10.{ifx}": (C64, out_oct), f"{X}.11.{ifx}": (C64, out_pkts), f"{X}.12.{ifx}": (C64, 0), f"{X}.13.{ifx}": (C64, 0)})


def _stp(t: dict, root: bytes, own_mac: bytes, root_port: int, tc: int, ports: dict, version=2):
    S = "1.3.6.1.2.1.17.2"
    t.update({f"{S}.1.0": 3, f"{S}.2.0": 32768, f"{S}.3.0": (TT, 5000), f"{S}.4.0": (C32, tc), f"{S}.5.0": root, f"{S}.6.0": 4 if root_port else 0,
              f"{S}.7.0": root_port, "1.3.6.1.2.1.17.1.1.0": own_mac, f"{S}.16.0": version})
    for bp, (ifx, state, dbridge) in ports.items():
        t.update({f"1.3.6.1.2.1.17.1.4.1.2.{bp}": ifx, f"{S}.15.1.1.{bp}": bp, f"{S}.15.1.3.{bp}": state, f"{S}.15.1.4.{bp}": 1,
                  f"{S}.15.1.8.{bp}": dbridge, f"{S}.15.1.10.{bp}": (C32, 3)})


CISCO_MAC = b"\x02\xc0\x00\x00\x93\x00"
L_LOC, L_REM, L_MAN = "1.0.8802.1.1.2.1.3.7.1", "1.0.8802.1.1.2.1.4.1.1", "1.0.8802.1.1.2.1.4.2.1"


def lldp(t: dict, local: dict, remotes: list):
    """local: {localPortNum: (port id subtype, port id)}; remotes: (localPortNum, remIndex, chassis mac, port subtype, port id, sys name,
    caps byte, mgmt ipv4 or None)."""
    for lp, (sub, pid) in local.items():
        t[f"{L_LOC}.2.{lp}"] = sub
        t[f"{L_LOC}.3.{lp}"] = pid
    for lp, ri, chassis, psub, pid, name, caps, ip in remotes:
        k = f"0.{lp}.{ri}"
        t.update({f"{L_REM}.4.{k}": 4, f"{L_REM}.5.{k}": chassis, f"{L_REM}.6.{k}": psub, f"{L_REM}.7.{k}": pid, f"{L_REM}.8.{k}": "",
                  f"{L_REM}.9.{k}": name, f"{L_REM}.10.{k}": "", f"{L_REM}.12.{k}": bytes([caps, 0])})
        if ip:
            t[f"{L_MAN}.3.{k}.1.4.{ip}"] = 2
CORE_MAC = b"\x02\xc0\x00\x00\x95\x00"
NEW_ROOT_MAC = b"\x02\xc0\x00\x00\x96\x00"


def cisco_c9300(step: int = 0, *, uptime_ticks: int | None = None) -> tuple[dict, dict]:
    """(default-context tree, {context: tree}) for a 2-member C9300-48P stack."""
    t: dict = {
        "1.3.6.1.2.1.1.1.0": "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE (fc3)",
        "1.3.6.1.2.1.1.2.0": (OID, "1.3.6.1.4.1.9.1.2694"),
        "1.3.6.1.2.1.1.3.0": (TT, uptime_ticks if uptime_ticks is not None else 864000000 + step * 6000),
        "1.3.6.1.2.1.1.4.0": "noc@example.net", "1.3.6.1.2.1.1.5.0": "WH1-ACC-SW01", "1.3.6.1.2.1.1.6.0": "Warehouse 1, IDF-2",
    }
    mb = 1_000_000
    _iface(t, 9, "Gi1/0/1", "GigabitEthernet1/0/1", 6, 1000, 1, alias="AP-ROW-A", in_oct=10 ** 9 + step * 375 * mb, out_oct=2 * 10 ** 9 + step * 75 * mb,
           in_pkts=10 ** 7 + step * 300000, out_pkts=2 * 10 ** 7 + step * 60000)
    _iface(t, 10, "Gi1/0/2", "GigabitEthernet1/0/2", 6, 1000, 1, alias="SCANNER-12", in_oct=5 * 10 ** 8 + step * mb, out_oct=10 ** 8,
           in_pkts=10 ** 6, out_pkts=10 ** 6, in_err=4 + step * 25)
    _iface(t, 11, "Gi1/0/3", "GigabitEthernet1/0/3", 6, 1000, 1 if step < 1 else 2, alias="PRINTER-3", last_change=100 if step < 1 else 864000000 + 5000)
    _iface(t, 12, "Gi1/0/4", "GigabitEthernet1/0/4", 6, 1000, 2, alias="")
    _iface(t, 37, "Te1/1/1", "TenGigabitEthernet1/1/1", 6, 10000, 1, alias="UPLINK-CORE-1", in_oct=8 * 10 ** 11 + step * 3000 * mb, out_oct=10 ** 11)
    _iface(t, 38, "Te2/1/1", "TenGigabitEthernet2/1/1", 6, 10000, 1, alias="UPLINK-CORE-2", in_oct=7 * 10 ** 11 + step * 2000 * mb, out_oct=10 ** 11)
    _iface(t, 65, "Po1", "Port-channel1", 161, 20000, 1, alias="TO-CORE", in_oct=15 * 10 ** 11 + step * 5000 * mb, out_oct=2 * 10 ** 11)
    _iface(t, 70, "Vl10", "Vlan10", 136, 1000, 1, in_oct=10 ** 8, out_oct=10 ** 8)
    D3, LIF = "1.3.6.1.2.1.10.7.2.1", "1.3.6.1.4.1.9.2.2.1.1"
    for ifx in (9, 10, 11, 12, 37, 38):
        t[f"{D3}.19.{ifx}"] = 3
        t[f"{D3}.3.{ifx}"] = (C32, 0)
        t[f"{LIF}.12.{ifx}"] = (C32, (2 + step * 25) if ifx == 10 else 0)
        t[f"{LIF}.17.{ifx}"] = (C32, 0)
        t[f"{LIF}.21.{ifx}"] = (C32, 2)
    # CISCO-PROCESS-MIB: one CPU row per stack member supervisor (phys index), memory in KB (HC columns)
    CPU = "1.3.6.1.4.1.9.9.109.1.1.1.1"
    t.update({f"{CPU}.2.19": 1000, f"{CPU}.6.19": 7, f"{CPU}.7.19": 12 if step < 2 else 93, f"{CPU}.8.19": 10,
              f"{CPU}.12.19": (G32, 0), f"{CPU}.13.19": (G32, 0), f"{CPU}.17.19": (C64, 3_000_000), f"{CPU}.19.19": (C64, 5_000_000)})
    ENV = "1.3.6.1.4.1.9.9.13.1"
    t.update({f"{ENV}.3.1.2.1008": "Switch 1 - Inlet Temp Sensor", f"{ENV}.3.1.3.1008": (G32, 31), f"{ENV}.3.1.4.1008": 46, f"{ENV}.3.1.6.1008": 1,
              f"{ENV}.4.1.2.1012": "Switch 1 - FAN - T1 1", f"{ENV}.4.1.3.1012": 1,
              f"{ENV}.5.1.2.1013": "Switch 1 - Power Supply A", f"{ENV}.5.1.3.1013": 1,
              f"{ENV}.5.1.2.1014": "Switch 1 - Power Supply B", f"{ENV}.5.1.3.1014": 5})
    STK = "1.3.6.1.4.1.9.9.500.1.2.1.1"
    t.update({f"{STK}.1.1000": 1, f"{STK}.3.1000": 1, f"{STK}.4.1000": 15, f"{STK}.6.1000": 4, f"{STK}.7.1000": b"\x02\xc0\x00\x00\x93\x00",
              f"{STK}.1.2000": 2, f"{STK}.3.2000": 2, f"{STK}.4.2000": 1, f"{STK}.6.2000": 4 if step < 2 else 11, f"{STK}.7.2000": b"\x02\xc0\x00\x00\x93\x80",
              "1.3.6.1.4.1.9.9.500.1.1.3.0": 1, "1.3.6.1.4.1.9.9.500.1.2.2.1.1.1001": 1, "1.3.6.1.4.1.9.9.500.1.2.2.1.1.1002": 1})
    ENT = "1.3.6.1.2.1.47.1.1.1.1"
    for idx, cls, name, model, serial in ((1000, 3, "Switch 1", "C9300-48P", "FOC0000X1AB"), (2000, 3, "Switch 2", "C9300-48P", "FOC0000X1AC"),
                                          (1013, 6, "Switch 1 - Power Supply A", "PWR-C1-715WAC-P", "DCB0000AAAA")):
        t.update({f"{ENT}.2.{idx}": name, f"{ENT}.5.{idx}": cls, f"{ENT}.7.{idx}": name, f"{ENT}.8.{idx}": "V02", f"{ENT}.10.{idx}": "17.09.04a" if cls == 3 else "",
                  f"{ENT}.11.{idx}": serial, f"{ENT}.13.{idx}": model})
    # POWER-ETHERNET-MIB + CISCO-POWER-ETHERNET-EXT-MIB (mW)
    PM, PP, PX = "1.3.6.1.2.1.105.1.3.1.1", "1.3.6.1.2.1.105.1.1.1", "1.3.6.1.4.1.9.9.402.1.2.1"
    t.update({f"{PM}.2.1": (G32, 437), f"{PM}.3.1": 1, f"{PM}.4.1": (G32, 61), f"{PM}.2.2": (G32, 437), f"{PM}.3.2": 1, f"{PM}.4.2": (G32, 0),
              f"{PP}.3.1.1": 1, f"{PP}.6.1.1": 3, f"{PP}.7.1.1": 3, f"{PP}.10.1.1": 4,
              f"{PP}.3.1.2": 1, f"{PP}.6.1.2": 2, f"{PP}.7.1.2": 3, f"{PP}.10.1.2": 1,
              f"{PX}.7.1.1": (G32, 15400), f"{PX}.9.1.1": (G32, 6100), f"{PX}.7.1.2": (G32, 0), f"{PX}.9.1.2": (G32, 0)})
    # IEEE8023-LAG-MIB: Te1/1/1 and Te2/1/1 in Po1; at step 2 Te2/1/1 stops distributing
    LAG = "1.2.840.10006.300.43.1.2.1.1"
    for ifx in (37, 38):
        bundled = not (ifx == 38 and step >= 2)
        t.update({f"{LAG}.12.{ifx}": 65, f"{LAG}.13.{ifx}": 65 if bundled else 0, f"{LAG}.21.{ifx}": bytes([0xBC if bundled else 0xA0]),
                  f"{LAG}.23.{ifx}": bytes([0xBC])})
        t[f"1.3.6.1.4.1.9.9.98.1.1.1.1.8.{ifx}"] = 65
    # CISCO-VTP-MIB / CISCO-VLAN-MEMBERSHIP-MIB
    VTP = "1.3.6.1.4.1.9.9.46.1.3.1.1"
    for vid, name in ((1, "default"), (10, "USERS"), (20, "VOICE"), (1002, "fddi-default")):
        t.update({f"{VTP}.2.1.{vid}": 1, f"{VTP}.3.1.{vid}": 1 if vid < 1000 else 2, f"{VTP}.4.1.{vid}": name})
    VM = "1.3.6.1.4.1.9.9.68.1.2.2.1.2"
    t.update({f"{VM}.9": 10, f"{VM}.10": 10, f"{VM}.11": 20, f"{VM}.12": 10})
    TR = "1.3.6.1.4.1.9.9.46.1.6.1.1"
    for ifx in (37, 38, 65):
        t.update({f"{TR}.4.{ifx}": vlan_bitmap([1, 10, 20]), f"{TR}.5.{ifx}": 1, f"{TR}.14.{ifx}": 1})
    for ifx in (9, 10, 11, 12):
        t.update({f"{TR}.14.{ifx}": 2, f"{TR}.5.{ifx}": 1})
    t["1.3.6.1.4.1.9.9.82.1.6.1.0"] = 5  # rapid-pvst+
    # BRIDGE-MIB default context (VLAN 1 instance)
    root1 = b"\x80\x00" + CORE_MAC
    _stp(t, root1, CISCO_MAC, 5, 10, {1: (9, 5, b"\x80\x00" + CISCO_MAC), 5: (65, 5, b"\x80\x00" + CORE_MAC)})
    # IP-MIB / IP-FORWARD-MIB
    t.update({"1.3.6.1.2.1.4.20.1.2.10.20.10.1": 70, "1.3.6.1.2.1.4.20.1.3.10.20.10.1": (IP, "255.255.255.0"), "1.3.6.1.2.1.4.24.6.0": (G32, 12)})
    # LLDP: Te1/1/1 ↔ FC2-ICX-01 1/1/2, Gi1/0/1 ↔ an access point, Te2/1/1 ↔ CORE-SW-01 (gone from step 2); CDP: phone on Gi1/0/2
    rem = [(1037, 1, b"\x02\x1c\x00\x00\x00\x01", 5, "1/1/2", "FC2-ICX-01", 0x28, "198.51.100.20"),
           (1009, 2, b"\x02\xaa\x00\x00\x00\x01", 5, "eth0", "AP-ROW-A-01", 0x10, "10.20.30.41")]
    if step < 2:
        rem.append((1038, 3, b"\x02\xcc\x00\x00\x00\x01", 5, "Gi0/0/12", "CORE-SW-01.example.net", 0x28, None))
    lldp(t, {1009: (5, "Gi1/0/1"), 1037: (5, "Te1/1/1"), 1038: (5, "Te2/1/1")}, rem)
    CDP = "1.3.6.1.4.1.9.9.23.1.2.1.1"
    t.update({f"{CDP}.3.10.1": 1, f"{CDP}.4.10.1": bytes([10, 20, 20, 5]), f"{CDP}.6.10.1": "SEP0200000000A2", f"{CDP}.7.10.1": "Port 1",
              f"{CDP}.8.10.1": "Cisco IP Phone 8845", f"{CDP}.9.10.1": bytes([0, 0, 0, 0x90])})
    # per-VLAN contexts (community@vlan / context vlan-N): BRIDGE-MIB STP + FDB
    ctx = {}
    for vid in (1, 10, 20):
        c: dict = {}
        root = b"\x80\x00" + (NEW_ROOT_MAC if (vid == 10 and step >= 1) else CORE_MAC)
        _stp(c, root, CISCO_MAC, 5, 10 + (vid == 10) * step * 3, {1: (9, 5, b"\x80\x00" + CISCO_MAC), 2: (10, 5, b"\x80\x00" + CISCO_MAC),
                                                                  5: (65, 5, b"\x80\x00" + CORE_MAC)})
        if vid == 10:
            fdb = "1.3.6.1.2.1.17.4.3.1"
            port_of_a = 1 if step < 1 else 2  # the scanner's MAC moves from Gi1/0/1 to Gi1/0/2 at step 1
            for m, bp in (((2, 0, 0, 0, 0xA1, 1), port_of_a), ((2, 0, 0, 0, 0xA1, 2), 2), ((2, 0, 0, 0, 0xC0, 1), 5)):
                k = ".".join(str(x) for x in m)
                c[f"{fdb}.1.{k}"] = bytes(m)
                c[f"{fdb}.2.{k}"] = bp
                c[f"{fdb}.3.{k}"] = 3
        ctx[f"vlan-{vid}"] = c
        ctx[str(vid)] = c
    return t, ctx


def ruckus_icx7150(step: int = 0) -> dict:
    t: dict = {
        "1.3.6.1.2.1.1.1.0": "Ruckus ICX7150-48P-4X10GR, IronWare Version 08.0.95dT213 Compiled on Mar 1 2023 at 10:00:00 labeled as SPS08095d",
        "1.3.6.1.2.1.1.2.0": (OID, "1.3.6.1.4.1.1991.1.3.62.2.3.1.1"),
        "1.3.6.1.2.1.1.3.0": (TT, 50000000 + step * 6000), "1.3.6.1.2.1.1.5.0": "FC2-ICX-01", "1.3.6.1.2.1.1.6.0": "Fulfilment centre 2, MDF",
    }
    mb = 1_000_000
    _iface(t, 1, "1/1/1", "GigabitEthernet1/1/1", 6, 1000, 1, alias="CONVEYOR-PLC", in_oct=10 ** 9 + step * 75 * mb, out_oct=10 ** 9)
    _iface(t, 2, "1/1/2", "GigabitEthernet1/1/2", 6, 1000, 1, in_oct=10 ** 8, out_oct=10 ** 8)
    _iface(t, 3, "1/1/3", "GigabitEthernet1/1/3", 6, 1000, 1, alias="AP-DOCK-1", in_oct=10 ** 8, out_oct=10 ** 8)
    _iface(t, 4, "1/1/4", "GigabitEthernet1/1/4", 6, 1000, 2)
    # a 32-bit-only port (old module): counter wraps between step 0 and 1
    _iface(t, 5, "1/1/5", "GigabitEthernet1/1/5", 6, 100, 1, in_oct=(2 ** 32 - 10 * mb) if step == 0 else (20 * mb), out_oct=0, hc=False)
    _iface(t, 2049, "lg1", "lg1", 161, 20000, 1, alias="TO-DIST")
    _iface(t, 3082, "ve10", "ve10", 136, 1000, 1)
    G = "1.3.6.1.4.1.1991.1.1.2.1"
    CPU = "1.3.6.1.4.1.1991.1.1.2.11.1.1"
    t.update({f"{CPU}.5.1.1.1": 4, f"{CPU}.5.1.1.5": 6, f"{CPU}.5.1.1.60": 9, f"{CPU}.5.1.1.300": 8,
              f"{G}.11.0": "08.0.95dT213", f"{G}.52.0": 9, f"{G}.53.0": 41, f"{G}.54.0": (G32, 1073741824), f"{G}.55.0": (G32, 633507676),
              "1.3.6.1.4.1.1991.1.1.1.1.2.0": "FEK0000Q0AA", "1.3.6.1.4.1.1991.1.1.1.1.19.0": 170})
    T2, F2, P2 = "1.3.6.1.4.1.1991.1.1.2.13.3.1", "1.3.6.1.4.1.1991.1.1.1.3.2.1", "1.3.6.1.4.1.1991.1.1.1.2.2.1"
    t.update({f"{T2}.4.1.1.1": "System temperature", f"{T2}.5.1.1.1": 76, f"{T2}.4.2.1.1": "System temperature", f"{T2}.5.2.1.1": 80 if step < 2 else 176,
              f"{F2}.1.1.1": 1, f"{F2}.3.1.1": "Fan 1", f"{F2}.4.1.1": 2,
              f"{P2}.1.1.1": 1, f"{P2}.3.1.1": "PSU 1", f"{P2}.4.1.1": 2, f"{P2}.1.1.2": 1, f"{P2}.3.1.2": "PSU 2", f"{P2}.4.1.2": 2 if step < 1 else 3})
    ST = "1.3.6.1.4.1.1991.1.1.3.31.2.2.1"
    for u, role, state in ((1, 2, 1), (2, 3, 2)):
        t.update({f"{ST}.2.{u}": role, f"{ST}.3.{u}": bytes([2, 0x1C, 0, 0, 0, u]), f"{ST}.4.{u}": 128, f"{ST}.5.{u}": state,
                  f"{ST}.6.{u}": "ICX7150-48P-4X10GR", f"{ST}.8.{u}": 2, f"{ST}.10.{u}": 2, f"{ST}.14.{u}": "08.0.95dT213"})
        t[f"1.3.6.1.4.1.1991.1.1.1.4.1.1.2.{u}"] = f"FEK0000Q0A{u}"
    PG, PP, PU = "1.3.6.1.4.1.1991.1.1.2.14.1", "1.3.6.1.4.1.1991.1.1.2.14.2.2.1", "1.3.6.1.4.1.1991.1.1.2.14.4.1.1"
    t.update({f"{PG}.1.0": (G32, 740000), f"{PG}.2.0": (G32, 690000), f"{PU}.2.1": (G32, 740000), f"{PU}.3.1": (G32, 690000),
              f"{PP}.2.3": 3, f"{PP}.3.3": (G32, 30000), f"{PP}.4.3": 4, f"{PP}.6.3": (G32, 7200),
              f"{PP}.2.1": 3, f"{PP}.3.1": (G32, 15400), f"{PP}.4.1": 2, f"{PP}.6.1": (G32, 4100)})
    LAG = "1.2.840.10006.300.43.1.2.1.1"
    # LAG members are 1/1/49-like 10G ports in reality; the fixture reuses 1/1/2 and 1/1/3 for brevity
    for ifx in (2, 3):
        t.update({f"{LAG}.12.{ifx}": 2049, f"{LAG}.13.{ifx}": 2049, f"{LAG}.21.{ifx}": bytes([0xBC]), f"{LAG}.23.{ifx}": bytes([0xBC])})
    Q = "1.3.6.1.2.1.17.7.1.4.3.1"
    for vid, name, egress, untagged in ((1, "DEFAULT-VLAN", [4, 5], [4, 5]), (10, "USERS", [1, 2, 3], [1, 2]), (20, "VOICE", [3], [])):
        t.update({f"{Q}.1.{vid}": name, f"{Q}.2.{vid}": portlist(egress), f"{Q}.4.{vid}": portlist(untagged), f"{Q}.5.{vid}": 1})
    for bp in (1, 2, 3, 4, 5):
        t[f"1.3.6.1.2.1.17.1.4.1.2.{bp}"] = bp
        t[f"1.3.6.1.2.1.17.7.1.4.5.1.1.{bp}"] = (G32, 10 if bp in (1, 2) else 1)
    t["1.3.6.1.2.1.17.7.1.4.2.1.3.0.10"] = (G32, 10)
    FDB = "1.3.6.1.2.1.17.7.1.2.2.1"
    for m, port in (((2, 0, 0, 0, 0xB1, 1), 1), ((2, 0, 0, 0, 0xB1, 2), 2 if step < 1 else 1)):
        k = "10." + ".".join(str(x) for x in m)
        t[f"{FDB}.2.{k}"] = port
        t[f"{FDB}.3.{k}"] = 3
    # LLDP: 1/1/2 ↔ WH1-ACC-SW01 (advertised with its domain and the long port name)
    lldp(t, {2: (7, "1/1/2"), 3: (7, "1/1/3")}, [(2, 1, b"\x02\xc0\x00\x00\x93\x00", 5, "TenGigabitEthernet1/1/1", "WH1-ACC-SW01.example.net", 0x28,
                                                 "192.0.2.10")])
    own = bytes([2, 0x1C, 0, 0, 0, 1])
    _stp(t, b"\x80\x00" + own, own, 0, 4 + step, {1: (1, 5, b"\x80\x00" + own), 2: (2, 5, b"\x80\x00" + own), 3: (3, 5, b"\x80\x00" + own)})
    return t
