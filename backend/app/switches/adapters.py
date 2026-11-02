"""Vendor adapters beyond Cisco / Ruckus (those live in collect.py): Fortinet (FortiGate, FortiSwitch) and Juniper
(EX, QFX, SRX, MX), plus the adapter interface and the "vendor_health" and "custom" collection groups.

Adapter interface (duck-typed; register with `register(adapter)`):
    vendor: str                       vendor key from fingerprints.VENDORS
    families: tuple[str, ...]         product lines the adapter knows (fingerprints family names)
    cpu_memory(ctx) / environment(ctx) / stack(ctx)    → shared normalised shapes (see CiscoAdapter)
    vendor_health(ctx)                → {"vendor": {...}} vendor-specific state, with `alarms` normalised to
                                        [{key, severity, component, detail}] for the switch_vendor_condition rule
Every value is read with GET / GETBULK only. A table that does not answer is "missing" (unsupported), never 0. The
standard-MIB fallback (std_cpu_memory / std_sensors, collect._with_standard) fills anything a vendor MIB leaves empty.

OIDs come from the vendors' public MIBs: FORTINET-CORE-MIB / FORTINET-FORTIGATE-MIB (1.3.6.1.4.1.12356.101),
FORTINET-FORTISWITCH-MIB (…12356.106), JUNIPER-MIB (jnxOperatingTable 1.3.6.1.4.1.2636.3.1.13), JUNIPER-ALARM-MIB
(…2636.3.4.2), JUNIPER-SRX5000-SPU-MONITORING-MIB (…2636.3.39.1.12). Which objects a given model / OS release answers
is recorded per device in the capability registry; the support matrix shows what has actually been observed.
"""
from __future__ import annotations

import re

from . import collect as C
from .collect import Ctx, _cols, num, text

# ------------------------------------------------------------------ Fortinet
FG = "1.3.6.1.4.1.12356.101"
FG_SYS = f"{FG}.4.1"                  # fgSystemInfo: .1 version .3 cpu % .4 mem % .5 mem capacity kB .6 disk MB .7 disk capacity MB .8 sessions
FG_PROC = f"{FG}.4.4.2.1"             # fgProcessorTable: .2 fgProcessorUsage
FG_SENSOR = f"{FG}.4.3.2.1"           # fgHwSensorTable: .2 name .3 value (string) .4 alarm status (0 no, 1 yes)
FG_HA_MODE = f"{FG}.13.1.1.0"         # fgHaSystemMode: 1 standalone, 2 activeActive, 3 activePassive
FG_HA_STATS = f"{FG}.13.2.1.1"        # fgHaStatsTable: .2 serial .11 hostname .12 sync status (0 unsynchronised, 1 synchronised) .16 primary serial
FG_VPN = f"{FG}.12.2.2.1"             # fgVpnTunTable: .3 phase 1 .4 phase 2 .5 remote gateway .18 in octets .19 out octets .20 status (1 down, 2 up)
FG_SDWAN = f"{FG}.4.9.2.1"            # fgVWLHealthCheckLinkTable: .2 name .4 state (0 alive, 1 dead) .5 latency .6 jitter .9 packet loss .14 interface
FS = "1.3.6.1.4.1.12356.106"
FS_SYS = f"{FS}.4.1"                  # fsSystemInfo: .2 cpu % .3 mem % .4 mem capacity kB
HA_MODE = {1: "standalone", 2: "active-active", 3: "active-passive"}


def _f(v) -> float | None:
    """Fortinet reports latency / jitter / sensor values as DisplayString: parse a leading number, else None."""
    m = re.match(r"\s*(-?[0-9]+(?:\.[0-9]+)?)", text(v)) if v is not None else None
    return float(m.group(1)) if m else None


class FortinetAdapter:
    vendor = "fortinet"
    families = ("FortiGate", "FortiSwitch")

    def _switch(self, ctx: Ctx) -> bool:
        return ctx.product_line == "FortiSwitch"

    async def cpu_memory(self, ctx: Ctx) -> dict:
        o = ctx.outcome
        if self._switch(ctx):
            g = await ctx.client.get([f"{FS_SYS}.2.0", f"{FS_SYS}.3.0", f"{FS_SYS}.4.0"])
            cpu, mem, cap = num(g.get(f"{FS_SYS}.2.0")), num(g.get(f"{FS_SYS}.3.0")), num(g.get(f"{FS_SYS}.4.0"))
            src = "FORTINET-FORTISWITCH-MIB fsSysCpuUsage / fsSysMemUsage"
            cpus = [{"id": "system", "name": "CPU", "pct_1m": cpu, "pct_5s": None, "pct_5m": None}] if cpu is not None else []
        else:
            g = await ctx.client.get([f"{FG_SYS}.3.0", f"{FG_SYS}.4.0", f"{FG_SYS}.5.0"])
            cpu, mem, cap = num(g.get(f"{FG_SYS}.3.0")), num(g.get(f"{FG_SYS}.4.0")), num(g.get(f"{FG_SYS}.5.0"))
            src = "FORTINET-FORTIGATE-MIB fgSysCpuUsage / fgSysMemUsage"
            procs = await _cols(ctx, FG_PROC, {"usage": 2})
            cpus = [{"id": i, "name": f"CPU {i}", "pct_1m": num(r.get("usage")), "pct_5s": None, "pct_5m": None}
                    for i, r in sorted(procs.items(), key=lambda kv: int(kv[0]) if kv[0].isdigit() else 0) if num(r.get("usage")) is not None]
            if cpu is not None and not cpus:
                cpus = [{"id": "system", "name": "CPU (system)", "pct_1m": cpu, "pct_5s": None, "pct_5m": None}]
        (o.ok if cpus else o.missing)("switch_cpu_utilization_percent", len(cpus) or 1, src)
        memory = None
        if mem is not None:
            memory = {"pct": float(mem), "total_bytes": cap * 1024 if cap else None,
                      "used_bytes": round(cap * 1024 * mem / 100) if cap else None, "source": src.split(" / ")[1] if " / " in src else src}
            o.ok("switch_memory_utilization_percent", 1, memory["source"])
        else:
            o.missing("switch_memory_utilization_percent")
        return {"cpu": {"pct": float(cpu) if cpu is not None else max(c["pct_1m"] for c in cpus), "cpus": cpus, "source": src} if cpus else None,
                "memory": memory}

    async def environment(self, ctx: Ctx) -> dict:
        o = ctx.outcome
        temps, fans, psus, sensors = [], [], [], []
        if not self._switch(ctx):
            rows = await _cols(ctx, FG_SENSOR, {"name": 2, "value": 3, "alarm": 4})
            for idx, r in sorted(rows.items(), key=lambda kv: int(kv[0]) if kv[0].isdigit() else 0):
                name, val, alarm = text(r.get("name")) or f"sensor {idx}", _f(r.get("value")), num(r.get("alarm"))
                state = "critical" if alarm == 1 else "ok" if alarm == 0 else "unknown"
                low = name.lower()
                if re.search(r"fan", low):
                    fans.append({"name": name, "state": state, "rpm": val})
                elif re.search(r"\bps[u0-9]|power supply|psu", low) and not re.search(r"temp|vin|vout|curr|\+?[0-9.]+v\b", low):
                    psus.append({"name": name, "state": state})
                elif re.search(r"temp|°c|cpu on-die|dts|tmp", low):
                    temps.append({"name": name, "celsius": val, "threshold": None, "state": "warning" if alarm == 1 else state})
                else:
                    sensors.append({"name": name, "kind": "voltage" if re.search(r"v\b|vin|vout|volt|\+[0-9.]+v", low) else "other", "unit": "",
                                    "value": val, "state": state})
        (o.ok if temps else o.missing)("switch_temperature_celsius", len(temps) or 1, "FORTINET-FORTIGATE-MIB fgHwSensorTable")
        (o.ok if fans else o.missing)("switch_fan_status", len(fans) or 1, "FORTINET-FORTIGATE-MIB fgHwSensorTable")
        (o.ok if psus else o.missing)("switch_psu_status", len(psus) or 1, "FORTINET-FORTIGATE-MIB fgHwSensorTable")
        if sensors:
            o.ok("switch_sensor_value", len(sensors), "FORTINET-FORTIGATE-MIB fgHwSensorTable")
        if not (temps or fans or psus or sensors):
            return {"environment": None}
        return {"environment": {"temperatures": temps, "fans": fans, "psus": psus, "sensors": sensors}}

    async def stack(self, ctx: Ctx) -> dict:
        return {"stack": None}

    async def vendor_health(self, ctx: Ctx) -> dict:
        o = ctx.outcome
        if self._switch(ctx):
            return {"vendor": None}
        out: dict = {"family": "FortiGate", "alarms": []}
        g = await ctx.client.get([f"{FG_SYS}.1.0", f"{FG_SYS}.6.0", f"{FG_SYS}.7.0", f"{FG_SYS}.8.0", FG_HA_MODE])
        sessions = num(g.get(f"{FG_SYS}.8.0"))
        out["sessions"] = sessions
        (o.ok if sessions is not None else o.missing)("fortigate_sessions", 1)
        du, dc = num(g.get(f"{FG_SYS}.6.0")), num(g.get(f"{FG_SYS}.7.0"))
        out["disk"] = {"used_mb": du, "capacity_mb": dc, "pct": round(100.0 * du / dc, 1) if du is not None and dc else None}
        out["version"] = text(g.get(f"{FG_SYS}.1.0"))
        mode = num(g.get(FG_HA_MODE))
        ha = {"mode": HA_MODE.get(mode or 0), "members": []}
        if mode is not None:
            o.ok("fortigate_ha_state", 1)
            if mode != 1:
                rows = await _cols(ctx, FG_HA_STATS, {"serial": 2, "host": 11, "sync": 12, "primary": 16})
                for i, r in sorted(rows.items()):
                    m = {"serial": text(r.get("serial")), "hostname": text(r.get("host")),
                         "synchronized": {0: False, 1: True}.get(num(r.get("sync"))), "primary_serial": text(r.get("primary"))}
                    ha["members"].append(m)
                    if m["synchronized"] is False:
                        out["alarms"].append({"key": f"ha_sync:{m['serial'] or i}", "severity": "high", "component": f"HA member {m['hostname'] or m['serial']}",
                                              "detail": "HA configuration is not synchronised with the primary"})
        else:
            o.missing("fortigate_ha_state")
        out["ha"] = ha
        vpn = await _cols(ctx, FG_VPN, {"p1": 3, "p2": 4, "gw": 5, "in": 18, "out": 19, "status": 20}, max_rows=4000)
        tunnels = []
        for i, r in sorted(vpn.items()):
            st = {1: "down", 2: "up"}.get(num(r.get("status")) or 0)
            t = {"phase1": text(r.get("p1")), "phase2": text(r.get("p2")), "remote_gw": text(r.get("gw")) if isinstance(r.get("gw"), (bytes, str)) else "",
                 "state": st, "in_octets": num(r.get("in")), "out_octets": num(r.get("out"))}
            tunnels.append(t)
        (o.ok if vpn else o.missing)("fortigate_vpn_tunnels", len(vpn) or 1)
        out["vpn_tunnels"] = tunnels[:2000]
        for t in tunnels:
            if t["state"] == "down":
                out["alarms"].append({"key": f"vpn:{t['phase1']}:{t['phase2']}", "severity": "high", "component": f"VPN {t['phase1']} / {t['phase2']}",
                                      "detail": f"IPsec tunnel to {t['remote_gw'] or '?'} is down"})
        sd = await _cols(ctx, FG_SDWAN, {"name": 2, "state": 4, "latency": 5, "jitter": 6, "loss": 9, "ifname": 14})
        links = [{"health_check": text(r.get("name")), "interface": text(r.get("ifname")), "state": {0: "alive", 1: "dead"}.get(num(r.get("state")) or -1),
                  "latency_ms": _f(r.get("latency")), "jitter_ms": _f(r.get("jitter")), "loss_pct": _f(r.get("loss"))} for _, r in sorted(sd.items())]
        (o.ok if sd else o.missing)("fortigate_sdwan_health", len(sd) or 1)
        out["sdwan"] = links
        for x in links:
            if x["state"] == "dead":
                out["alarms"].append({"key": f"sdwan:{x['health_check']}:{x['interface']}", "severity": "high",
                                      "component": f"SD-WAN {x['health_check']} via {x['interface']}", "detail": "SD-WAN health check member is dead"})
        return {"vendor": out}


# ------------------------------------------------------------------ Juniper
JNX_OPER = "1.3.6.1.4.1.2636.3.1.13.1"     # jnxOperatingTable: .5 descr .6 state .7 temp °C .8 cpu % .11 buffer (memory) % .15 memory MB
JNX_ALARM = "1.3.6.1.4.1.2636.3.4.2"       # jnxYellowAlarms .2 / jnxRedAlarms .3: .1 state (2 off, 3 on) .2 count
JNX_SPU = "1.3.6.1.4.1.2636.3.39.1.12.1.1.1"  # SRX SPU: .4 cpu % .5 memory % .6 current flow sessions .7 max flow sessions
JNX_STATE = {1: "unknown", 2: "running", 3: "ready", 4: "reset", 5: "running", 6: "down", 7: "standby"}


class JuniperAdapter:
    vendor = "juniper"
    families = ("EX", "QFX", "SRX", "MX")

    async def _oper(self, ctx: Ctx) -> list[dict]:
        if "jnx_oper" not in ctx.prev:
            rows = await _cols(ctx, JNX_OPER, {"descr": 5, "state": 6, "temp": 7, "cpu": 8, "buffer": 11, "mem_mb": 15})
            ctx.prev["jnx_oper"] = [{"index": i, "descr": text(r.get("descr")), "state": JNX_STATE.get(num(r.get("state")) or 0, "unknown"),
                                     "temp": num(r.get("temp")), "cpu": num(r.get("cpu")), "buffer": num(r.get("buffer")), "mem_mb": num(r.get("mem_mb"))}
                                    for i, r in sorted(rows.items())]
        return ctx.prev["jnx_oper"]

    async def cpu_memory(self, ctx: Ctx) -> dict:
        o = ctx.outcome
        res = [r for r in await self._oper(ctx) if re.search(r"routing engine", r["descr"], re.I) and r["state"] != "down"]
        cpus = [{"id": r["index"], "name": r["descr"], "pct_1m": r["cpu"], "pct_5s": None, "pct_5m": None} for r in res if r["cpu"] is not None]
        (o.ok if cpus else o.missing)("switch_cpu_utilization_percent", len(cpus) or 1, "JUNIPER-MIB jnxOperatingCPU (Routing Engine)")
        mem = None
        r0 = next((r for r in res if r["buffer"] is not None), None)
        if r0:
            total = r0["mem_mb"] * 1024 * 1024 if r0["mem_mb"] else None
            mem = {"pct": float(r0["buffer"]), "total_bytes": total, "used_bytes": round(total * r0["buffer"] / 100) if total else None,
                   "source": "JUNIPER-MIB jnxOperatingBuffer (Routing Engine)"}
        (o.ok if mem else o.missing)("switch_memory_utilization_percent", 1, mem["source"] if mem else "")
        # the primary RE (first running) drives the device value; a standby RE is listed but not maxed in
        primary = [c for c, r in zip(cpus, res) if r["state"] != "standby"] or cpus
        return {"cpu": {"pct": max(c["pct_1m"] for c in primary), "cpus": cpus, "source": "JUNIPER-MIB"} if cpus else None, "memory": mem}

    async def environment(self, ctx: Ctx) -> dict:
        o = ctx.outcome
        rows = await self._oper(ctx)
        temps = [{"name": r["descr"], "celsius": float(r["temp"]), "threshold": None, "state": "ok"} for r in rows if r["temp"]]
        state = lambda r: "ok" if r["state"] in ("running", "ready", "standby") else "failed" if r["state"] == "down" else r["state"]  # noqa: E731
        fans = [{"name": r["descr"], "state": state(r)} for r in rows if re.search(r"\bfan", r["descr"], re.I)]
        psus = [{"name": r["descr"], "state": state(r)} for r in rows if re.search(r"\bPEM\b|power supply|\bPSU\b|power entry", r["descr"], re.I)]
        src = "JUNIPER-MIB jnxOperatingTable"
        (o.ok if temps else o.missing)("switch_temperature_celsius", len(temps) or 1, src)
        (o.ok if fans else o.missing)("switch_fan_status", len(fans) or 1, src)
        (o.ok if psus else o.missing)("switch_psu_status", len(psus) or 1, src)
        if not (temps or fans or psus):
            return {"environment": None}
        return {"environment": {"temperatures": temps, "fans": fans, "psus": psus}}

    async def stack(self, ctx: Ctx) -> dict:
        return {"stack": None}   # Virtual Chassis (JUNIPER-VIRTUALCHASSIS-MIB) is not implemented yet

    async def vendor_health(self, ctx: Ctx) -> dict:
        o = ctx.outcome
        out: dict = {"family": ctx.product_line or "Junos", "alarms": []}
        g = await ctx.client.get([f"{JNX_ALARM}.2.1.0", f"{JNX_ALARM}.2.2.0", f"{JNX_ALARM}.3.1.0", f"{JNX_ALARM}.3.2.0"])
        yellow_on, yellow_n = num(g.get(f"{JNX_ALARM}.2.1.0")), num(g.get(f"{JNX_ALARM}.2.2.0"))
        red_on, red_n = num(g.get(f"{JNX_ALARM}.3.1.0")), num(g.get(f"{JNX_ALARM}.3.2.0"))
        if yellow_n is None and red_n is None and yellow_on is None and red_on is None:
            o.missing("juniper_chassis_alarms")
        else:
            o.ok("juniper_chassis_alarms", 1)
            out["alarm_counts"] = {"yellow": yellow_n, "red": red_n}
            if red_on == 3 or (red_n or 0) > 0:
                out["alarms"].append({"key": "chassis_red", "severity": "critical", "component": "chassis", "detail": f"{red_n or 'one or more'} red (major) chassis alarm(s) active"})
            if yellow_on == 3 or (yellow_n or 0) > 0:
                out["alarms"].append({"key": "chassis_yellow", "severity": "medium", "component": "chassis", "detail": f"{yellow_n or 'one or more'} yellow (minor) chassis alarm(s) active"})
        rows = await self._oper(ctx)
        comps = [{"name": r["descr"], "state": r["state"]} for r in rows if r["descr"]]
        out["components"] = comps[:500]
        for r in rows:
            if r["state"] == "down" and re.search(r"fpc|pic|routing engine|pem|power|fan", r["descr"], re.I):
                out["alarms"].append({"key": f"component:{r['index']}", "severity": "high", "component": r["descr"], "detail": f"{r['descr']} is down"})
        if (ctx.product_line or "").upper() == "SRX":
            spu = await _cols(ctx, JNX_SPU, {"cpu": 4, "mem": 5, "cur": 6, "max": 7})
            s = [{"index": i, "cpu_pct": num(r.get("cpu")), "mem_pct": num(r.get("mem")), "sessions": num(r.get("cur")), "max_sessions": num(r.get("max"))}
                 for i, r in sorted(spu.items())]
            (o.ok if s else o.missing)("srx_flow_sessions", len(s) or 1)
            out["spu"] = s
            if s:
                out["sessions"] = sum(x["sessions"] or 0 for x in s)
                out["max_sessions"] = sum(x["max_sessions"] or 0 for x in s) or None
        return {"vendor": out}


# ------------------------------------------------------------------ registration and groups
REGISTRY: dict[str, object] = {}


def register(adapter) -> None:
    for attr in ("vendor", "cpu_memory", "environment", "stack"):
        if not hasattr(adapter, attr):
            raise TypeError(f"adapter {adapter!r} lacks {attr}")
    REGISTRY[adapter.vendor] = adapter
    C.ADAPTERS[adapter.vendor] = adapter


register(FortinetAdapter())
register(JuniperAdapter())


async def collect_vendor_health(ctx: Ctx) -> dict:
    a = C.ADAPTERS.get(ctx.vendor)
    fn = getattr(a, "vendor_health", None)
    if fn is None:
        return {"vendor": None}
    return await fn(ctx)


async def collect_custom(ctx: Ctx) -> dict:
    """Administrator-defined read-only OIDs (SnmpCustomOid) for this device: one GET per scalar (batched), one walk per
    table column. Values that are not numeric are kept as text for `info` items and skipped for numeric ones."""
    items = ctx.custom_oids
    if not items:
        ctx.outcome.not_configured("custom_oid_values", "no custom OID applies to this device")
        return {"custom": None}
    out = []
    scalars = [x for x in items if x["method"] == "get"]
    if scalars:
        g = await ctx.client.get([x["oid"] for x in scalars])
        for x in scalars:
            out.append(_custom_value(x, x["oid"], g.get(x["oid"])))
    for x in [i for i in items if i["method"] == "walk"]:
        for oid, v in (await ctx.client.walk(x["oid"], max_rows=2000)):
            out.append(_custom_value(x, oid, v, index=oid[len(x["oid"]) + 1:]))
    ok = any(r["status"] == "ok" for r in out)
    (ctx.outcome.ok if ok else ctx.outcome.missing)("custom_oid_values", sum(1 for r in out if r["status"] == "ok") or 1)
    return {"custom": out}


def _custom_value(x: dict, oid: str, v, index: str = "") -> dict:
    from .snmp import MISSING
    base = {"name": x["name"], "oid": oid, "index": index, "unit": x["unit"], "value_type": x["value_type"]}
    if v is MISSING or v is None:
        return {**base, "status": "missing", "value": None, "raw": None}
    raw = v.hex() if isinstance(v, bytes) and not text(v).isprintable() else text(v) if isinstance(v, bytes) else v
    n = num(v)
    if n is None and isinstance(v, (bytes, str)):
        try:
            n = float(text(v))
        except ValueError:
            n = None
    if x["value_type"] == "info":
        return {**base, "status": "ok", "value": None, "raw": raw}
    if n is None:
        return {**base, "status": "invalid", "value": None, "raw": raw}
    return {**base, "status": "ok", "value": float(n) * float(x.get("scale") or 1), "raw": raw}
