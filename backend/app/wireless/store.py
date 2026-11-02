"""Persist one wireless poll of a controller: AP / radio / WLAN / client inventory, state machines, events and history.

AP state (docs/WIRELESS.md)
    up           listed by the controller and associated (bsnAPOperationStatus = associated)
    degraded     listed but downloading an image / disassociating, a radio administratively up is down, or CPU ≥ 90 %
    maintenance  administratively disabled on the controller
    down         previously known and absent from a successful AP-table walk on 2 consecutive polls
    unknown      never seen in a successful walk, or the controller's AP table could not be read (collection problem,
                 not an outage)
Roams are inferred from a client's AP changing between two polls; their time is the poll time (not a measured roam
duration). Counter rates skip resets and wraps instead of producing negative or huge values.
"""
from __future__ import annotations

import logging
import math
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import Switch, SwitchInterface, WirelessAp, WirelessClient, WirelessEvent, WirelessRadio, WirelessWlan
from ..switches.collect import port_key
from . import rf as RF

log = logging.getLogger("wireless")
DOWN_AFTER_MISSING = 2
MAX_CLIENT_EVENTS = 2000          # per poll; beyond this, association churn is summarised in one event
METRIC_COLS = ["ts", "wlc_id", "ap_id", "slot", "wlan_id", "band", "metric", "value", "source"]
CLIENT_COLS = ["ts", "wlc_id", "mac", "ap_id", "slot", "ssid", "band", "rssi_dbm", "snr_db", "tx_rate_mbps", "rx_bytes", "tx_bytes", "source"]
SRC_BSN, SRC_CL = "AIRESPACE-WIRELESS-MIB", "CISCO-LWAPP-AP-MIB"
RF_COLS = ["ts", "site", "wlc_id", "ap_id", "radio_id", "slot", "vendor", "band", "channel", "center_mhz", "width_mhz", "metric", "value", "unit",
           "source", "status", "quality"]
# plausible ranges: a value outside is recorded as status "invalid" (value NULL), never clamped or used by analytics
RF_RANGES = {"channel_util_pct": (0, 100), "tx_util_pct": (0, 100), "rx_util_pct": (0, 100), "interference_pct": (0, 100), "retry_pct": (0, 100),
             "noise_dbm": (-120, -20), "interference_dbm": (-120, 0), "clients": (0, 5000), "poor_snr_clients": (0, 5000),
             "tx_power_level": (1, 8), "tx_power_dbm": (-10, 36), "link_changes": (0, 10**12)}
RF_UNITS = {"channel_util_pct": "%", "tx_util_pct": "%", "rx_util_pct": "%", "interference_pct": "%", "retry_pct": "%", "noise_dbm": "dBm",
            "interference_dbm": "dBm", "clients": "clients", "poor_snr_clients": "clients", "tx_power_level": "level", "tx_power_dbm": "dBm",
            "link_changes": "count", "channel": "", "radio_up": ""}


def rf_value(metric: str, v):
    """(value, status) for one RF sample: missing stays missing, implausible values become invalid (never zero, never clamped)."""
    if v is None:
        return None, "missing"
    lo_hi = RF_RANGES.get(metric)
    if lo_hi and not (lo_hi[0] <= v <= lo_hi[1]):
        return None, "invalid"
    return float(v), "ok"


def _aware(v):
    return v if v is None or v.tzinfo else v.replace(tzinfo=timezone.utc)


def _dur(s) -> str:
    s = int(s or 0)
    d, r = divmod(s, 86400)
    h, r = divmod(r, 3600)
    m = r // 60
    return f"{d}d {h}h" if d else f"{h}h {m}m" if h else f"{m}m"


def delta(cur, prev):
    """Counter delta; None on reset / wrap / missing (never a negative or wrapped value)."""
    if cur is None or prev is None or cur < prev:
        return None
    return cur - prev


class Out:
    def __init__(self, s: AsyncSession, sw: Switch, now: datetime):
        self.s, self.sw, self.now = s, sw, now
        self.metrics: list[dict] = []
        self.samples: list[dict] = []
        self.rf_rows: list[dict] = []
        self.events: list[WirelessEvent] = []
        self.client_events = 0

    def m(self, metric: str, value, *, ap_id=0, slot=-1, wlan_id=0, band="", source=""):
        if value is None:
            return  # unsupported / not measured: no sample, never a zero
        self.metrics.append({"ts": self.now, "wlc_id": self.sw.id, "ap_id": ap_id or 0, "slot": slot if slot is not None else -1,
                             "wlan_id": wlan_id or 0, "band": band or "", "metric": metric, "value": float(value), "source": source})

    def rf(self, r: WirelessRadio, a: WirelessAp, metric: str, value, *, source: str, quality: str = "measured", status: str | None = None):
        v, st = rf_value(metric, value)
        self.rf_rows.append({"ts": self.now, "site": a.site or "", "wlc_id": self.sw.id, "ap_id": a.id, "radio_id": r.id or 0, "slot": r.slot,
                             "vendor": self.sw.vendor or "cisco", "band": r.band or "", "channel": r.channel, "center_mhz": r.center_frequency_mhz,
                             "width_mhz": r.channel_width_mhz, "metric": metric, "value": v, "unit": RF_UNITS.get(metric, ""), "source": source,
                             "status": status or st, "quality": quality})

    def ev(self, kind: str, severity: str, detail: str, *, ap_id=None, client_mac="", component="", client=False, **data):
        if client:
            self.client_events += 1
            if self.client_events > MAX_CLIENT_EVENTS:
                return
        e = WirelessEvent(wlc_id=self.sw.id, ap_id=ap_id, client_mac=client_mac, at=self.now, kind=kind, severity=severity,
                          component=component[:255], detail=detail, data=data)
        self.s.add(e)
        self.events.append(e)


def ap_state(ap: WirelessAp, radios_down: int) -> str:
    if ap.admin_enabled is False:
        return "maintenance"
    if ap.oper_status == "associated" or (not ap.oper_status and ap.present):
        return "degraded" if radios_down or (ap.cpu_pct or 0) >= 90 else "up"
    if ap.oper_status in ("downloading", "disassociating"):
        return "degraded"
    return "unknown"


def _set_state(o, new: str, now: datetime):
    if o.state != new:
        o.state, o.state_since = new, now
        return True
    return False


def tx_dbm(levels: dict, level: int | None) -> float | None:
    """dBm of the current power level from the controller's mW-per-level table; None unless both are reported."""
    if level is None or not levels:
        return None
    mw = levels.get(str(level), levels.get(level))
    return round(10 * math.log10(mw), 1) if mw and mw > 0 else None


def channel_change_reason(r: WirelessRadio, d: dict) -> tuple[str, str]:
    """Explain a channel change from what the controller reports. SNMP does not carry the DCA trigger, so the reason is
    an inference with a stated confidence, never presented as the controller's own reason."""
    recent = [x for x in (r.radar or []) if x.get("channel") == r.channel and (x.get("last_heard_s") is not None and x["last_heard_s"] <= 900)]
    if recent:
        return f"radar detected on channel {r.channel} (DFS)", "high"
    if r.channel_assignment == "automatic":
        return "assigned by RRM / DCA; the controller does not report the trigger over SNMP", "medium"
    if r.channel_assignment == "customized":
        return "static channel changed (configuration)", "medium"
    return "reason not reported", "low"


def _radar(radios, aps, radar: dict, now: datetime, out: Out):
    for key, lst in radar.items():
        m, slot = key.rsplit("/", 1)
        a = aps.get(m)
        r = radios.get((a.id, int(slot))) if a else None
        if r is None:
            continue
        prev = {x.get("channel"): x for x in (r.radar or [])}
        cur = []
        for x in lst:
            p = prev.get(x["channel"])
            fresh = p is None or (x.get("last_heard_s") is not None and p.get("last_heard_s") is not None and x["last_heard_s"] < p["last_heard_s"])
            if fresh and x.get("last_heard_s") is not None and x["last_heard_s"] <= 3600:
                out.ev("dfs_radar", "medium", f"{a.name} radio {r.slot}: radar detected on channel {x['channel']} "
                       f"({x['last_heard_s']} s ago)", ap_id=a.id, component=f"{a.name}/{r.slot}", channel=x["channel"],
                       mhz=RF.channel_freq("5", x["channel"]), band=r.band)
            cur.append({**x, "seen_at": now.isoformat()})
        r.radar = cur[:50]


async def _neighbors(s: AsyncSession, sw: Switch, radios, aps, nbrs: dict, now: datetime):
    """Resolve RRM neighbours to known APs (by base radio MAC) and keep the 50 strongest per radio."""
    known = {a.mac: a for a in (await s.execute(select(WirelessAp))).scalars()}
    for key, lst in nbrs.items():
        m, slot = key.rsplit("/", 1)
        a = aps.get(m)
        r = radios.get((a.id, int(slot))) if a else None
        if r is None:
            continue
        rows = []
        for n in lst:
            na = known.get(n["mac"])
            rows.append({**n, "ap_id": na.id if na else None, "ap_name": na.name if na else "", "site": na.site if na else "",
                         "same_controller": bool(na and na.wlc_id == sw.id)})
        rows.sort(key=lambda x: (x["rssi_dbm"] is None, -(x["rssi_dbm"] or -999)))
        r.neighbors, r.neighbors_collected_at = rows[:50], now


async def persist(s: AsyncSession, ch, sw: Switch, data: dict, ran: set[str], now: datetime, intervals: dict, sw_health: dict | None = None) -> dict:
    """sw_health: the poller's health dict for this controller (the summary goes under "wireless")."""
    out = Out(s, sw, now)
    aps = {a.mac: a for a in (await s.execute(select(WirelessAp).where(WirelessAp.wlc_id == sw.id))).scalars()}
    radios = {(r.ap_id, r.slot): r for r in (await s.execute(select(WirelessRadio).where(WirelessRadio.wlc_id == sw.id))).scalars()}
    holder = sw_health if sw_health is not None else dict(sw.health or {})
    health = dict(holder.get("wireless") or {})
    # ---------------------------------------------------------------- APs
    if "wireless_ap" in ran and data.get("wireless_aps") is not None:
        seen: dict = data["wireless_aps"]
        table_ok = bool(data.get("wireless_ap_table_ok"))
        for m, d in seen.items():
            a = aps.get(m)
            if a is None:
                a = WirelessAp(wlc_id=sw.id, mac=m, site=sw.site or "", building=sw.building or "", floor=sw.floor or "", first_seen=now,
                               state="unknown", counters={})
                s.add(a)
                aps[m] = a
                out.ev("ap_joined", "informational", f"AP {d['name'] or m} discovered on {sw.name}", component=d["name"] or m)
            elif not a.present:
                out.ev("ap_reconnected", "informational", f"AP {a.name or m} is listed by the controller again", component=a.name or m)
            prev_up = a.uptime_s
            if d.get("uptime_s") is not None and prev_up is not None and d["uptime_s"] < prev_up and a.present:
                out.ev("ap_reboot", "medium", f"AP {d['name'] or m} restarted (uptime {_dur(prev_up)} → {_dur(d['uptime_s'])})"
                       + (f"; last reboot reason {d['reboot_reason']}" if d.get("reboot_reason") else ""), component=d["name"] or m,
                       reason=d.get("reboot_reason"))
            if d.get("software") and a.software and d["software"] != a.software:
                out.ev("ap_software_change", "low", f"AP {d['name'] or m} software {a.software} → {d['software']}", component=d["name"] or m)
            for k in ("name", "ip", "model", "serial", "software", "location"):
                if d.get(k):
                    setattr(a, k, str(d[k])[:255])
            a.oper_status = d.get("oper_status") or ""
            a.admin_enabled = d.get("admin_enabled")
            a.uptime_s, a.join_uptime_s = d.get("uptime_s"), d.get("join_uptime_s")
            a.last_reboot_reason = d.get("reboot_reason") or ""
            a.cpu_pct, a.mem_pct, a.clients = d.get("cpu_pct"), d.get("mem_pct"), d.get("clients")
            a.radio_count = d.get("slots")
            a.power_status = d.get("power_status") or ""
            a.tags = d.get("tags") or {}
            c = dict(a.counters or {})
            c.update(missing_polls=0, sources=d.get("sources", []))
            if d.get("assoc_fail") is not None:
                c["assoc_fail_delta"] = delta(d["assoc_fail"], c.get("assoc_fail"))
                c["assoc_fail"] = d["assoc_fail"]
            a.counters = c
            a.present, a.last_seen = True, now
        for m, a in aps.items():
            if m in seen:
                continue
            if not table_ok:
                continue  # the controller's AP table could not be read: a collection problem, not an AP outage
            c = dict(a.counters or {})
            c["missing_polls"] = int(c.get("missing_polls") or 0) + 1
            a.counters = c
            if c["missing_polls"] >= DOWN_AFTER_MISSING and a.state != "down":
                a.present = False
                if _set_state(a, "down", now):
                    out.ev("ap_down", "high", f"AP {a.name or m} is no longer joined to {sw.name} (absent from {c['missing_polls']} consecutive "
                           f"successful AP-table polls)", ap_id=a.id, component=a.name or m)
        health["ap_table_ok"] = table_ok
    await s.flush()
    ap_by_id = {a.id: a for a in aps.values()}
    # ---------------------------------------------------------------- CDP uplinks → monitored switch / port
    if "wireless_ap_cdp" in ran and data.get("wireless_ap_cdp") is not None:
        sws = [x for x in (await s.execute(select(Switch).where(Switch.id != sw.id))).scalars()]

        def match(name: str, addr: str):
            n = (name or "").split(".")[0].lower()
            for x in sws:
                if addr and x.address == addr:
                    return x
            for x in sws:
                if n and n in {(x.sys_name or "").split(".")[0].lower(), (x.name or "").split(".")[0].lower()}:
                    return x
            return None
        for m, u in data["wireless_ap_cdp"].items():
            a = aps.get(m)
            if a is None:
                continue
            a.uplink = u
            target = match(u.get("switch", ""), u.get("address", ""))
            a.switch_id = target.id if target else None
            a.switch_ifindex = None
            if target and u.get("port"):
                pk = port_key(u["port"])
                for i in (await s.execute(select(SwitchInterface).where(SwitchInterface.switch_id == target.id))).scalars():
                    if port_key(i.name) == pk or port_key(i.descr or "") == pk:
                        a.switch_ifindex = i.ifindex
                        break
    # ---------------------------------------------------------------- radios
    rf_radio: list[tuple] = []
    if "wireless_radio" in ran and data.get("wireless_radios") is not None:
        rlist = data["wireless_radios"]
        rw = data.get("wireless_radio_wlans") or {}
        for key, d in rlist.items():
            a = aps.get(d["ap_mac"])
            if a is None:
                continue
            r = radios.get((a.id, d["slot"]))
            if r is None:
                r = WirelessRadio(ap_id=a.id, wlc_id=sw.id, slot=d["slot"], state="unknown", counters={}, wlans=[], power_levels={}, radar=[],
                                  neighbors=[])
                s.add(r)
                await s.flush()   # radio id is part of every RF telemetry row
                radios[(a.id, d["slot"])] = r
            if r.channel is not None and d.get("channel") is not None and d["channel"] != r.channel:
                r.channel_changes = (r.channel_changes or 0) + 1
                r.last_channel_change_at = now
                why, conf = channel_change_reason(r, d)
                out.ev("channel_change", "low", f"{a.name} radio {d['slot']} ({d.get('band') or '?'} GHz) channel {r.channel} → {d['channel']}"
                       f" ({why})", ap_id=a.id, component=f"{a.name}/{d['slot']}", old=r.channel, new=d["channel"], band=d.get("band"),
                       old_mhz=RF.channel_freq(d.get("band") or "", r.channel), new_mhz=RF.channel_freq(d.get("band") or "", d["channel"]),
                       reason=why, reason_confidence=conf)
            if r.tx_power_level is not None and d.get("tx_power_level") is not None and d["tx_power_level"] != r.tx_power_level:
                out.ev("tx_power_change", "informational", f"{a.name} radio {d['slot']} transmit power level {r.tx_power_level} → {d['tx_power_level']}"
                       f" ({'RRM / TPC' if r.power_assignment == 'automatic' else 'configuration'})", ap_id=a.id, component=f"{a.name}/{d['slot']}",
                       old=r.tx_power_level, new=d["tx_power_level"], band=d.get("band"))
            if r.link_changes is not None and d.get("link_changes") is not None and d["link_changes"] > r.link_changes:
                out.ev("radio_link_change", "medium", f"{a.name} radio {d['slot']} link changed {d['link_changes'] - r.link_changes} time(s) since the last poll",
                       ap_id=a.id, component=f"{a.name}/{d['slot']}", count=d["link_changes"] - r.link_changes, band=d.get("band"))
            for k in ("band", "radio_type", "channel", "channel_width_mhz", "tx_power_level", "channel_util_pct", "tx_util_pct", "rx_util_pct",
                      "clients", "poor_snr_clients", "admin_enabled", "oper_up", "link_changes"):
                setattr(r, k, d.get(k))
            fd = RF.describe(r.band, r.channel, r.channel_width_mhz)
            r.frequency_mhz, r.center_frequency_mhz, r.dfs = fd["frequency_mhz"], fd["center_frequency_mhz"], fd["dfs"]
            r.tx_power_dbm = tx_dbm(r.power_levels, r.tx_power_level)
            prev = dict(r.counters or {})
            cur = d.get("counters") or {}
            dtx, dretry = delta(cur.get("tx_frames"), prev.get("tx_frames")), delta(cur.get("retries"), prev.get("retries"))
            r.retry_pct = round(100 * dretry / dtx, 2) if dtx and dretry is not None else None
            r.counters = cur
            new = "disabled" if d.get("admin_enabled") is False else "up" if d.get("oper_up") else "down" if d.get("oper_up") is False else "unknown"
            if r.state != new and r.state != "unknown":
                sev = "high" if new == "down" else "informational"
                out.ev(f"radio_{new}", sev, f"{a.name} radio {d['slot']} ({d.get('band') or '?'} GHz) {r.state} → {new}", ap_id=a.id,
                       component=f"{a.name}/{d['slot']}", band=d.get("band"))
            _set_state(r, new, now)
            if key in rw:
                r.wlans = rw[key]
            r.last_seen, r.present = now, True
            b = d.get("band")
            out.m("wireless_radio_up", 1 if new == "up" else 0, ap_id=a.id, slot=d["slot"], band=b, source=SRC_BSN)
            for k, mk in (("channel_util_pct", "wireless_radio_channel_utilization_percent"), ("tx_util_pct", "wireless_radio_tx_utilization_percent"),
                          ("rx_util_pct", "wireless_radio_rx_utilization_percent"), ("clients", "wireless_radio_client_count"),
                          ("channel", "wireless_radio_channel")):
                out.m(mk, d.get(k), ap_id=a.id, slot=d["slot"], band=b, source=SRC_BSN)
            out.m("wireless_radio_retry_percent", r.retry_pct, ap_id=a.id, slot=d["slot"], band=b, source=SRC_BSN)
            rf_radio.append((r, a))
        for r in radios.values():
            if r.last_seen and _aware(r.last_seen) < now - timedelta(seconds=1) and r.present and ap_by_id.get(r.ap_id) and not ap_by_id[r.ap_id].present:
                r.present = False
    if "wireless_radio_rf" in ran and data.get("wireless_rf") is not None:
        for key, d in data["wireless_rf"].items():
            m, slot = key.rsplit("/", 1)
            a = aps.get(m)
            r = radios.get((a.id, int(slot))) if a else None
            if r is None:
                continue
            r.noise_dbm, r.interference_pct, r.interference_dbm = d.get("noise_dbm"), d.get("interference_pct"), d.get("interference_dbm")
            out.m("wireless_radio_noise_dbm", r.noise_dbm, ap_id=a.id, slot=r.slot, band=r.band, source=SRC_BSN)
            out.m("wireless_radio_interference_percent", r.interference_pct, ap_id=a.id, slot=r.slot, band=r.band, source=SRC_BSN)
            r.rf_collected_at = now
            for k in ("noise_dbm", "interference_pct", "interference_dbm"):
                out.rf(r, a, k, getattr(r, k), source=SRC_BSN + (" bsnAPIfNoiseTable" if k == "noise_dbm" else " bsnAPIfInterferenceTable"))
    if "wireless_radio_rf" in ran and data.get("wireless_radar_ok"):
        _radar(radios, aps, data.get("wireless_radar") or {}, now, out)
    if "wireless_radio_meta" in ran and data.get("wireless_radio_meta") is not None:
        for key, d in data["wireless_radio_meta"].items():
            m, slot = key.rsplit("/", 1)
            a = aps.get(m)
            r = radios.get((a.id, int(slot))) if a else None
            if r is None:
                continue
            for k in ("channel_assignment", "power_assignment", "regdomain_supported", "country", "environment", "recommended_channel",
                      "recommended_power_level", "radio_mac"):
                setattr(r, k, d.get(k) if d.get(k) is not None else (None if k in ("regdomain_supported", "recommended_channel", "recommended_power_level") else ""))
            r.power_levels = {str(k): v for k, v in (d.get("power_levels_mw") or {}).items()}
            r.tx_power_dbm = tx_dbm(r.power_levels, r.tx_power_level)
            r.meta_collected_at = now
    if "wireless_rf_neighbors" in ran and data.get("wireless_rf_neighbors") is not None:
        await _neighbors(s, sw, radios, aps, data["wireless_rf_neighbors"], now)
    for r, a in rf_radio:
        for k in ("channel_util_pct", "tx_util_pct", "rx_util_pct", "clients", "poor_snr_clients", "tx_power_level", "link_changes"):
            out.rf(r, a, k, getattr(r, k), source=SRC_CL if k == "link_changes" else SRC_BSN)
        out.rf(r, a, "retry_pct", r.retry_pct, source=SRC_BSN + " (retries / transmitted frames)", quality="derived")
        out.rf(r, a, "tx_power_dbm", r.tx_power_dbm, source=SRC_BSN + " bsnAPIfDot11PhyTxPowerTable", quality="derived")
        out.rf(r, a, "radio_up", None if r.state == "unknown" else (1 if r.state == "up" else 0), source=SRC_BSN)
        out.rf(r, a, "channel", r.channel if RF.valid_channel(r.band, r.channel) or r.band == "5/6" else None, source=SRC_BSN,
               status=None if r.channel is None or RF.valid_channel(r.band, r.channel) or r.band == "5/6" else "invalid")
    # AP state (needs radios)
    for a in aps.values():
        if not a.present:
            continue
        rd = sum(1 for r in radios.values() if r.ap_id == a.id and r.state == "down")
        new = ap_state(a, rd)
        old = a.state
        if _set_state(a, new, now) and old not in ("unknown",):
            out.ev(f"ap_{new}", "high" if new == "down" else "medium" if new == "degraded" else "informational",
                   f"AP {a.name} {old} → {new}" + (f" ({rd} radio(s) down)" if rd else ""), ap_id=a.id, component=a.name)
        out.m("wireless_ap_up", 1 if new in ("up", "degraded") else 0, ap_id=a.id, source=SRC_BSN)
        out.m("wireless_ap_client_count", a.clients, ap_id=a.id, source=SRC_CL)
        out.m("wireless_ap_cpu_percent", a.cpu_pct, ap_id=a.id, source=SRC_CL)
        out.m("wireless_ap_memory_percent", a.mem_pct, ap_id=a.id, source=SRC_CL)
        out.m("wireless_ap_assoc_failures", (a.counters or {}).get("assoc_fail_delta"), ap_id=a.id, source=SRC_CL)
    # ---------------------------------------------------------------- WLANs
    wlans = {w.wlan_id: w for w in (await s.execute(select(WirelessWlan).where(WirelessWlan.wlc_id == sw.id))).scalars()}
    if "wireless_wlan" in ran and data.get("wireless_wlans") is not None:
        rw = data.get("wireless_radio_wlans") or {}
        by_wlan_aps: dict[int, set] = {}
        by_wlan_radios: dict[int, int] = {}
        for key, lst in rw.items():
            for w in lst:
                by_wlan_aps.setdefault(w["wlan_id"], set()).add(key.split("/")[0])
                by_wlan_radios[w["wlan_id"]] = by_wlan_radios.get(w["wlan_id"], 0) + 1
            m, slot = key.rsplit("/", 1)
            a = aps.get(m)
            r = radios.get((a.id, int(slot))) if a else None
            if r is not None:
                r.wlans = lst
        for wid, d in data["wireless_wlans"].items():
            w = wlans.get(wid)
            if w is None:
                w = WirelessWlan(wlc_id=sw.id, wlan_id=wid)
                s.add(w)
                wlans[wid] = w
            for k in ("profile", "ssid", "enabled", "security", "max_clients", "clients"):
                setattr(w, k, d.get(k))
            w.aps = len(by_wlan_aps.get(wid, set())) if rw else None
            w.radios = by_wlan_radios.get(wid) if rw else None
            w.present, w.last_seen = True, now
            out.m("wireless_wlan_up", 1 if d.get("enabled") else 0, wlan_id=wid, source=SRC_BSN)
            out.m("wireless_wlan_client_count", d.get("clients"), wlan_id=wid, source=SRC_BSN)
        for wid, w in wlans.items():
            if wid not in data["wireless_wlans"] and data["wireless_wlans"]:
                w.present = False
    # ---------------------------------------------------------------- clients
    if "wireless_client" in ran and data.get("wireless_clients") is not None:
        cur: dict = data["wireless_clients"]
        table_ok = bool(data.get("wireless_client_table_ok"))
        known = {c.mac: c for c in (await s.execute(select(WirelessClient).where(WirelessClient.wlc_id == sw.id,
                                                                               WirelessClient.present.is_(True)))).scalars()}
        ap_mac_id = {m: a.id for m, a in aps.items()}
        new_macs = [m for m in cur if m not in known]
        stale = {c.mac: c for c in (await s.execute(select(WirelessClient).where(WirelessClient.wlc_id == sw.id, WirelessClient.mac.in_(new_macs[:5000]),
                                                                               WirelessClient.present.is_(False)))).scalars()} if new_macs else {}
        for m, d in cur.items():
            c = known.get(m) or stale.get(m)
            ap_id = ap_mac_id.get(d.get("ap_mac", ""))
            if c is None:
                c = WirelessClient(wlc_id=sw.id, mac=m, first_seen=now, roams=0, disconnects=0)
                s.add(c)
                out.ev("client_associated", "informational", f"client {m} associated to {aps[d['ap_mac']].name if d.get('ap_mac') in aps else d.get('ap_mac') or '?'}"
                       f" on {d.get('ssid') or '?'}", ap_id=ap_id, client_mac=m, client=True, ssid=d.get("ssid"))
            elif not c.present:
                out.ev("client_associated", "informational", f"client {m} associated again on {d.get('ssid') or '?'}", ap_id=ap_id, client_mac=m,
                       client=True, ssid=d.get("ssid"))
            elif c.ap_mac and d.get("ap_mac") and c.ap_mac != d["ap_mac"]:
                c.roams = (c.roams or 0) + 1
                frm = aps.get(c.ap_mac)
                to = aps.get(d["ap_mac"])
                out.ev("client_roam", "informational", f"client {m} roamed {frm.name if frm else c.ap_mac} → {to.name if to else d['ap_mac']}"
                       " (inferred from consecutive polls)", ap_id=ap_id, client_mac=m, client=True, from_ap=c.ap_mac, to_ap=d["ap_mac"],
                       from_ap_id=frm.id if frm else None, to_ap_id=ap_id, from_band=c.band, to_band=d.get("band"),
                       controller_prev_ap=d.get("roam_from") or None, measured=False)
            for k in ("ip", "ap_mac", "slot", "band", "protocol", "ssid", "wlan_profile", "vlan", "channel", "status", "auth_mode", "reason",
                      "rssi_dbm", "snr_db", "tx_rate_mbps", "session_s", "rx_bytes", "tx_bytes", "sources"):
                setattr(c, k, d.get(k) if d.get(k) is not None else ([] if k == "sources" else "" if k in ("ip", "ap_mac", "band", "protocol", "ssid",
                                                                                                                 "wlan_profile", "status", "auth_mode", "reason") else None))
            c.username = (d.get("username") or "")[:128]
            c.ap_id = ap_id
            c.present, c.last_seen = True, now
            out.samples.append({"ts": now, "wlc_id": sw.id, "mac": m, "ap_id": ap_id or 0, "slot": d.get("slot") if d.get("slot") is not None else -1,
                                "ssid": d.get("ssid") or "", "band": d.get("band") or "", "rssi_dbm": d.get("rssi_dbm"), "snr_db": d.get("snr_db"),
                                "tx_rate_mbps": d.get("tx_rate_mbps"), "rx_bytes": d.get("rx_bytes"), "tx_bytes": d.get("tx_bytes"),
                                "source": "+".join(d.get("sources") or [])})
        if table_ok and not data.get("wireless_client_truncated"):
            for m, c in known.items():
                if m not in cur:
                    c.present = False
                    c.disconnects = (c.disconnects or 0) + 1
                    out.ev("client_disconnected", "informational", f"client {m} no longer listed by the controller"
                           + (f" (last reason {c.reason})" if c.reason else ""), ap_id=c.ap_id, client_mac=m, client=True, last_ap=c.ap_mac,
                           reason=c.reason or None)
        if out.client_events > MAX_CLIENT_EVENTS:
            out.ev("client_churn", "informational", f"{out.client_events} client association changes in one poll; {MAX_CLIENT_EVENTS} recorded individually")
        out.m("wireless_wlc_client_count", len(cur), source="+".join(sorted({x for d in cur.values() for x in d.get("sources", [])})))
        # per-AP / per-WLAN counts when the controller did not report them
        per_ap: dict[int, int] = {}
        per_ssid: dict[str, int] = {}
        for d in cur.values():
            if ap_mac_id.get(d.get("ap_mac", "")):
                per_ap[ap_mac_id[d["ap_mac"]]] = per_ap.get(ap_mac_id[d["ap_mac"]], 0) + 1
            per_ssid[d.get("ssid") or ""] = per_ssid.get(d.get("ssid") or "", 0) + 1
        health["client_counts_derived"] = {"per_ap": True}
        for a in aps.values():
            if a.clients is None and a.present:
                a.clients = per_ap.get(a.id, 0)
        for w in wlans.values():
            if w.clients is None and w.present:
                w.clients = per_ssid.get(w.ssid, 0)
        health["clients_truncated"] = bool(data.get("wireless_client_truncated"))
    # ---------------------------------------------------------------- controller summary
    present = [a for a in aps.values() if a.present or a.state == "down"]
    health.update(aps=len(present), aps_up=sum(1 for a in present if a.state == "up"), aps_down=sum(1 for a in present if a.state == "down"),
                  aps_degraded=sum(1 for a in present if a.state == "degraded"), wlans=sum(1 for w in wlans.values() if w.present),
                  updated_at=now.isoformat())
    if "wireless_client" in ran and data.get("wireless_clients") is not None:
        health["clients"] = len(data["wireless_clients"])
    holder["wireless"] = health
    if sw_health is None:
        sw.health = holder
    out.m("wireless_wlc_ap_count", health["aps"], source=SRC_BSN)
    out.m("wireless_wlc_aps_up", health["aps_up"], source=SRC_BSN)
    out.m("wireless_wlc_up", 1, source="SNMPv2-MIB")
    out.m("wireless_wlc_cpu_percent", sw.cpu_pct, source="CISCO-PROCESS-MIB")
    out.m("wireless_wlc_memory_percent", sw.mem_pct, source="CISCO-MEMORY-POOL-MIB")
    await s.flush()
    try:
        if out.metrics:
            await ch.ainsert("wireless_metrics", out.metrics, METRIC_COLS)
        if out.rf_rows:
            await ch.ainsert("rf_telemetry", out.rf_rows, RF_COLS)
        if out.samples:
            await ch.ainsert("wireless_client_samples", out.samples, CLIENT_COLS)
    except Exception:  # history is best effort; inventory and state are already in the session
        log.exception("storing wireless metrics failed for %s", sw.name)
    return {"events": len(out.events), "metrics": len(out.metrics), "client_samples": len(out.samples)}


async def housekeeping(s: AsyncSession, now: datetime | None = None, events_days: int = 30, clients_days: int = 7) -> None:
    now = now or datetime.now(timezone.utc)
    await s.execute(delete(WirelessEvent).where(WirelessEvent.at < now - timedelta(days=events_days)))
    await s.execute(delete(WirelessClient).where(WirelessClient.present.is_(False), WirelessClient.last_seen < now - timedelta(days=clients_days)))
    await s.commit()

