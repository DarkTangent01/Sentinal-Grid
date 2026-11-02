"""RF analytics: explainable, rule-based findings over collected controller telemetry (docs/WIRELESS.md, RF section).

Every finding names the radio, band, channel, frequency, the observed value, the threshold, how long the condition has
held (from the rf_telemetry history), a comparison with the radio's own 7-day baseline, the supporting evidence and a
confidence level. Nothing is inferred from missing data: a rule that lacks its inputs produces no finding, and the
`coverage` block reports which inputs were unavailable.

Interference is never diagnosed from equal channel numbers alone. Co-/adjacent-channel findings require (1) an RRM
neighbour the radio actually hears at or above an RSSI threshold, (2) spectral overlap computed from both radios' channel
and width (app/wireless/rf.py), and (3) an elevated channel utilisation or 802.11 interference measurement on the radio.

Root-cause text comes from a pluggable provider (RCA_PROVIDERS). Only the rule-based provider exists; an AI provider must
take the same finding + collected telemetry and may not add facts that are not in it.
"""
from __future__ import annotations

import statistics
from datetime import datetime, timedelta, timezone
from typing import Protocol

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import Switch, WirelessAp, WirelessClient, WirelessEvent, WirelessRadio
from . import rf as RF
from .service import thresholds, util_limit

RULES = ("high_channel_utilization", "channel_contention", "cochannel_interference", "adjacent_channel_interference", "high_noise",
         "poor_client_snr", "excessive_retries", "uneven_client_distribution", "repeated_channel_changes", "radio_failure")
SEV = {"high_channel_utilization": "medium", "channel_contention": "medium", "cochannel_interference": "medium", "adjacent_channel_interference": "low",
       "high_noise": "medium", "poor_client_snr": "low", "excessive_retries": "medium", "uneven_client_distribution": "low",
       "repeated_channel_changes": "low", "radio_failure": "high"}
METRIC_OF = {"high_channel_utilization": "channel_util_pct", "high_noise": "noise_dbm", "excessive_retries": "retry_pct",
             "channel_contention": "channel_util_pct"}


def _aware(v):
    if isinstance(v, str):
        v = datetime.fromisoformat(v.replace(" ", "T"))
    return v if v is None or v.tzinfo else v.replace(tzinfo=timezone.utc)


class RcaProvider(Protocol):
    name: str

    def explain(self, finding: dict) -> dict: ...


class RuleBasedRca:
    """Possible causes and next steps per rule. Text is generic guidance, qualified by the finding's own evidence."""
    name = "rules"
    CAUSES = {
        "high_channel_utilization": (["High client load or heavy traffic on this radio", "Many overlapping BSSIDs / SSIDs on the channel",
                                      "Neighbouring APs (own or foreign) sharing the channel", "Wide channel on a congested band"],
                                     ["Compare channel utilisation with the radio's own Tx/Rx utilisation (own traffic vs others)",
                                      "Review the RRM neighbour list for APs on the same channel", "Check the number of SSIDs broadcast on this radio",
                                      "Consider client load balancing or band steering (change on the controller, not here)"]),
        "channel_contention": (["Airtime is consumed by other transmitters (neighbouring APs or foreign networks) rather than this AP's own traffic"],
                               ["Inspect co-channel neighbours and 802.11 interference measurements", "Check for foreign networks on the channel",
                                "Review DCA channel plan and channel width for the area"]),
        "cochannel_interference": (["Another AP radio heard at high signal strength occupies overlapping spectrum"],
                                   ["Confirm both radios' channels and widths in RF & Frequency → Radio details",
                                    "Review transmit power / RRM TPC on the overlapping radios", "Review DCA channel assignment and channel width"]),
        "adjacent_channel_interference": (["A neighbouring radio on a partially overlapping channel is heard strongly (non-aligned bonding or 2.4 GHz "
                                           "channels closer than 5 apart)"],
                                          ["Use a non-overlapping channel plan (2.4 GHz: 1/6/11)", "Align bonded channel blocks between neighbours"]),
        "high_noise": (["Non-802.11 energy (microwave ovens, cameras, Bluetooth, industrial equipment) or a faulty radio"],
                       ["Use spectrum analysis (CleanAir) on the AP to identify the source; SNMP does not identify non-Wi-Fi interferers",
                        "Compare with neighbouring APs: a single radio with high noise suggests a local source or hardware fault"]),
        "poor_client_snr": (["Clients far from the AP or behind obstructions", "Raised noise floor on the channel", "Coverage hole"],
                            ["Check client RSSI alongside SNR (RSSI good + SNR poor = noise)", "Review coverage and transmit power in the area"]),
        "excessive_retries": (["Contention or interference on the channel", "Clients with poor signal", "Hidden-node collisions"],
                              ["Correlate with channel utilisation, interference and client SNR on this radio",
                               "Check whether retries concentrate on a few clients"]),
        "uneven_client_distribution": (["Clients sticky to one AP", "Neighbouring radios with lower power or disabled", "AP placement"],
                                       ["Compare transmit power of this radio and its neighbours", "Review load balancing / band steering"]),
        "repeated_channel_changes": (["DFS radar detections on 5 GHz", "DCA reacting to persistent interference", "Unstable static configuration"],
                                     ["Review RF events: radar detections and change reasons", "Review DCA sensitivity and anchor time on the controller"]),
        "radio_failure": (["Radio administratively up but operationally down", "Repeated radio link changes (resets)", "Power budget (PoE) limits"],
                          ["Check the AP's power status and switch port PoE", "Review AP events and the controller log for radio resets"]),
    }

    def explain(self, finding: dict) -> dict:
        causes, steps = self.CAUSES.get(finding["rule"], ([], []))
        return {"engine": self.name, "possible_causes": causes, "steps": steps}


RCA_PROVIDERS: dict[str, RcaProvider] = {"rules": RuleBasedRca()}


async def _history(ch, radio_ids: list[int], now: datetime, minutes: int) -> tuple[dict, dict]:
    """(window samples {(radio_id, metric): [(ts, value)]}, 7-day baseline {(radio_id, metric): avg}) from rf_telemetry."""
    if ch is None or not radio_ids:
        return {}, {}
    try:
        rows = await ch.aquery("SELECT radio_id, metric, groupArray(ts) AS o_t, groupArray(value) AS o_v FROM rf_telemetry WHERE ts >= {t0:DateTime64(3)} "
                               "AND status = 'ok' AND radio_id IN {r:Array(UInt32)} AND metric IN {m:Array(String)} GROUP BY radio_id, metric",
                               {"t0": now - timedelta(minutes=minutes), "r": radio_ids, "m": ["channel_util_pct", "noise_dbm", "retry_pct", "tx_util_pct",
                                                                                              "rx_util_pct", "interference_pct"]})
        base = await ch.aquery("SELECT radio_id, metric, avg(value) AS o_avg, count() AS o_n FROM rf_telemetry WHERE ts >= {t0:DateTime64(3)} "
                               "AND ts < {t1:DateTime64(3)} AND status = 'ok' AND radio_id IN {r:Array(UInt32)} GROUP BY radio_id, metric",
                               {"t0": now - timedelta(days=7), "t1": now - timedelta(minutes=minutes), "r": radio_ids})
    except Exception:
        return {}, {}
    win = {(int(r["radio_id"]), r["metric"]): sorted((_aware(t), v) for t, v in zip(r["o_t"], r["o_v"])) for r in rows}
    bl = {(int(r["radio_id"]), r["metric"]): (round(float(r["o_avg"]), 1), int(r["o_n"])) for r in base}
    return win, bl


def _persist(samples: list, bad, frac: float) -> tuple[bool | None, datetime | None, int, int]:
    """(persistent?, first bad ts of the current run, bad, total). None when there is no history to judge."""
    if not samples:
        return None, None, 0, 0
    flags = [bad(v) for _, v in samples]
    first = None
    for (t, _), f in zip(reversed(samples), reversed(flags)):
        if not f:
            break
        first = t
    nbad = sum(flags)
    return (nbad / len(samples) >= frac and flags[-1]), first, nbad, len(samples)


async def analyze(s: AsyncSession, ch=None, *, site: str | None = None, wlc_ids: list[int] | None = None, ap_id: int | None = None,
                  band: str | None = None, now: datetime | None = None, engine: str = "rules") -> dict:
    now = now or datetime.now(timezone.utc)
    rca = RCA_PROVIDERS[engine]
    wlcs = {w.id: w for w in (await s.execute(select(Switch).where(func.lower(Switch.role) == "wlc"))).scalars()}
    q = select(WirelessRadio).where(WirelessRadio.present.is_(True))
    if wlc_ids:
        q = q.where(WirelessRadio.wlc_id.in_(wlc_ids))
    if ap_id:
        q = q.where(WirelessRadio.ap_id == ap_id)
    radios = [r for r in (await s.execute(q)).scalars() if r.wlc_id in wlcs]
    aps = {a.id: a for a in (await s.execute(select(WirelessAp).where(WirelessAp.id.in_({r.ap_id for r in radios} or {0})))).scalars()}
    if site:
        radios = [r for r in radios if aps.get(r.ap_id) and aps[r.ap_id].site == site]
    if band:
        radios = [r for r in radios if r.band == band]
    all_radios = {(r.ap_id, r.slot): r for r in (await s.execute(select(WirelessRadio).where(WirelessRadio.present.is_(True)))).scalars()}
    by_mac_ap = {a.mac: a for a in (await s.execute(select(WirelessAp))).scalars()}
    persist_min = max(int(thresholds(w)["rf_persistence_minutes"]) for w in wlcs.values()) if wlcs else 15
    win, base = await _history(ch, [r.id for r in radios], now, persist_min)
    clients = list((await s.execute(select(WirelessClient).where(WirelessClient.present.is_(True),
                                                                 WirelessClient.ap_id.in_({r.ap_id for r in radios} or {0})))).scalars())
    cl_by: dict[tuple, list] = {}
    for c in clients:
        cl_by.setdefault((c.ap_id, c.slot), []).append(c)
    since = now - timedelta(hours=24)
    ev_counts: dict[tuple, dict] = {}
    for e in (await s.execute(select(WirelessEvent).where(WirelessEvent.at >= since, WirelessEvent.kind.in_(("channel_change", "radio_link_change", "dfs_radar")),
                                                          WirelessEvent.ap_id.in_({r.ap_id for r in radios} or {0})))).scalars():
        comp = (e.component or "").rsplit("/", 1)
        slot = int(comp[1]) if len(comp) == 2 and comp[1].isdigit() else None
        d = ev_counts.setdefault((e.ap_id, slot), {})
        d[e.kind] = d.get(e.kind, 0) + (e.data or {}).get("count", 1) if e.kind == "radio_link_change" else d.get(e.kind, 0) + 1
    findings: list[dict] = []
    gaps = {"no_history": 0, "no_neighbors": 0, "no_noise": 0, "no_util": 0, "no_retry": 0}

    def base_of(r, metric):
        b = base.get((r.id, metric))
        return {"avg_7d": b[0], "samples_7d": b[1]} if b else {"avg_7d": None, "samples_7d": 0}

    def make(r, rule, title, observed, threshold, unit, evidence, confidence, *, first=None, persistence=None, metric=None, extra=None):
        a = aps.get(r.ap_id)
        f = {"id": f"{rule}:{r.id}", "rule": rule, "title": title, "severity": SEV[rule], "confidence": confidence,
             "site": a.site if a else "", "wlc_id": r.wlc_id, "wlc": wlcs[r.wlc_id].name, "ap_id": r.ap_id, "ap": a.name if a else "",
             "radio_id": r.id, "slot": r.slot, "band": r.band, "channel": r.channel, "width_mhz": r.channel_width_mhz,
             "frequency_mhz": r.frequency_mhz, "center_frequency_mhz": r.center_frequency_mhz, "dfs": r.dfs,
             "observed": {"metric": metric, "value": observed, "unit": unit}, "threshold": threshold,
             "since": first.isoformat() if first else None, "duration_s": int((now - first).total_seconds()) if first else None,
             "persistence": persistence, "history": base_of(r, metric) if metric else None, "evidence": evidence, **(extra or {})}
        f.update(rca.explain(f))
        findings.append(f)

    for r in radios:
        a = aps.get(r.ap_id)
        if a is None or a.state in ("maintenance",) or r.state == "disabled":
            continue
        t = thresholds(wlcs[r.wlc_id])
        frac = float(t["rf_persistence_fraction"])
        lim = util_limit(t, r.band)
        # 1 / 2 utilisation and contention
        if r.channel_util_pct is None:
            gaps["no_util"] += 1
        else:
            sm = win.get((r.id, "channel_util_pct"), [])
            ok, first, nbad, n = _persist(sm, lambda v: v >= lim, frac)
            if not sm:
                gaps["no_history"] += 1
            if r.channel_util_pct >= lim and ok is not False:
                make(r, "high_channel_utilization", f"Channel utilisation {r.channel_util_pct:.0f}% on {a.name} radio {r.slot}", r.channel_util_pct, lim, "%",
                     [f"bsnAPIfLoadChannelUtilization = {r.channel_util_pct:.0f}% (threshold {lim:.0f}% for {r.band or '?'} GHz)",
                      f"{nbad} of {n} samples ≥ threshold in the last {t['rf_persistence_minutes']} min" if n else "no history yet: persistence not established"],
                     "high" if ok else "low", first=first, persistence={"bad": nbad, "samples": n, "window_min": t["rf_persistence_minutes"]},
                     metric="channel_util_pct")
            if r.tx_util_pct is not None and r.rx_util_pct is not None:
                others = r.channel_util_pct - r.tx_util_pct - r.rx_util_pct
                if r.channel_util_pct >= lim - 10 and others >= float(t["contention_pct"]):
                    make(r, "channel_contention", f"{others:.0f}% of airtime on {a.name} radio {r.slot} is used by other transmitters",
                         round(others, 1), t["contention_pct"], "%",
                         [f"channel utilisation {r.channel_util_pct:.0f}% − own Tx {r.tx_util_pct:.0f}% − own Rx {r.rx_util_pct:.0f}% = {others:.0f}%"],
                         "medium", metric="channel_util_pct")
        # 3 / 4 co- and adjacent-channel (RF proximity + overlap + measured impact)
        if not r.neighbors:
            gaps["no_neighbors"] += 1
        my_span = RF.span_mhz(r.band, r.channel, r.channel_width_mhz)
        impact = (r.channel_util_pct is not None and r.channel_util_pct >= lim * 0.8) or (r.interference_pct is not None and r.interference_pct >= t["interference_pct"])
        if r.neighbors and my_span and impact:
            co, adj = [], []
            for n in r.neighbors:
                if n.get("rssi_dbm") is None or n.get("channel") is None:
                    continue
                na = by_mac_ap.get(n["mac"])
                nr = all_radios.get((na.id, n["slot"])) if na and n.get("slot") is not None else None
                nwidth = nr.channel_width_mhz if nr and nr.channel == n["channel"] else n.get("width_mhz")
                nspan = RF.span_mhz(r.band, n["channel"], nwidth)
                ov = RF.overlap_mhz(my_span, nspan)
                if not ov:
                    continue
                row = {"neighbor": n.get("ap_name") or n["mac"], "neighbor_ap_id": n.get("ap_id"), "slot": n.get("slot"), "channel": n["channel"],
                       "width_mhz": nwidth, "rssi_dbm": n["rssi_dbm"], "overlap_mhz": ov}
                full = ov >= min(my_span[1] - my_span[0], nspan[1] - nspan[0])   # the narrower channel lies entirely inside the other
                if full and n["rssi_dbm"] >= t["cochannel_rssi_dbm"]:
                    co.append(row)
                elif not full and n["rssi_dbm"] >= t["adjacent_rssi_dbm"]:
                    adj.append(row)
            meas = (f"channel utilisation {r.channel_util_pct:.0f}%" if r.channel_util_pct is not None else "") + \
                   (f", 802.11 interference {r.interference_pct:.0f}%" if r.interference_pct is not None else "")
            if co:
                strongest = max(x["rssi_dbm"] for x in co)
                make(r, "cochannel_interference", f"{len(co)} co-channel neighbour(s) heard by {a.name} radio {r.slot} on channel {r.channel}",
                     strongest, t["cochannel_rssi_dbm"], "dBm",
                     [f"RRM neighbour {x['neighbor']} on channel {x['channel']}"
                      f"{' / ' + str(x['width_mhz']) + ' MHz' if x['width_mhz'] else ''} heard at {x['rssi_dbm']} dBm, {x['overlap_mhz']} MHz overlap" for x in co[:10]]
                     + [f"measured impact: {meas}"], "high" if strongest >= -67 and r.channel_util_pct is not None and r.channel_util_pct >= lim else "medium",
                     metric=None, extra={"neighbors": co[:20]})
            if adj:
                strongest = max(x["rssi_dbm"] for x in adj)
                make(r, "adjacent_channel_interference", f"{len(adj)} partially overlapping neighbour(s) heard by {a.name} radio {r.slot}", strongest,
                     t["adjacent_rssi_dbm"], "dBm",
                     [f"RRM neighbour {x['neighbor']} on channel {x['channel']} (this radio: {r.channel}) heard at {x['rssi_dbm']} dBm, "
                      f"{x['overlap_mhz']} MHz partial overlap" for x in adj[:10]] + [f"measured impact: {meas}"], "medium", extra={"neighbors": adj[:20]})
        # 5 noise
        if r.noise_dbm is None:
            gaps["no_noise"] += 1
        elif r.noise_dbm >= t["noise_dbm"]:
            sm = win.get((r.id, "noise_dbm"), [])
            ok, first, nbad, n = _persist(sm, lambda v: v >= t["noise_dbm"], frac)
            if ok is not False:
                make(r, "high_noise", f"Noise floor {r.noise_dbm:.0f} dBm on {a.name} radio {r.slot}", r.noise_dbm, t["noise_dbm"], "dBm",
                     [f"bsnAPIfDBNoisePower on channel {r.channel} = {r.noise_dbm:.0f} dBm (threshold {t['noise_dbm']} dBm)",
                      f"{nbad} of {n} samples ≥ threshold" if n else "no history yet: persistence not established"],
                     "high" if ok else "low", first=first, persistence={"bad": nbad, "samples": n}, metric="noise_dbm")
        # 6 client SNR
        cs = [c for c in cl_by.get((r.ap_id, r.slot), []) if c.snr_db is not None]
        poor = [c for c in cs if c.snr_db <= t["snr_poor_db"]]
        if cs and len(poor) >= int(t["poor_snr_min_clients"]):
            make(r, "poor_client_snr", f"{len(poor)} of {len(cs)} clients on {a.name} radio {r.slot} report SNR ≤ {t['snr_poor_db']} dB", len(poor),
                 t["poor_snr_min_clients"], "clients",
                 [f"client {c.mac}: SNR {c.snr_db:.0f} dB" + (f", RSSI {c.rssi_dbm:.0f} dBm" if c.rssi_dbm is not None else "") for c in poor[:10]],
                 "high" if len(poor) >= len(cs) / 2 else "medium", extra={"clients_measured": len(cs)})
        # 7 retries
        if r.retry_pct is None:
            gaps["no_retry"] += 1
        elif r.retry_pct >= t["retry_pct"]:
            sm = win.get((r.id, "retry_pct"), [])
            ok, first, nbad, n = _persist(sm, lambda v: v >= t["retry_pct"], frac)
            if ok is not False:
                make(r, "excessive_retries", f"{r.retry_pct:.1f}% of frames retried on {a.name} radio {r.slot}", r.retry_pct, t["retry_pct"], "%",
                     [f"bsnAPIfDot11RetryCount / TransmittedFrameCount over the last interval = {r.retry_pct:.1f}%",
                      f"{nbad} of {n} samples ≥ threshold" if n else "no history yet: persistence not established"],
                     "high" if ok else "low", first=first, persistence={"bad": nbad, "samples": n}, metric="retry_pct")
        # 9 channel changes
        ec = ev_counts.get((r.ap_id, r.slot), {})
        if ec.get("channel_change", 0) >= int(t["channel_changes_per_day"]):
            make(r, "repeated_channel_changes", f"{ec['channel_change']} channel changes in 24 h on {a.name} radio {r.slot}", ec["channel_change"],
                 t["channel_changes_per_day"], "changes/24h",
                 [f"{ec['channel_change']} channel_change events in 24 h", f"{ec.get('dfs_radar', 0)} DFS radar detection(s) in 24 h",
                  f"channel assignment: {r.channel_assignment or 'not reported'}"], "high")
        # 10 radio failure
        if r.state == "down" and r.admin_enabled is not False and a.state in ("up", "degraded"):
            since_t = _aware(r.state_since)
            make(r, "radio_failure", f"{a.name} radio {r.slot} is down while administratively enabled", "down", "up", "",
                 [f"bsnAPIfOperStatus = down, bsnAPIfAdminStatus = enable, AP state {a.state}"], "high", first=since_t)
        elif ec.get("radio_link_change", 0) >= int(t["link_changes_per_day"]):
            make(r, "radio_failure", f"{ec['radio_link_change']} radio link changes in 24 h on {a.name} radio {r.slot}", ec["radio_link_change"],
                 t["link_changes_per_day"], "changes/24h", [f"cLApDot11IfLinkChangeCount increased {ec['radio_link_change']} time(s) in 24 h"], "medium")
    # 8 uneven distribution (per site and band, among radios that hear each other)
    groups: dict[tuple, list] = {}
    for r in radios:
        a = aps.get(r.ap_id)
        if a and r.clients is not None and r.state == "up":
            groups.setdefault((a.site, r.band), []).append(r)
    for (_site, _band), rs in groups.items():
        if len(rs) < 3:
            continue
        med = statistics.median([x.clients for x in rs])
        for r in rs:
            t = thresholds(wlcs[r.wlc_id])
            if r.clients < int(t["uneven_min_clients"]) or r.clients < float(t["uneven_ratio"]) * max(med, 1):
                continue
            light = []
            for n in r.neighbors or []:
                na = by_mac_ap.get(n.get("mac"))
                nr = all_radios.get((na.id, n.get("slot"))) if na else None
                if nr and nr.band == r.band and nr.clients is not None and n.get("rssi_dbm") is not None and n["rssi_dbm"] >= -70 \
                        and nr.clients <= r.clients / float(t["uneven_ratio"]):
                    light.append(f"{na.name} radio {nr.slot}: {nr.clients} clients, heard at {n['rssi_dbm']} dBm")
            if light:
                make(r, "uneven_client_distribution", f"{aps[r.ap_id].name} radio {r.slot} serves {r.clients} clients (site/band median {med:g})",
                     r.clients, round(float(t["uneven_ratio"]) * max(med, 1), 1), "clients",
                     [f"{r.clients} clients vs median {med:g} across {len(rs)} radios ({_band} GHz)"] + light[:8], "medium")
    findings.sort(key=lambda f: (["high", "medium", "low"].index(f["severity"]) if f["severity"] in ("high", "medium", "low") else 3,
                                 ["high", "medium", "low"].index(f["confidence"]), f["ap"], f["slot"]))
    return {"generated_at": now.isoformat(), "engine": rca.name, "findings": findings, "radios_evaluated": len(radios),
            "coverage": {"radios_without_history": gaps["no_history"], "radios_without_neighbor_data": gaps["no_neighbors"],
                         "radios_without_noise": gaps["no_noise"], "radios_without_utilization": gaps["no_util"],
                         "radios_without_retry_rate": gaps["no_retry"]},
            "counts": {k: sum(1 for f in findings if f["rule"] == k) for k in RULES}}
