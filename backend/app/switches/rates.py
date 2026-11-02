"""Counter deltas, rates and utilisation from successive SNMP samples.

Rates are always delta / elapsed between two valid samples, never derived from cumulative values. A delta is refused
(no rate for that interval, no false spike) when:
  * the switch restarted (sysUpTime went backwards) or ifCounterDiscontinuityTime changed,
  * the ifIndex now names a different interface (index renumbering after a reload or module change),
  * a 64-bit counter decreased (a reset: 64-bit counters do not wrap in practice),
  * a 32-bit counter decreased and the wrap-corrected delta would exceed the interface speed (a reset, not a wrap),
  * the resulting rate exceeds 1.5 × the interface speed (implausible: counter reset or speed change mid-interval).
Samples taken across a data gap (elapsed > max_gap) still produce an average rate but are flagged GAP so threshold
alerts ignore them.
"""
from __future__ import annotations

WRAP32 = 2 ** 32
# flags stored with every interface sample
GAP, UNCERTAIN_UTIL, COUNTER32, RESET, NO_SPEED = 1, 2, 4, 8, 16
VIRTUAL_TYPES = {1, 24, 53, 131, 135, 136, 150, 166}   # other, loopback, propVirtual, tunnel, l2vlan, l3ipvlan, mplsTunnel, mpls
PHYSICAL_TYPES = {6, 7, 62, 69, 117, 26}                # ethernetCsmacd, iso88023, fastEther, fastEtherFX, gigabitEthernet, ethernet3Mbit
LAG_TYPE = 161


def counter_delta(prev: int | None, cur: int | None, bits: int, elapsed: float, max_rate: float | None = None) -> tuple[int | None, str]:
    """Delta between two raw counter readings. max_rate is in counter units per second (bytes/s for octets)."""
    if prev is None or cur is None:
        return None, "no previous sample"
    if elapsed <= 0:
        return None, "non-positive interval"
    if cur >= prev:
        d = cur - prev
    elif bits == 32:
        d = cur + WRAP32 - prev
        if max_rate is not None and d / elapsed > max_rate * 1.1:
            return None, "counter reset"
    else:
        return None, "counter reset"
    if max_rate is not None and max_rate > 0 and d / elapsed > max_rate * 1.5:
        return None, "implausible rate (counter reset or speed change)"
    return d, ""


def speed_of(high_speed_mbps: int | None, if_speed: int | None) -> tuple[int | None, str]:
    """Interface speed in bit/s and its source. ifSpeed saturates at 4294967295 for > 4 Gbit/s links."""
    if high_speed_mbps:
        return int(high_speed_mbps) * 1_000_000, "ifHighSpeed"
    if if_speed and if_speed < 4294967295:
        return int(if_speed), "ifSpeed"
    if if_speed == 4294967295:
        return None, "ifSpeed saturated, no ifHighSpeed"
    return None, "speed not reported"


def interface_rates(prev: dict | None, cur: dict, *, elapsed: float, uptime_prev: int | None, uptime_cur: int | None,
                    max_gap: float) -> dict:
    """prev / cur: {'name', 'type', 'oper', 'speed_bps', 'disc', 'hc': bool, 'c': {counter: value}} for one ifIndex.

    Returns {'rx_bps', 'tx_bps', 'rx_pps', 'tx_pps', 'rx_util', 'tx_util', 'in_errors', 'out_errors', 'in_discards',
             'out_discards', 'crc', 'flags', 'reason'} with None for anything that cannot be computed."""
    out = {k: None for k in ("rx_bps", "tx_bps", "rx_pps", "tx_pps", "rx_util", "tx_util", "in_errors", "out_errors",
                             "in_discards", "out_discards", "crc")}
    flags = 0
    if not cur.get("hc"):
        flags |= COUNTER32
    if prev is None:
        out.update(flags=flags, reason="first sample")
        return out
    reason = ""
    if uptime_prev is not None and uptime_cur is not None and uptime_cur < uptime_prev:
        reason = "switch restarted (sysUpTime decreased)"
    elif prev.get("disc") is not None and cur.get("disc") is not None and prev["disc"] != cur["disc"]:
        reason = "counter discontinuity (ifCounterDiscontinuityTime changed)"
    elif prev.get("name") and cur.get("name") and prev["name"] != cur["name"]:
        reason = f"ifIndex now names {cur['name']} (was {prev['name']})"
    elif bool(prev.get("hc")) != bool(cur.get("hc")):
        reason = "counter width changed"
    if reason:
        out.update(flags=flags | RESET, reason=reason)
        return out
    if elapsed > max_gap:
        flags |= GAP
    bits = 64 if cur.get("hc") else 32
    speed = cur.get("speed_bps")
    byte_rate = speed / 8 if speed else None
    pc, cc = prev.get("c") or {}, cur.get("c") or {}

    def d(name, max_rate=None, b=bits):
        v, why = counter_delta(pc.get(name), cc.get(name), b, elapsed, max_rate)
        return v, why

    rx, why_rx = d("in_octets", byte_rate)
    tx, why_tx = d("out_octets", byte_rate)
    if rx is not None:
        out["rx_bps"] = rx * 8 / elapsed
    if tx is not None:
        out["tx_bps"] = tx * 8 / elapsed
    if (why_rx == "counter reset") or (why_tx == "counter reset"):
        flags |= RESET
    # a packet is at least 64 bytes: max packet rate ≈ speed / 512 (+ slack)
    pkt_max = speed / 512 if speed else None
    for name, key in (("in_pkts", "rx_pps"), ("out_pkts", "tx_pps")):
        v, _ = d(name, pkt_max)
        if v is not None:
            out[key] = v / elapsed
    # error / discard counters are 32-bit in IF-MIB; report per-interval increments
    for name in ("in_errors", "out_errors", "in_discards", "out_discards", "crc"):
        v, _ = d(name, pkt_max, 32)
        if v is not None:
            out[name] = v
    if bits == 32 and speed and speed / 8 * elapsed >= WRAP32:
        flags |= UNCERTAIN_UTIL  # a 32-bit octet counter can wrap more than once in this interval
    util_ok = cur.get("type") not in VIRTUAL_TYPES and speed
    if not speed:
        flags |= NO_SPEED
    elif cur.get("type") in VIRTUAL_TYPES:
        flags |= UNCERTAIN_UTIL
    if util_ok:
        for k_bps, k_util in (("rx_bps", "rx_util"), ("tx_bps", "tx_util")):
            if out[k_bps] is not None:
                u = 100.0 * out[k_bps] / speed
                if u > 105:
                    out[k_util] = None
                    flags |= UNCERTAIN_UTIL
                else:
                    out[k_util] = min(u, 100.0)
    out.update(flags=flags, reason=why_rx or why_tx or "")
    return out


def flag_names(flags: int) -> list[str]:
    return [n for b, n in ((GAP, "gap"), (UNCERTAIN_UTIL, "uncertain_utilization"), (COUNTER32, "32bit_counters"),
                           (RESET, "counter_reset"), (NO_SPEED, "speed_unknown")) if flags & b]
