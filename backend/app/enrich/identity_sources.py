"""Sentinel Grid identity contributors (app/platform/identity.py registry): what the security logs know about hosts.

  fortigate  traffic logs with device detection: srcmac, srchwvendor, devtype, osname, srcname per source address. Most
             srcmac values are the last router / AP in front of the FortiGate: a MAC behind several addresses, or one
             FortiGate itself types "Router", is never bound to an address as a host.
  vpn        VPN logins: the tunnel address assigned to a user (and the user's public address)
  windows    successful Windows logons: workstation address ↔ account
  dhcp       DHCP leases from FortiGate DHCP logs or Zeek dhcp.log: address ↔ MAC ↔ host name
Every query reads at most one window (since the previous pass, capped at 10 minutes for raw-log extraction).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from ..platform.eventquery import table
from ..platform.identity import Observations, is_unicast_host_mac, norm_mac, register_contributor, router_macs

RAW_WINDOW = timedelta(minutes=10)


def _t(v) -> datetime:
    t = v if isinstance(v, datetime) else datetime.fromisoformat(str(v).replace("Z", ""))
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _kv(field: str) -> str:
    """ClickHouse expression extracting key=value / key="value" from a FortiGate raw line."""
    return f"extract(raw, '{field}=\"?([^\" ]+)')" if field in ("srcmac", "devtype") else f"extract(raw, '{field}=\"([^\"]*)\"')"


async def fortigate(ch, s: AsyncSession, since: datetime, now: datetime) -> Observations:
    o = Observations()
    since = max(since, now - RAW_WINDOW)
    rows = await ch.aquery(
        f"SELECT src_ip AS ip, {_kv('srcmac')} AS mac, any({_kv('srchwvendor')}) AS vendor, any({_kv('devtype')}) AS devtype, "
        f"any({_kv('osname')}) AS os, any({_kv('srcname')}) AS name, max(event_time) AS t FROM {table()} "
        "WHERE event_time >= {a:DateTime64(3)} AND event_time < {b:DateTime64(3)} AND category = 'traffic' AND position(raw, 'srcmac=') > 0 "
        "GROUP BY ip, mac LIMIT 200000", {"a": since, "b": now})
    pairs = [(r["ip"], norm_mac(r["mac"])) for r in rows]
    routers = router_macs([(ip, m) for ip, m in pairs if m])
    for r, (ip, mac) in zip(rows, pairs):
        if not mac or not is_unicast_host_mac(mac):
            continue
        router = mac in routers or (r["devtype"] or "").strip('"').lower() == "router"
        d = o.device(mac)
        if r["vendor"]:
            d.update(vendor=r["vendor"].strip('"'), vendor_source="fortigate")
        d.setdefault("sources", set()).add("fortigate")
        if router:
            d["inventory"] = "Network equipment"
            continue
        d.update(fortigate_devtype=(r["devtype"] or "").strip('"'), os=r["os"] or "", seen=_t(r["t"]))
        if r["name"]:
            d.update(hostname=r["name"], hostname_source="fortigate")
        o.ip_mac.append((ip, mac, "fortigate", _t(r["t"])))
    return o


async def vpn(ch, s: AsyncSession, since: datetime, now: datetime) -> Observations:
    o = Observations()
    rows = await ch.aquery(
        f"SELECT user AS u, src_ip AS remote, any(extract(raw, 'tunnelip=\"?([0-9a-fA-F.:]+)')) AS tunnel, max(event_time) AS t FROM {table()} "
        "WHERE event_time >= {a:DateTime64(3)} AND event_time < {b:DateTime64(3)} AND event_subtype = 'vpn' AND user != '' GROUP BY u, remote LIMIT 20000",
        {"a": since, "b": now})
    for r in rows:
        t = _t(r["t"])
        if r["tunnel"] and r["tunnel"] not in ("0.0.0.0", "N/A"):
            o.ip_user.append((r["tunnel"], r["u"], "vpn", t))
        if r["remote"]:
            o.ip_user.append((r["remote"], r["u"], "vpn_remote", t))
    return o


async def windows(ch, s: AsyncSession, since: datetime, now: datetime) -> Observations:
    o = Observations()
    rows = await ch.aquery(
        f"SELECT src_ip AS ip, user AS u, max(event_time) AS t FROM {table()} WHERE event_time >= {{a:DateTime64(3)}} AND event_time < {{b:DateTime64(3)}} "
        "AND event_type = 'windows' AND event_subtype IN ('4624', '4768', '4769', '4776') AND user != '' AND src_ip NOT IN ('', '-', '127.0.0.1', '::1') "
        "AND positionCaseInsensitive(action, 'fail') = 0 AND NOT endsWith(user, '$') GROUP BY ip, u LIMIT 20000", {"a": since, "b": now})
    for r in rows:
        o.ip_user.append((r["ip"], r["u"], "windows", _t(r["t"])))
    return o


async def dhcp(ch, s: AsyncSession, since: datetime, now: datetime) -> Observations:
    o = Observations()
    rows = await ch.aquery(
        f"SELECT if(event_type = 'zeek', src_ip, extract(raw, ' ip=\"?([0-9.]+)')) AS ip, "
        f"if(event_type = 'zeek', JSONExtractString(raw, 'mac'), extract(raw, ' mac=\"?([0-9a-fA-F:]{{17}})')) AS mac, "
        f"any(if(event_type = 'zeek', JSONExtractString(raw, 'host_name'), extract(raw, ' hostname=\"([^\"]*)\"'))) AS name, max(event_time) AS t "
        f"FROM {table()} WHERE event_time >= {{a:DateTime64(3)}} AND event_time < {{b:DateTime64(3)}} AND ((event_type = 'zeek' AND event_subtype = 'dhcp') "
        "OR (category = 'system' AND position(raw, 'DHCP Ack') > 0)) GROUP BY ip, mac LIMIT 20000", {"a": since, "b": now})
    for r in rows:
        mac = norm_mac(r["mac"])
        if not mac or not r["ip"]:
            continue
        t = _t(r["t"])
        o.ip_mac.append((r["ip"], mac, "dhcp", t))
        d = o.device(mac)
        d.setdefault("sources", set()).add("dhcp")
        if r["name"]:
            d.update(hostname=r["name"], hostname_source="dhcp", seen=t)
    return o


register_contributor("grid.fortigate", "grid", fortigate)
register_contributor("grid.vpn", "grid", vpn)
register_contributor("grid.windows", "grid", windows)
register_contributor("grid.dhcp", "grid", dhcp)
