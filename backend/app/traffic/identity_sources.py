"""Sentinel NMS identity contributors (app/platform/identity.py registry): what the network itself knows about hosts.

  wireless   controller client tables: IP ↔ MAC, SSID, AP, VLAN, user name (802.1X / captive portal), site
  switch_mac MAC address tables: the switch port a MAC is connected to (access port preferred over uplinks / LAGs), VLAN
  sflow      sampled frames: the MAC on the internal endpoint's side of each flow (router / gateway MACs dropped)
  tacacs     TACACS+ accounting / authentication: the administrator's workstation address ↔ user name
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import Switch, SwitchInterface, SwitchMac, WirelessAp, WirelessClient
from ..platform.identity import Observations, is_unicast_host_mac, norm_mac, register_contributor, router_macs
from . import networks as N

UPLINK_MACS = 20      # a port that learned more MACs than this is an uplink / trunk, not a host's access port


def _aware(t: datetime | None) -> datetime | None:
    return t if t is None or t.tzinfo else t.replace(tzinfo=timezone.utc)


async def _inventory_macs(s: AsyncSession) -> set[str]:
    """MACs of inventory devices are network equipment, not hosts (AP radios, controller interfaces)."""
    out = {norm_mac(m) for (m,) in (await s.execute(select(WirelessAp.mac))).all()}
    return {m for m in out if m}


async def wireless(ch, s: AsyncSession, since: datetime, now: datetime) -> Observations:
    o = Observations()
    wlcs = {w.id: w for w in (await s.execute(select(Switch).where(Switch.device_type == "wlc"))).scalars()}
    aps = {a.id: a.name for a in (await s.execute(select(WirelessAp))).scalars()}
    rows = (await s.execute(select(WirelessClient).where(WirelessClient.present.is_(True)))).scalars().all()
    for c in rows:
        mac = norm_mac(c.mac)
        if not mac:
            continue
        seen = _aware(c.last_seen) or now
        d = o.device(mac)
        d.update(wireless=True, ssid=c.ssid, ap=aps.get(c.ap_id or 0, ""), vlan=c.vlan, site=getattr(wlcs.get(c.wlc_id), "site", ""), seen=seen)
        d.setdefault("sources", set()).add("wireless")
        if c.username:
            d["user"] = c.username
        if c.ip and c.ip not in ("0.0.0.0", "::"):
            o.ip_mac.append((c.ip, mac, "wireless", seen))
            if c.username:
                o.ip_user.append((c.ip, c.username, "wireless", seen))
    return o


async def switch_macs(ch, s: AsyncSession, since: datetime, now: datetime) -> Observations:
    o = Observations()
    sws = {x.id: x for x in (await s.execute(select(Switch))).scalars()}
    lags = {(i.switch_id, i.ifindex) for i in (await s.execute(select(SwitchInterface).where(SwitchInterface.kind == "lag"))).scalars()}
    rows = (await s.execute(select(SwitchMac).where(SwitchMac.present.is_(True)))).scalars().all()
    per_port = Counter((r.switch_id, r.ifindex) for r in rows)
    best: dict[str, tuple] = {}
    for r in rows:
        mac = norm_mac(r.mac)
        if not mac or not is_unicast_host_mac(mac):
            continue
        n = per_port[(r.switch_id, r.ifindex)]
        score = ((r.switch_id, r.ifindex) in lags or n > UPLINK_MACS, n)
        if mac not in best or score < best[mac][0]:
            best[mac] = (score, r)
    for mac, (score, r) in best.items():
        if score[0]:
            continue                       # only seen on uplinks / LAGs: the access switch is not monitored
        sw = sws.get(r.switch_id)
        d = o.device(mac)
        d.update(switch=sw.name if sw else "", port=r.port_name or f"ifIndex {r.ifindex}", vlan=r.vlan_id or None, site=sw.site if sw else "",
                 seen=_aware(r.last_seen) or now)
        d.setdefault("sources", set()).add("switch_mac")
    return o


async def sflow(ch, s: AsyncSession, since: datetime, now: datetime) -> Observations:
    o = Observations()
    nets = await N.load(s)
    rows = await ch.aquery(
        "SELECT ip, mac, max(ts) AS t FROM (SELECT src_ip AS ip, src_mac AS mac, ts FROM flows WHERE ts >= {a:DateTime64(3)} AND ts < {b:DateTime64(3)} "
        "AND src_mac != '' UNION ALL SELECT dst_ip AS ip, dst_mac AS mac, ts FROM flows WHERE ts >= {a:DateTime64(3)} AND ts < {b:DateTime64(3)} AND dst_mac != '') "
        "GROUP BY ip, mac LIMIT 200000", {"a": since, "b": now})
    pairs = [(r["ip"], norm_mac(r["mac"])) for r in rows]
    routers = router_macs([(ip, m) for ip, m in pairs if m])
    skip = await _inventory_macs(s)
    for r, (ip, mac) in zip(rows, pairs):
        if not mac or mac in routers or mac in skip or not is_unicast_host_mac(mac) or not nets.is_internal(ip):
            continue
        t = r["t"] if isinstance(r["t"], datetime) else datetime.fromisoformat(str(r["t"]))
        o.ip_mac.append((ip, mac, "sflow", _aware(t)))
    for m in routers:
        if is_unicast_host_mac(m):
            o.device(m).update(inventory="Network equipment", sources={"sflow"}, seen=now)   # routes for several addresses
    return o


async def tacacs(ch, s: AsyncSession, since: datetime, now: datetime) -> Observations:
    o = Observations()
    try:
        rows = await ch.aquery(
            "SELECT remote_addr AS ip, username AS u, max(ts) AS t FROM tacacs_events WHERE ts >= {a:DateTime64(3)} AND ts < {b:DateTime64(3)} "
            "AND username != '' AND remote_addr != '' AND result IN ('pass', 'success', 'permit', 'ok', 'accepted') GROUP BY ip, u LIMIT 10000",
            {"a": since, "b": now})
    except Exception:
        return o
    for r in rows:
        t = r["t"] if isinstance(r["t"], datetime) else datetime.fromisoformat(str(r["t"]))
        o.ip_user.append((r["ip"], r["u"], "tacacs", _aware(t)))
    return o


register_contributor("nms.wireless", "nms", wireless)
register_contributor("nms.switch_mac", "nms", switch_macs)
register_contributor("nms.sflow", "nms", sflow)
register_contributor("nms.tacacs", "nms", tacacs)
