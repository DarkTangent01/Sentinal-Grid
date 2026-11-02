"""APIs: switch monitoring (Cisco / Ruckus ICX over read-only SNMP).

Read endpoints need a signed-in user; onboarding, credentials, networks, discovery, polling and test calls need an
administrator. Credentials are write-only (never returned). Every change is audited.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import re
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import load_only
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db.ch import ClickHouse
from ..db.models import (Alert, Switch, SwitchCredential, SwitchDiscoveryRun, SwitchEvent, SwitchInterface, SwitchMac, SwitchNetwork,
                         SwitchPollRun, SwitchVlan, User)
from ..db.pg import get_session
from ..products import site_allowed
from ..switches import poller as P
from ..switches import service as V
from ..switches.rates import flag_names
from ..switches.registry import GROUPS, METRICS
from ..switches.snmp import AUTH_PROTOCOLS, PRIV_PROTOCOLS, Credentials, SnmpError
from .deps import audit, ch_dep, csv_safe, current_user, iso, limiter, require_admin

router = APIRouter(prefix="/api/switches", tags=["switches"])
RANGE = r"^(15m|1h|6h|24h|7d|30d)$"
NAME = r"^[A-Za-z0-9][A-Za-z0-9 ._()/:-]{0,127}$"


def _rate(user: User, key: str, limit: int):
    if not limiter.check(f"sw:{key}:{user.id}", limit):
        raise HTTPException(429, f"too many {key} requests; try again in a minute")


async def _get(s: AsyncSession, sid: int, user: User | None = None) -> Switch:
    sw = await s.get(Switch, sid)
    if sw is None or (user is not None and not site_allowed(user, sw.site)):   # out-of-scope devices look absent
        raise HTTPException(404, "switch not found")
    return sw


# ------------------------------------------------------------------ catalogue
@router.get("/meta")
async def meta(user: User = Depends(current_user)):
    return {"groups": [{"key": k, **v} for k, v in GROUPS.items()],
            "metrics": [{"key": m.key, "group": m.group, "category": m.category, "source": m.source, "oid": m.oid, "type": m.dtype, "unit": m.unit,
                         "vendors": list(m.vendors), "note": m.note} for m in METRICS],
            "auth_protocols": list(AUTH_PROTOCOLS), "priv_protocols": list(PRIV_PROTOCOLS), "snmpv2c_allowed": get_settings().switch_allow_snmpv2c,
            "ranges": list(V.RANGES), "is_admin": user.role == "admin",
            "statuses": {"healthy": "collected on the last attempt and fresh", "unavailable": "supported before, missing on the last attempt",
                         "unsupported": "never returned by this device", "failed": "the last attempt raised an error",
                         "stale": "last success older than 3 intervals", "not_configured": "disabled for this switch, or needs device configuration",
                         "pending": "not attempted yet"},
            "flags": {"gap": "sample spans a data gap (average over the gap; ignored by alerts)", "uncertain_utilization":
                      "utilisation not reliable (virtual interface, 32-bit counter may wrap twice, rate above speed)",
                      "32bit_counters": "interface has no 64-bit counters", "counter_reset": "counter reset / restart / ifIndex change: no rate",
                      "speed_unknown": "interface speed not reported: no utilisation"}}


# ------------------------------------------------------------------ overview / inventory
@router.get("/overview")
async def overview(site: list[str] = Query(default=[]), vendor: list[str] = Query(default=[]), model: str | None = Query(None, max_length=64),
                   q: str | None = Query(None, max_length=128), range: str = Query("24h", pattern=RANGE), user: User = Depends(current_user),
                   s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    return await V.overview(s, ch, site=site, vendor=vendor, model=model, q=q, range_=range, user=user)


@router.get("")
async def inventory(site: list[str] = Query(default=[]), vendor: list[str] = Query(default=[]), model: str | None = Query(None, max_length=64),
                    q: str | None = Query(None, max_length=128), state: list[str] = Query(default=[]),
                    sort: str = Query("name", pattern=r"^(name|state|site|cpu|mem|errors|coverage|last_poll|alerts)$"),
                    limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0), user: User = Depends(current_user),
                    s: AsyncSession = Depends(get_session)):
    now = datetime.now(timezone.utc)
    sws = [x for x in (await s.execute(select(Switch))).scalars().all() if V.matches(x, site, vendor, model, q) and (not state or x.state in state)
           and site_allowed(user, x.site)]
    alerts = await V.open_alerts_by_switch(s)
    creds = await V.credential_names(s)
    rows = [V.switch_row(x, now, creds, alerts) for x in sws]
    key = {"name": lambda r: r["name"].lower(), "state": lambda r: (r["state"] != "down", r["state"] != "auth_failed", r["name"]),
           "site": lambda r: (r["site"], r["name"]), "cpu": lambda r: -(r["cpu_pct"] or -1), "mem": lambda r: -(r["mem_pct"] or -1),
           "errors": lambda r: -(r["if_errors"] or 0), "coverage": lambda r: r["coverage_pct"] if r["coverage_pct"] is not None else 101,
           "last_poll": lambda r: r["last_success_at"] or "", "alerts": lambda r: -r["alerts_open"]}[sort]
    rows.sort(key=key)
    return {"total": len(rows), "items": rows[offset:offset + limit]}


@router.get("/export.csv")
async def export_csv(user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    now = datetime.now(timezone.utc)
    creds = await V.credential_names(s)
    cols = ["name", "address", "vendor", "model", "serial", "firmware", "site", "building", "floor", "rack", "role", "credential", "state",
            "if_total", "if_up", "cpu_pct", "mem_pct", "poe_used_w", "poe_budget_w", "coverage_pct", "last_success_at"]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for sw in (await s.execute(select(Switch).order_by(Switch.name))).scalars():
        if not site_allowed(user, sw.site):
            continue
        r = V.switch_row(sw, now, creds)
        w.writerow([csv_safe(r.get(c)) for c in cols])
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=switches.csv"})


@router.get("/interfaces")
async def all_interfaces(q: str | None = Query(None, max_length=128), site: list[str] = Query(default=[]), vendor: list[str] = Query(default=[]),
                         kind: str | None = Query(None, pattern=r"^(physical|lag|svi|virtual)$"), oper: str | None = Query(None, pattern=r"^(up|down)$"),
                         vlan: int | None = Query(None, ge=1, le=4094), sort: str = Query("util", pattern=r"^(util|errors|discards|name|traffic)$"),
                         errors_only: bool = False, limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0),
                         user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    # filter, sort, count and page in SQL: loading every interface of every switch to return one page does not scale
    sws = {x.id: x for x in (await s.execute(select(Switch).options(load_only(Switch.id, Switch.name, Switch.site, Switch.vendor, Switch.model)))).scalars()
           if V.matches(x, site, vendor, None, None) and site_allowed(user, x.site)}
    I = SwitchInterface  # noqa: E741
    st = select(I).where(I.switch_id.in_(list(sws) or [0]), I.present.is_(True))
    if kind:
        st = st.where(I.kind == kind)
    if oper == "up":
        st = st.where(I.oper == "up")
    elif oper == "down":
        st = st.where(I.oper != "up")
    if vlan:
        st = st.where(or_(I.access_vlan == vlan, I.native_vlan == vlan))
    if q:
        like = f"%{q}%"
        st = st.where(or_(I.name.ilike(like), I.alias.ilike(like), I.descr.ilike(like)))
    errs = func.coalesce(I.in_errors_delta, 0) + func.coalesce(I.out_errors_delta, 0) + func.coalesce(I.crc_delta, 0)
    if errors_only:
        st = st.where(errs > 0)
    rx, tx = func.coalesce(I.rx_util, 0), func.coalesce(I.tx_util, 0)
    order = {"util": [case((rx >= tx, rx), else_=tx).desc()], "errors": [errs.desc()], "discards": [func.coalesce(I.discards_delta, 0).desc()],
             "traffic": [(func.coalesce(I.rx_bps, 0) + func.coalesce(I.tx_bps, 0)).desc()], "name": [Switch.name, I.ifindex]}[sort]
    total = (await s.execute(select(func.count()).select_from(st.subquery()))).scalar_one()
    if sort == "name":
        st = st.join(Switch, Switch.id == I.switch_id)
    rows = (await s.execute(st.order_by(*order, I.switch_id, I.ifindex).limit(limit).offset(offset))).scalars().all()
    return {"total": total, "items": [_ifrow(r, sws[r.switch_id]) for r in rows]}


def _ifrow(r: SwitchInterface, sw: Switch | None = None) -> dict:
    d = {"switch_id": r.switch_id, "ifindex": r.ifindex, "name": r.name, "descr": r.descr, "alias": r.alias, "type": r.if_type, "kind": r.kind,
         "mtu": r.mtu, "speed_bps": r.speed_bps, "speed_source": r.speed_source, "admin": r.admin, "oper": r.oper, "duplex": r.duplex, "mac": r.mac,
         "mode": r.mode, "access_vlan": r.access_vlan, "native_vlan": r.native_vlan, "lag_ifindex": r.lag_ifindex, "poe": r.poe,
         "rx_bps": r.rx_bps, "tx_bps": r.tx_bps, "rx_util": r.rx_util, "tx_util": r.tx_util, "in_errors": r.in_errors_delta, "out_errors": r.out_errors_delta,
         "crc": r.crc_delta, "discards": r.discards_delta, "flags": flag_names(r.sample_flags or 0), "note": r.sample_note,
         "hc_counters": bool((r.counters or {}).get("hc")), "last_change_at": iso(r.last_change_at), "last_sample_at": iso(r.last_sample_at),
         "present": r.present}
    if sw is not None:
        d.update(switch=sw.name, site=sw.site)
    return d


@router.get("/macs/search")
async def mac_search(mac: str = Query(min_length=4, max_length=17), user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    m = re.sub(r"[^0-9a-f]", "", mac.lower())
    if not m:
        raise HTTPException(422, "enter a MAC address or part of one")
    norm = ":".join(m[i:i + 2] for i in range(0, len(m), 2))
    rows = (await s.execute(select(SwitchMac, Switch.name, Switch.site).join(Switch, Switch.id == SwitchMac.switch_id).where(SwitchMac.mac.like(f"%{norm}%"))
                            .order_by(SwitchMac.last_seen.desc()).limit(200))).all()
    return {"items": [_macrow(r, name) for r, name, site in rows if site_allowed(user, site)]}


def _macrow(r: SwitchMac, switch: str | None = None) -> dict:
    return {"switch_id": r.switch_id, "switch": switch, "mac": r.mac, "vlan": r.vlan_id, "ifindex": r.ifindex, "port": r.port_name, "status": r.status,
            "moves": r.moves, "present": r.present, "first_seen": iso(r.first_seen), "last_seen": iso(r.last_seen)}


@router.get("/events")
async def events(switch_id: int | None = None, kind: list[str] = Query(default=[]), severity: list[str] = Query(default=[]),
                 range: str = Query("24h", pattern=RANGE), q: str | None = Query(None, max_length=128), limit: int = Query(100, ge=1, le=1000),
                 offset: int = Query(0, ge=0), user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    t0, _t1 = V.window(range)
    st = select(SwitchEvent).where(SwitchEvent.at >= t0)
    if user.role != "admin" and user.sites:
        st = st.where(SwitchEvent.switch_id.in_([x.id for x in (await s.execute(select(Switch))).scalars() if site_allowed(user, x.site)] or [0]))
    if switch_id:
        st = st.where(SwitchEvent.switch_id == switch_id)
    if kind:
        st = st.where(SwitchEvent.kind.in_(kind))
    if severity:
        st = st.where(SwitchEvent.severity.in_(severity))
    if q:
        st = st.where(or_(SwitchEvent.detail.ilike(f"%{q}%"), SwitchEvent.component.ilike(f"%{q}%")))
    total = (await s.execute(select(func.count()).select_from(st.subquery()))).scalar_one()
    rows = (await s.execute(st.order_by(SwitchEvent.at.desc()).offset(offset).limit(limit))).scalars().all()
    by = {x.id: x for x in (await s.execute(select(Switch).where(Switch.id.in_({r.switch_id for r in rows} or {0})))).scalars()}
    return {"total": total, "items": [V.event_row(e, by) for e in rows]}


# ------------------------------------------------------------------ topology (LLDP / CDP)
@router.get("/topology")
async def topology(site: str | None = Query(None, max_length=128), endpoints: bool = False, lost_hours: int = Query(24, ge=1, le=720),
                   user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    from ..switches.topology import build
    return await build(s, site=site or None, endpoints=endpoints, lost_hours=lost_hours)


@router.get("/topology/path")
async def topology_path(src: str = Query(max_length=300), dst: str = Query(max_length=300), site: str | None = Query(None, max_length=128),
                        include_degraded: bool = True, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    """Is there a working layer-2 path between two nodes (switches / firewalls / neighbors)? BFS over links that are up
    (and degraded, unless excluded); the answer also says which links on the alternative are down or lost."""
    from ..switches.topology import build, path
    topo = await build(s, site=site or None, endpoints=True)
    ids = {n["id"] for n in topo["nodes"]}
    if src not in ids or dst not in ids:
        raise HTTPException(404, "node not in the topology")
    usable = ("up", "degraded") if include_degraded else ("up",)
    p = path(topo, src, dst, usable=usable)
    if not p["connected"]:
        p["via_any_link"] = path(topo, src, dst, usable=("up", "degraded", "down", "lost", "unknown"))
    return p


# ------------------------------------------------------------------ device
@router.get("/{sid}")
async def detail(sid: int, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    sw = await _get(s, sid, user)
    now = datetime.now(timezone.utc)
    row = V.switch_row(sw, now, await V.credential_names(s), await V.open_alerts_by_switch(s))
    h = dict(sw.health or {})
    h.pop("entity_names", None)
    alerts = (await s.execute(select(Alert).where(Alert.rule_key.like("switch_%"), Alert.group_key.like(f"{sid}:%"))
                              .order_by(Alert.last_seen.desc()).limit(100))).scalars().all()
    vlans = (await s.execute(select(func.count()).select_from(SwitchVlan).where(SwitchVlan.switch_id == sid, SwitchVlan.present.is_(True)))).scalar_one()
    macs = (await s.execute(select(func.count()).select_from(SwitchMac).where(SwitchMac.switch_id == sid, SwitchMac.present.is_(True)))).scalar_one()
    caps = V.capability_view(sw, now)
    sections = {g["group"]: any(m["group"] == g["group"] and m["status"] in ("healthy", "unavailable", "stale", "failed") for m in caps["metrics"])
                for g in caps["groups"]}
    site_fw = []
    if sw.site:
        from ..db.models import Firewall
        fws = (await s.execute(select(Firewall.id, Firewall.name).where(func.lower(Firewall.site) == sw.site.lower(), Firewall.is_demo.is_(False)))).all()
        if fws:
            fa = (await s.execute(select(Alert).where(Alert.status.in_(["new", "investigating"]), Alert.last_seen >= now.replace(microsecond=0) - timedelta(days=1))
                                  .order_by(Alert.last_seen.desc()).limit(500))).scalars().all()
            ids = {f.id for f in fws}
            site_fw = [{"id": a.id, "name": a.name, "severity": a.severity, "last_seen": iso(a.last_seen), "rule_key": a.rule_key}
                       for a in fa if not a.rule_key.startswith("switch_") and set(a.firewall_ids or []) & ids][:20]
        site_fw = {"firewalls": [{"id": f.id, "name": f.name} for f in fws], "alerts": site_fw}
    return {**row, "sys_descr": sw.sys_descr, "sys_object_id": sw.sys_object_id, "health": h, "vlan_count": vlans, "mac_count": macs,
            "sections": sections, "capability_summary": caps["coverage"], "groups": caps["groups"],
            "alerts": [{"id": a.id, "name": a.name, "severity": a.severity, "status": a.status, "first_seen": iso(a.first_seen), "last_seen": iso(a.last_seen),
                        "explanation": a.explanation, "evidence": a.evidence, "rule_key": a.rule_key, "group_key": a.group_key} for a in alerts],
            "site_context": site_fw or None}


@router.get("/{sid}/interfaces")
async def interfaces(sid: int, q: str | None = Query(None, max_length=128), kind: str | None = Query(None, pattern=r"^(physical|lag|svi|virtual)$"),
                     oper: str | None = Query(None, pattern=r"^(up|down)$"), errors_only: bool = False, include_absent: bool = False,
                     limit: int = Query(500, ge=1, le=2000), offset: int = Query(0, ge=0), user: User = Depends(current_user),
                     s: AsyncSession = Depends(get_session)):
    await _get(s, sid, user)
    st = select(SwitchInterface).where(SwitchInterface.switch_id == sid)
    if not include_absent:
        st = st.where(SwitchInterface.present.is_(True))
    if kind:
        st = st.where(SwitchInterface.kind == kind)
    if oper:
        st = st.where(SwitchInterface.oper == "up") if oper == "up" else st.where(SwitchInterface.oper != "up")
    if q:
        st = st.where(or_(SwitchInterface.name.ilike(f"%{q}%"), SwitchInterface.alias.ilike(f"%{q}%")))
    rows = (await s.execute(st.order_by(SwitchInterface.ifindex))).scalars().all()
    if errors_only:
        rows = [r for r in rows if ((r.in_errors_delta or 0) + (r.out_errors_delta or 0) + (r.crc_delta or 0)) > 0]
    t0, _t1 = V.window("24h")
    flaps: dict = {}
    for ifx, n in (await s.execute(select(SwitchEvent.data, SwitchEvent.kind).where(SwitchEvent.switch_id == sid, SwitchEvent.at >= t0,
                                                                                    SwitchEvent.kind.in_(["port_up", "port_down", "port_flap"])))).all():
        k = (ifx or {}).get("ifindex")
        flaps[k] = flaps.get(k, 0) + (2 if n == "port_flap" else 1)
    items = []
    for r in rows[offset:offset + limit]:
        d = _ifrow(r)
        d["changes_24h"] = flaps.get(r.ifindex, 0)
        items.append(d)
    return {"total": len(rows), "items": items}


@router.get("/{sid}/interfaces/{ifindex}")
async def interface_detail(sid: int, ifindex: int, range: str = Query("24h", pattern=RANGE), user: User = Depends(current_user),
                           s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    sw = await _get(s, sid, user)
    r = (await s.execute(select(SwitchInterface).where(SwitchInterface.switch_id == sid, SwitchInterface.ifindex == ifindex))).scalars().first()
    if r is None:
        raise HTTPException(404, "interface not found")
    t0, t1 = V.window(range)
    series = await V.interface_series(ch, sid, ifindex, t0, t1)
    evs = (await s.execute(select(SwitchEvent).where(SwitchEvent.switch_id == sid, SwitchEvent.at >= t0).order_by(SwitchEvent.at.desc()).limit(2000))).scalars().all()
    evs = [e for e in evs if (e.data or {}).get("ifindex") == ifindex or (e.data or {}).get("to_ifindex") == ifindex or (e.data or {}).get("from_ifindex") == ifindex
           or (e.kind.startswith("lacp") and r.name in (e.component or ""))][:200]
    vl = (await s.execute(select(SwitchVlan).where(SwitchVlan.switch_id == sid, SwitchVlan.present.is_(True)))).scalars().all()
    lag = None
    if r.lag_ifindex:
        lag = ((sw.health or {}).get("lacp") or {}).get("lags", {}).get(str(r.lag_ifindex))
    elif r.kind == "lag":
        lag = ((sw.health or {}).get("lacp") or {}).get("lags", {}).get(str(r.ifindex))
    alerts = (await s.execute(select(Alert).where(Alert.rule_key.like("switch_%"), Alert.group_key.like(f"{sid}:{ifindex}%"))
                              .order_by(Alert.last_seen.desc()).limit(50))).scalars().all()
    macs = (await s.execute(select(func.count()).select_from(SwitchMac).where(SwitchMac.switch_id == sid, SwitchMac.ifindex == ifindex,
                                                                               SwitchMac.present.is_(True)))).scalar_one()
    return {"switch": {"id": sw.id, "name": sw.name, "site": sw.site}, "interface": _ifrow(r), "series": series,
            "events": [V.event_row(e) for e in evs], "vlans": {"tagged": [v.vlan_id for v in vl if ifindex in (v.tagged or [])],
                                                               "untagged": [v.vlan_id for v in vl if ifindex in (v.untagged or [])]},
            "lag": lag, "mac_count": macs,
            "alerts": [{"id": a.id, "name": a.name, "severity": a.severity, "status": a.status, "last_seen": iso(a.last_seen), "explanation": a.explanation}
                       for a in alerts]}


@router.get("/{sid}/timeseries")
async def timeseries(sid: int, metric: str = Query(pattern=r"^(" + "|".join(V.DEVICE_METRICS) + r")$"), range: str = Query("24h", pattern=RANGE),
                     user: User = Depends(current_user), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    await _get(s, sid, user)
    t0, t1 = V.window(range)
    return await V.device_series(ch, sid, metric, t0, t1)


@router.get("/{sid}/vlans")
async def vlans(sid: int, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _get(s, sid, user)
    names = {r.ifindex: r.name for r in (await s.execute(select(SwitchInterface).where(SwitchInterface.switch_id == sid))).scalars()}
    svis = {int(m.group(1)): ix for ix, n in names.items() if (m := re.match(r"(?i)^vl(?:an)?\s?(\d+)$", n or ""))}
    ifs = {r.ifindex: r for r in (await s.execute(select(SwitchInterface).where(SwitchInterface.switch_id == sid))).scalars()}
    rows = (await s.execute(select(SwitchVlan).where(SwitchVlan.switch_id == sid).order_by(SwitchVlan.vlan_id))).scalars().all()
    out = []
    for v in rows:
        svi = ifs.get(svis.get(v.vlan_id)) if svis.get(v.vlan_id) else None
        out.append({"vlan_id": v.vlan_id, "name": v.name, "state": v.state, "present": v.present, "first_seen": iso(v.first_seen), "last_seen": iso(v.last_seen),
                    "tagged": [{"ifindex": i, "name": names.get(i, str(i))} for i in v.tagged or []],
                    "untagged": [{"ifindex": i, "name": names.get(i, str(i))} for i in v.untagged or []],
                    "svi": {"ifindex": svi.ifindex, "name": svi.name, "oper": svi.oper} if svi else None})
    ev = (await s.execute(select(SwitchEvent).where(SwitchEvent.switch_id == sid, SwitchEvent.kind.in_(["vlan_added", "vlan_removed", "vlan_renamed"]))
                          .order_by(SwitchEvent.at.desc()).limit(100))).scalars().all()
    return {"items": out, "changes": [V.event_row(e) for e in ev], "svi_mapping": "by interface name (VlanN); Ruckus ve interfaces are listed under Interfaces"}


@router.get("/{sid}/macs")
async def macs(sid: int, q: str | None = Query(None, max_length=64), vlan: int | None = Query(None, ge=0, le=4094), ifindex: int | None = None,
               include_absent: bool = False, limit: int = Query(200, ge=1, le=2000), offset: int = Query(0, ge=0), user: User = Depends(current_user),
               s: AsyncSession = Depends(get_session)):
    await _get(s, sid, user)
    st = select(SwitchMac).where(SwitchMac.switch_id == sid)
    if not include_absent:
        st = st.where(SwitchMac.present.is_(True))
    if vlan is not None:
        st = st.where(SwitchMac.vlan_id == vlan)
    if ifindex is not None:
        st = st.where(SwitchMac.ifindex == ifindex)
    if q:
        st = st.where(or_(SwitchMac.mac.ilike(f"%{q.lower()}%"), SwitchMac.port_name.ilike(f"%{q}%")))
    total = (await s.execute(select(func.count()).select_from(st.subquery()))).scalar_one()
    rows = (await s.execute(st.order_by(SwitchMac.vlan_id, SwitchMac.port_name, SwitchMac.mac).offset(offset).limit(limit))).scalars().all()
    moves = (await s.execute(select(SwitchEvent).where(SwitchEvent.switch_id == sid, SwitchEvent.kind.in_(["mac_move", "mac_learning_burst"]))
                             .order_by(SwitchEvent.at.desc()).limit(100))).scalars().all()
    return {"total": total, "items": [_macrow(r) for r in rows], "moves": [V.event_row(e) for e in moves]}


@router.get("/{sid}/neighbors")
async def neighbors(sid: int, include_absent: bool = True, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    from ..db.models import SwitchNeighbor
    from ..switches.topology import _short, node_type
    await _get(s, sid, user)
    sws = (await s.execute(select(Switch))).scalars().all()
    by_ip = {x.address: x for x in sws}
    by_name = {_short(n): x for x in sws for n in (x.name, x.sys_name) if n}
    st = select(SwitchNeighbor).where(SwitchNeighbor.switch_id == sid)
    if not include_absent:
        st = st.where(SwitchNeighbor.present.is_(True))
    rows = (await s.execute(st.order_by(SwitchNeighbor.local_port))).scalars().all()
    ifs = {r.ifindex: r for r in (await s.execute(select(SwitchInterface).where(SwitchInterface.switch_id == sid))).scalars()}
    out = []
    for r in rows:
        m = by_ip.get(r.remote_mgmt_ip) or by_name.get(_short(r.remote_name))
        li = ifs.get(r.local_ifindex)
        out.append({"local_ifindex": r.local_ifindex, "local_port": r.local_port, "local_oper": li.oper if li else None, "protocol": r.protocol,
                    "remote_name": r.remote_name, "chassis_id": r.chassis_id, "remote_port": r.remote_port, "remote_port_desc": r.remote_port_desc,
                    "remote_mgmt_ip": r.remote_mgmt_ip, "remote_descr": r.remote_descr, "capabilities": r.capabilities,
                    "type": node_type(r.capabilities, r.remote_descr), "matched_switch": {"id": m.id, "name": m.name} if m and m.id != sid else None,
                    "present": r.present, "first_seen": iso(r.first_seen), "last_seen": iso(r.last_seen)})
    return {"items": out}


@router.get("/{sid}/capabilities")
async def capabilities(sid: int, user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    return V.capability_view(await _get(s, sid, user))


@router.get("/{sid}/polls")
async def polls(sid: int, limit: int = Query(100, ge=1, le=500), user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    await _get(s, sid, user)
    rows = (await s.execute(select(SwitchPollRun).where(SwitchPollRun.switch_id == sid).order_by(SwitchPollRun.started_at.desc()).limit(limit))).scalars().all()
    ok = sum(1 for r in rows if r.ok)
    return {"success_pct": round(100 * ok / len(rows), 1) if rows else None,
            "avg_duration_ms": round(sum(r.duration_ms for r in rows) / len(rows)) if rows else None,
            "items": [{"id": r.id, "started_at": iso(r.started_at), "duration_ms": r.duration_ms, "ok": r.ok, "kind": r.kind, "requests": r.requests,
                       "groups": r.groups, "error": r.error} for r in rows]}


# ------------------------------------------------------------------ admin: credentials
class CredentialIn(BaseModel):
    name: str = Field(pattern=NAME)
    version: str = Field("v3", pattern=r"^(v3|v2c)$")
    username: str = Field("", max_length=32)
    auth_protocol: str = Field("sha", max_length=16)
    priv_protocol: str = Field("aes128", max_length=16)
    auth_key: str | None = Field(None, max_length=128)       # write-only; omit on update to keep
    priv_key: str | None = Field(None, max_length=128)
    community: str | None = Field(None, max_length=64)
    description: str = Field("", max_length=500)


def _cred_out(c: SwitchCredential, used: int = 0) -> dict:
    return {"id": c.id, "name": c.name, "version": c.version, "username": c.username, "auth_protocol": c.auth_protocol, "priv_protocol": c.priv_protocol,
            "security_level": Credentials(version=c.version, auth_protocol=c.auth_protocol, priv_protocol=c.priv_protocol).security_level,
            "has_secret": bool(c.secret_ciphertext), "description": c.description, "used_by": used, "created_by": c.created_by,
            "created_at": iso(c.created_at), "updated_at": iso(c.updated_at)}


@router.get("/admin/credentials")
async def list_credentials(_: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    used = dict((await s.execute(select(Switch.credential_id, func.count()).group_by(Switch.credential_id))).all())
    return {"items": [_cred_out(c, used.get(c.id, 0)) for c in (await s.execute(select(SwitchCredential).order_by(SwitchCredential.name))).scalars()]}


def _check_cred(body: CredentialIn, existing: dict | None) -> dict:
    secret = dict(existing or {})
    for k in ("auth_key", "priv_key", "community"):
        v = getattr(body, k)
        if v:
            secret[k] = v
    if body.version == "v2c":
        secret = {"community": secret.get("community", "")}
    else:
        secret.pop("community", None)
        if body.auth_protocol == "none":
            secret.pop("auth_key", None)
        if body.priv_protocol == "none":
            secret.pop("priv_key", None)
    c = Credentials(version=body.version, community=secret.get("community", ""), username=body.username, auth_protocol=body.auth_protocol,
                    auth_key=secret.get("auth_key", ""), priv_protocol=body.priv_protocol, priv_key=secret.get("priv_key", ""))
    try:
        c.validate()
        P.check_version_allowed(body.version)
    except SnmpError as e:
        raise HTTPException(422, e.message)
    return secret


@router.post("/admin/credentials", status_code=201)
async def create_credential(body: CredentialIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    if (await s.execute(select(SwitchCredential).where(SwitchCredential.name == body.name))).scalars().first():
        raise HTTPException(409, "a credential profile with this name exists")
    secret = _check_cred(body, None)
    c = SwitchCredential(name=body.name, version=body.version, username=body.username if body.version == "v3" else "",
                         auth_protocol=body.auth_protocol if body.version == "v3" else "none", priv_protocol=body.priv_protocol if body.version == "v3" else "none",
                         secret_ciphertext=P.seal_secret(secret), description=body.description, created_by=user.username)
    s.add(c)
    await s.commit()
    await audit(s, request, user.username, "switch_credential_create", c.name, {"version": c.version, "security_level": _cred_out(c)["security_level"]})
    return _cred_out(c)


@router.put("/admin/credentials/{cid}")
async def update_credential(cid: int, body: CredentialIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    c = await s.get(SwitchCredential, cid)
    if c is None:
        raise HTTPException(404, "credential profile not found")
    import json
    from ..security import TokenCipher
    existing = json.loads(TokenCipher().decrypt(c.secret_ciphertext)) if c.secret_ciphertext and body.version == c.version else {}
    secret = _check_cred(body, existing)
    c.name, c.version, c.description = body.name, body.version, body.description
    c.username = body.username if body.version == "v3" else ""
    c.auth_protocol = body.auth_protocol if body.version == "v3" else "none"
    c.priv_protocol = body.priv_protocol if body.version == "v3" else "none"
    c.secret_ciphertext = P.seal_secret(secret)
    await s.commit()
    await audit(s, request, user.username, "switch_credential_update", c.name,
                {"version": c.version, "secrets_changed": [k for k in ("auth_key", "priv_key", "community") if getattr(body, k)]})
    return _cred_out(c)


@router.delete("/admin/credentials/{cid}")
async def delete_credential(cid: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    c = await s.get(SwitchCredential, cid)
    if c is None:
        raise HTTPException(404, "credential profile not found")
    if (await s.execute(select(func.count()).select_from(Switch).where(Switch.credential_id == cid))).scalar_one():
        raise HTTPException(409, "the profile is assigned to switches; reassign them first")
    await s.delete(c)
    await s.commit()
    await audit(s, request, user.username, "switch_credential_delete", c.name)
    return {"ok": True}


# ------------------------------------------------------------------ admin: authorised networks
class NetworkIn(BaseModel):
    cidr: str = Field(max_length=64)
    site: str = Field("", max_length=128)
    description: str = Field("", max_length=500)
    allow_discovery: bool = False

    @field_validator("cidr")
    @classmethod
    def _cidr(cls, v):
        try:
            n = ipaddress.ip_network(v.strip(), strict=False)
        except ValueError:
            raise ValueError("enter a network in CIDR form, e.g. 10.20.0.0/24")
        if n.prefixlen < (16 if n.version == 4 else 48):
            raise ValueError("networks larger than /16 (IPv4) or /48 (IPv6) cannot be authorised")
        if n.is_loopback or n.is_link_local or n.is_multicast or n.is_unspecified or n.is_reserved:
            raise ValueError("loopback, link-local, multicast and reserved ranges cannot be authorised")
        return str(n)


@router.get("/admin/networks")
async def list_networks(user: User = Depends(current_user), s: AsyncSession = Depends(get_session)):
    sws = (await s.execute(select(Switch.address))).all()
    out = []
    for n in (await s.execute(select(SwitchNetwork).order_by(SwitchNetwork.cidr))).scalars():
        net = ipaddress.ip_network(n.cidr)
        out.append({"id": n.id, "cidr": n.cidr, "site": n.site, "description": n.description, "allow_discovery": n.allow_discovery,
                    "switches": sum(1 for (a,) in sws if ipaddress.ip_address(a) in net), "created_by": n.created_by, "created_at": iso(n.created_at)})
    return {"items": out}


@router.post("/admin/networks", status_code=201)
async def create_network(body: NetworkIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    if (await s.execute(select(SwitchNetwork).where(SwitchNetwork.cidr == body.cidr))).scalars().first():
        raise HTTPException(409, "this network is already authorised")
    n = SwitchNetwork(cidr=body.cidr, site=body.site, description=body.description, allow_discovery=body.allow_discovery, created_by=user.username)
    s.add(n)
    await s.commit()
    await audit(s, request, user.username, "switch_network_create", n.cidr, {"allow_discovery": n.allow_discovery})
    return {"id": n.id, "cidr": n.cidr}


@router.put("/admin/networks/{nid}")
async def update_network(nid: int, body: NetworkIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    n = await s.get(SwitchNetwork, nid)
    if n is None:
        raise HTTPException(404, "network not found")
    if body.cidr != n.cidr:
        raise HTTPException(422, "the CIDR of an authorised network cannot change; add a new network instead")
    n.site, n.description, n.allow_discovery = body.site, body.description, body.allow_discovery
    await s.commit()
    await audit(s, request, user.username, "switch_network_update", n.cidr, {"allow_discovery": n.allow_discovery})
    return {"id": n.id, "cidr": n.cidr}


@router.delete("/admin/networks/{nid}")
async def delete_network(nid: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    n = await s.get(SwitchNetwork, nid)
    if n is None:
        raise HTTPException(404, "network not found")
    net = ipaddress.ip_network(n.cidr)
    others = [ipaddress.ip_network(x.cidr) for x in (await s.execute(select(SwitchNetwork).where(SwitchNetwork.id != nid))).scalars()]
    stranded = [a for (a,) in (await s.execute(select(Switch.address))).all() if ipaddress.ip_address(a) in net
                and not any(ipaddress.ip_address(a) in o for o in others)]
    if stranded:
        raise HTTPException(409, f"{len(stranded)} switch(es) are only authorised by this network; remove them first")
    await s.delete(n)
    await s.commit()
    await audit(s, request, user.username, "switch_network_delete", n.cidr)
    return {"ok": True}


# ------------------------------------------------------------------ admin: switches
class SwitchIn(BaseModel):
    name: str = Field(pattern=NAME)
    address: str = Field(max_length=64)
    port: int = Field(161, ge=1, le=65535)
    credential_id: int
    site: str = Field("", max_length=128)
    building: str = Field("", max_length=128)
    floor: str = Field("", max_length=64)
    rack: str = Field("", max_length=64)
    role: str = Field("", max_length=32)
    notes: str = Field("", max_length=2000)
    monitoring: str = Field("active", pattern=r"^(active|paused)$")
    poll_interval_seconds: int = Field(60, ge=30, le=3600)
    group_intervals: dict[str, int] = Field(default_factory=dict)
    thresholds: dict[str, float | int | str] = Field(default_factory=dict)
    timeout_ms: int = Field(3000, ge=500, le=15000)
    retries: int = Field(1, ge=0, le=3)

    @field_validator("group_intervals")
    @classmethod
    def _gi(cls, v):
        for k, x in v.items():
            if k not in GROUPS or k == "system":
                raise ValueError(f"unknown or fixed metric group '{k}'")
            if x != 0 and not 30 <= x <= 86400:
                raise ValueError("group intervals must be 0 (disabled) or 30-86400 seconds")
        return v

    @field_validator("thresholds")
    @classmethod
    def _th(cls, v):
        allowed = {"cpu_pct", "mem_pct", "storage_pct", "celsius", "pct", "util_pct", "min_errors", "min_discards", "min_changes", "min_moves_per_mac",
                   "min_moves_per_switch", "mac_new_per_poll"}
        bad = set(v) - allowed
        if bad:
            raise ValueError(f"unknown thresholds: {', '.join(sorted(bad))}")
        for k, x in v.items():
            if not isinstance(x, (int, float)) or x < 0:
                raise ValueError(f"threshold {k} must be a non-negative number")
        return v


async def _validated(s: AsyncSession, body: SwitchIn, sid: int | None = None) -> str:
    nets = (await s.execute(select(SwitchNetwork))).scalars().all()
    try:
        addr = P.validate_address(body.address, nets)
    except ValueError as e:
        raise HTTPException(422, str(e))
    cred = await s.get(SwitchCredential, body.credential_id)
    if cred is None:
        raise HTTPException(422, "credential profile not found")
    try:
        P.check_version_allowed(cred.version)
    except SnmpError as e:
        raise HTTPException(422, e.message)
    for col, val, what in ((Switch.name, body.name, "name"), (Switch.address, addr, "management address")):
        other = (await s.execute(select(Switch).where(col == val))).scalars().first()
        if other and other.id != sid:
            raise HTTPException(409, f"another switch already uses this {what}")
    return addr


def _apply(sw: Switch, body: SwitchIn, addr: str):
    for k in ("name", "port", "credential_id", "site", "building", "floor", "rack", "role", "notes", "monitoring", "poll_interval_seconds",
              "group_intervals", "thresholds", "timeout_ms", "retries"):
        setattr(sw, k, getattr(body, k))
    sw.address = addr


@router.post("", status_code=201)
async def create(body: SwitchIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    addr = await _validated(s, body)
    sw = Switch(created_by=user.username, state="unknown", capabilities={}, group_state={}, health={})
    _apply(sw, body, addr)
    s.add(sw)
    await s.commit()
    await audit(s, request, user.username, "switch_create", sw.name, {"address": sw.address, "site": sw.site})
    return {"id": sw.id}


@router.put("/{sid}")
async def update_switch(sid: int, body: SwitchIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    sw = await _get(s, sid, user)
    addr = await _validated(s, body, sid)
    before = {k: getattr(sw, k) for k in ("address", "credential_id", "monitoring", "poll_interval_seconds")}
    if addr != sw.address or body.credential_id != sw.credential_id:
        sw.vendor, sw.uptime_ticks, sw.state, sw.fail_streak = "unknown", None, "unknown", 0  # re-identify; no counter deltas across devices
        for r in (await s.execute(select(SwitchInterface).where(SwitchInterface.switch_id == sid))).scalars():
            r.counters = {}
    _apply(sw, body, addr)
    await s.commit()
    await audit(s, request, user.username, "switch_update", sw.name, {"before": before, "after": {k: getattr(sw, k) for k in before}})
    return {"id": sw.id}


@router.delete("/{sid}")
async def delete_switch(sid: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    sw = await _get(s, sid, user)
    await s.delete(sw)
    await s.commit()
    await audit(s, request, user.username, "switch_delete", sw.name, {"address": sw.address})
    return {"ok": True}


@router.post("/{sid}/monitoring/{action}")
async def set_monitoring(sid: int, action: str, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    if action not in ("pause", "resume"):
        raise HTTPException(404, "unknown action")
    sw = await _get(s, sid, user)
    sw.monitoring = "paused" if action == "pause" else "active"
    await s.commit()
    await audit(s, request, user.username, f"switch_{action}", sw.name)
    return {"monitoring": sw.monitoring}


@router.post("/{sid}/poll")
async def poll_now(sid: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    _rate(user, "poll", 10)
    sw = await _get(s, sid, user)
    now = datetime.now(timezone.utc)
    from sqlalchemy import update
    res = await s.execute(update(Switch).where(Switch.id == sid, (Switch.lease_until.is_(None)) | (Switch.lease_until < now))
                          .values(lease_until=now + timedelta(seconds=get_settings().switch_poll_timeout_seconds)))
    await s.commit()
    if res.rowcount != 1:
        raise HTTPException(409, "a poll of this switch is already running")
    try:
        await s.refresh(sw)
        cred = await s.get(SwitchCredential, sw.credential_id) if sw.credential_id else None
        r = await P.poll_switch(s, ch, sw, cred, kind="poll", force=True)
    finally:
        sw.lease_until = None
        await s.commit()
    await audit(s, request, user.username, "switch_poll_now", sw.name, {"ok": r.get("ok")})
    return r


class TestIn(BaseModel):
    address: str = Field(max_length=64)
    port: int = Field(161, ge=1, le=65535)
    credential_id: int
    timeout_ms: int = Field(3000, ge=500, le=15000)
    retries: int = Field(1, ge=0, le=3)
    full: bool = True
    wlc: bool = False          # wireless controller: also run the wireless capability scan (AP / radio / WLAN / client MIBs)


@router.post("/test")
async def test_switch(body: TestIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    """Test connectivity and credentials, identify vendor / model, detect supported metrics and preview what will be
    collected. Nothing is stored."""
    _rate(user, "test", 10)
    nets = (await s.execute(select(SwitchNetwork))).scalars().all()
    try:
        addr = P.validate_address(body.address, nets)
    except ValueError as e:
        raise HTTPException(422, str(e))
    cred = await s.get(SwitchCredential, body.credential_id)
    if cred is None:
        raise HTTPException(422, "credential profile not found")
    r = await P.probe(addr, cred, port=body.port, timeout=body.timeout_ms / 1000, retries=body.retries, groups=None if body.full else ["system"],
                      wlc=body.wlc)
    await audit(s, request, user.username, "switch_test", addr, {"ok": r.get("ok"), "vendor": (r.get("identity") or {}).get("vendor")}, success=bool(r.get("ok")))
    return r


@router.post("/{sid}/test")
async def test_existing(sid: int, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    sw = await _get(s, sid, user)
    return await test_switch(TestIn(address=sw.address, port=sw.port, credential_id=sw.credential_id or 0, timeout_ms=sw.timeout_ms, retries=sw.retries,
                                    wlc=P.is_wlc(sw)), request, user, s)


class ImportIn(BaseModel):
    csv: str = Field(max_length=500_000)
    dry_run: bool = True


IMPORT_COLS = ["name", "address", "credential", "site", "building", "floor", "rack", "role", "port", "poll_interval_seconds", "notes"]


@router.post("/import")
async def import_csv(body: ImportIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    """Bulk onboarding. Columns: name,address,credential (profile name)[,site,building,floor,rack,role,port,poll_interval_seconds,notes].
    dry_run validates every row and reports errors without creating anything."""
    _rate(user, "import", 10)
    reader = csv.DictReader(io.StringIO(body.csv.lstrip("﻿")))
    if not reader.fieldnames or not {"name", "address", "credential"} <= {f.strip().lower() for f in reader.fieldnames}:
        raise HTTPException(422, "the CSV needs a header row with at least: name,address,credential")
    creds = {c.name: c.id for c in (await s.execute(select(SwitchCredential))).scalars()}
    rows, seen_names, seen_addr = [], set(), set()
    for i, raw in enumerate(reader, start=2):
        if i > 2001:
            raise HTTPException(422, "at most 2000 rows per import")
        r = {k.strip().lower(): (v or "").strip() for k, v in raw.items() if k}
        res = {"line": i, "name": r.get("name", ""), "address": r.get("address", ""), "errors": []}
        try:
            body_i = SwitchIn(name=r.get("name", ""), address=r.get("address", ""), credential_id=creds.get(r.get("credential", ""), 0),
                              site=r.get("site", ""), building=r.get("building", ""), floor=r.get("floor", ""), rack=r.get("rack", ""), role=r.get("role", ""),
                              notes=r.get("notes", ""), port=int(r.get("port") or 161), poll_interval_seconds=int(r.get("poll_interval_seconds") or 60))
        except (ValueError, TypeError) as e:
            res["errors"].append(str(e).split("\n")[0][:300])
            rows.append(res)
            continue
        if body_i.credential_id == 0:
            res["errors"].append(f"unknown credential profile '{r.get('credential', '')}'")
        else:
            try:
                addr = await _validated(s, body_i)
                res["address"] = addr
                if body_i.name in seen_names or addr in seen_addr:
                    res["errors"].append("duplicate name or address in this file")
                seen_names.add(body_i.name)
                seen_addr.add(addr)
                res["_body"] = body_i
            except HTTPException as e:
                res["errors"].append(e.detail)
        rows.append(res)
    ok = [r for r in rows if not r["errors"]]
    created = 0
    if not body.dry_run and ok and len(ok) == len(rows):
        for r in ok:
            sw = Switch(created_by=user.username, state="unknown", capabilities={}, group_state={}, health={})
            _apply(sw, r["_body"], r["address"])
            s.add(sw)
            created += 1
        await s.commit()
        await audit(s, request, user.username, "switch_import", f"{created} switches", {"names": [r["name"] for r in ok][:200]})
    for r in rows:
        r.pop("_body", None)
    return {"rows": rows, "valid": len(ok), "invalid": len(rows) - len(ok), "created": created, "dry_run": body.dry_run,
            "note": "" if body.dry_run or created else "nothing was created: fix every invalid row first (the import is all-or-nothing)"}


# ------------------------------------------------------------------ admin: discovery
class DiscoveryIn(BaseModel):
    network_id: int
    credential_id: int


@router.get("/admin/discovery")
async def discovery_runs(_: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    rows = (await s.execute(select(SwitchDiscoveryRun).order_by(SwitchDiscoveryRun.id.desc()).limit(20))).scalars().all()
    return {"items": [{"id": r.id, "cidr": r.cidr, "network_id": r.network_id, "credential_id": r.credential_id, "status": r.status,
                       "requested_by": r.requested_by, "created_at": iso(r.created_at), "started_at": iso(r.started_at), "finished_at": iso(r.finished_at),
                       "scanned": r.scanned, "found": len(r.results or []), "results": r.results, "error": r.error} for r in rows]}


@router.post("/admin/discovery", status_code=202)
async def start_discovery(body: DiscoveryIn, request: Request, user: User = Depends(require_admin), s: AsyncSession = Depends(get_session)):
    _rate(user, "discovery", 3)
    n = await s.get(SwitchNetwork, body.network_id)
    if n is None or not n.allow_discovery:
        raise HTTPException(422, "discovery is only allowed in an authorised network with 'allow discovery' enabled")
    cred = await s.get(SwitchCredential, body.credential_id)
    if cred is None:
        raise HTTPException(422, "credential profile not found")
    from ..switches.discovery import hosts_of
    try:
        P.check_version_allowed(cred.version)
        hosts = hosts_of(n.cidr)
    except (ValueError, SnmpError) as e:
        raise HTTPException(422, getattr(e, "message", str(e)))
    if (await s.execute(select(SwitchDiscoveryRun).where(SwitchDiscoveryRun.status.in_(["queued", "running"])))).scalars().first():
        raise HTTPException(409, "a discovery run is already queued or running")
    r = SwitchDiscoveryRun(network_id=n.id, cidr=n.cidr, credential_id=cred.id, status="queued", requested_by=user.username)
    s.add(r)
    await s.commit()
    await audit(s, request, user.username, "switch_discovery", n.cidr, {"hosts": len(hosts), "credential": cred.name})
    return {"id": r.id, "hosts": len(hosts)}
