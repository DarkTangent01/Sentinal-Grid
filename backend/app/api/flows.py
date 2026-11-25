"""APIs: Sentinel NMS → Flow Analytics (NetFlow / IPFIX / sFlow collected by app/flows). Read-only.

Ranges up to 6 hours read the raw records (minute detail); longer ranges read the hourly rollups. Byte and packet
counts already include the exporter's sampling rate, so they estimate the real traffic; the response says when sampled
data is present.
"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.ch import ClickHouse
from ..db.models import Firewall, Switch, SwitchInterface, User
from ..db.pg import get_session
from .deps import ch_dep, current_user

router = APIRouter(prefix="/api/nms/flows", tags=["nms-flows"])
RANGES = {"1h": (1, 60), "6h": (6, 300), "24h": (24, 3600), "7d": (168, 3600), "30d": (720, 21600)}
PROTO = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6", 89: "OSPF", 112: "VRRP"}
SERVICES = {20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http", 88: "kerberos",
            110: "pop3", 123: "ntp", 137: "netbios", 138: "netbios", 139: "netbios", 143: "imap", 161: "snmp", 162: "snmp-trap", 389: "ldap",
            443: "https", 445: "smb", 465: "smtps", 500: "ike", 514: "syslog", 587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s",
            1194: "openvpn", 1433: "mssql", 1521: "oracle", 1812: "radius", 1813: "radius-acct", 3306: "mysql", 3389: "rdp", 4500: "ipsec-nat",
            5060: "sip", 5061: "sips", 5222: "xmpp", 5432: "postgres", 5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
            9092: "kafka", 9200: "elasticsearch", 27017: "mongodb"}
BY = ("talkers", "sources", "destinations", "services", "interfaces", "vlans", "exporters")


def _win(range_: str) -> tuple[datetime, int, bool]:
    hours, bucket = RANGES[range_]
    return datetime.now(timezone.utc) - timedelta(hours=hours), bucket, hours <= 6


def _filters(exporter: str | None, ip: str | None, raw: bool) -> tuple[str, dict]:
    parts, p = [], {}
    if exporter:
        parts.append("exporter = {ex:String}")
        p["ex"] = exporter
    if ip:
        parts.append("(src_ip = {ip:String} OR dst_ip = {ip:String})")
        p["ip"] = ip
    return "".join(f" AND {x}" for x in parts), p


async def _names(s: AsyncSession) -> tuple[dict, dict]:
    sw = {x.address: x.name for x in (await s.execute(select(Switch))).scalars()}
    fw = {x.host: x.name for x in (await s.execute(select(Firewall).where(Firewall.is_demo.is_(False)))).scalars()}
    return {**fw, **sw}, {x.id: x.name for x in (await s.execute(select(Switch))).scalars()}


def _svc(proto: int, port: int) -> str:
    p = PROTO.get(proto, str(proto))
    return f"{p}/{port} ({SERVICES[port]})" if port in SERVICES else (f"{p}/{port}" if port else p)


@router.get("/summary")
async def summary(range: str = Query("24h", pattern="^(1h|6h|24h|7d|30d)$"), exporter: str | None = Query(None, max_length=64),
                  ip: str | None = Query(None, max_length=64), _: User = Depends(current_user), s: AsyncSession = Depends(get_session),
                  ch: ClickHouse = Depends(ch_dep)):
    t0, bucket, raw = _win(range)
    f, p = _filters(exporter, ip, raw)
    if ip:                                   # only the raw / talker tables carry addresses
        table, ts, flows_expr = ("flows", "ts", "count()") if raw else ("flows_talkers_hourly", "hour", "sum(flows)")
    else:
        table, ts, flows_expr = ("flows", "ts", "count()") if raw else ("flows_if_hourly", "hour", "sum(flows)")
    series = await ch.aquery(f"SELECT toUnixTimestamp(toStartOfInterval({ts}, INTERVAL {bucket} SECOND)) AS t, sum(bytes) AS b, sum(packets) AS pk, "
                             f"{flows_expr} AS fl FROM {table} WHERE {ts} >= {{t0:DateTime64(3)}}{f} GROUP BY t ORDER BY t", {"t0": t0, **p})
    exps = await ch.aquery(f"SELECT exporter, sum(bytes) AS b, max({ts}) AS last FROM {table} WHERE {ts} >= {{t0:DateTime64(3)}}{f} "
                           "GROUP BY exporter ORDER BY b DESC", {"t0": t0, **p})
    sampled = await ch.aquery("SELECT max(sampling) AS m, count() AS n FROM flows WHERE ts >= {t0:DateTime64(3)}" + f, {"t0": max(t0, datetime.now(timezone.utc) - timedelta(days=30)), **p})
    names, _ = await _names(s)
    return {"range": range, "bucket_seconds": bucket, "source": "raw records" if raw else "hourly rollups",
            "points": [{"t": datetime.fromtimestamp(int(r["t"]), tz=timezone.utc).isoformat(), "bytes": int(r["b"]),
                        "bps": round(int(r["b"]) * 8 / bucket, 1), "packets": int(r["pk"]), "flows": int(r["fl"])} for r in series],
            "totals": {"bytes": sum(int(r["b"]) for r in series), "packets": sum(int(r["pk"]) for r in series), "flows": sum(int(r["fl"]) for r in series)},
            "exporters": [{"exporter": r["exporter"], "name": names.get(r["exporter"], r["exporter"]), "bytes": int(r["b"]), "last": str(r["last"])} for r in exps],
            "sampled": int(sampled[0]["m"] or 1) > 1 if sampled and int(sampled[0]["n"] or 0) else False}


@router.get("/top")
async def top(by: str = Query("talkers", pattern="^(" + "|".join(BY) + ")$"), range: str = Query("24h", pattern="^(1h|6h|24h|7d|30d)$"),
              exporter: str | None = Query(None, max_length=64), ip: str | None = Query(None, max_length=64), limit: int = Query(25, ge=1, le=200),
              _: User = Depends(current_user), s: AsyncSession = Depends(get_session), ch: ClickHouse = Depends(ch_dep)):
    t0, _b, raw = _win(range)
    f, p = _filters(exporter, ip if by in ("talkers", "sources", "destinations") or raw else None, raw)
    if by in ("talkers", "sources", "destinations"):
        table, ts, fl = ("flows", "ts", "count()") if raw else ("flows_talkers_hourly", "hour", "sum(flows)")
        keys = {"talkers": "src_ip, dst_ip", "sources": "src_ip", "destinations": "dst_ip"}[by]
    else:
        table, ts, fl = ("flows", "ts", "count()") if raw else ("flows_if_hourly", "hour", "sum(flows)")
        port = "if(src_port != 0 AND (dst_port = 0 OR src_port < dst_port), src_port, dst_port)" if raw else "port"
        keys = {"services": f"proto, {port} AS port", "interfaces": "exporter, device_id, in_if, out_if", "vlans": "vlan",
                "exporters": "exporter"}[by]
    group = ", ".join(k.split(" AS ")[-1] for k in keys.split(", "))
    rows = await ch.aquery(f"SELECT {keys}, sum(bytes) AS b, sum(packets) AS pk, {fl} AS fl FROM {table} WHERE {ts} >= {{t0:DateTime64(3)}}{f} "
                           f"GROUP BY {group} ORDER BY b DESC LIMIT {int(limit)}", {"t0": t0, **p})
    names, sw_names = await _names(s)
    ifn = {}
    if by == "interfaces":
        ids = {int(r["device_id"]) for r in rows}
        ifn = {(i.switch_id, i.ifindex): i.name for i in (await s.execute(select(SwitchInterface).where(SwitchInterface.switch_id.in_(ids or {0})))).scalars()}
    total = sum(int(r["b"]) for r in rows) or 1
    items = []
    for r in rows:
        it = {"bytes": int(r["b"]), "packets": int(r["pk"]), "flows": int(r["fl"]), "share": round(100 * int(r["b"]) / total, 1)}
        if by == "services":
            it.update(proto=int(r["proto"]), port=int(r["port"]), label=_svc(int(r["proto"]), int(r["port"])))
        elif by == "interfaces":
            d = int(r["device_id"])
            it.update(exporter=r["exporter"], device=sw_names.get(d) or names.get(r["exporter"], r["exporter"]), in_if=int(r["in_if"]), out_if=int(r["out_if"]),
                      in_name=ifn.get((d, int(r["in_if"])), f"ifIndex {r['in_if']}"), out_name=ifn.get((d, int(r["out_if"])), f"ifIndex {r['out_if']}"))
        elif by == "exporters":
            it.update(exporter=r["exporter"], name=names.get(r["exporter"], r["exporter"]))
        else:
            it.update({k: r[k] for k in ("src_ip", "dst_ip", "vlan") if k in r})
        items.append(it)
    return {"by": by, "range": range, "items": items, "source": "raw records" if raw else "hourly rollups"}
