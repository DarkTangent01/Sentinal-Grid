"""Traffic intelligence settings (single PostgreSQL row, traffic_settings.data), merged over DEFAULTS."""
from __future__ import annotations

import ipaddress

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import TrafficSetting

DEFAULTS: dict = {
    # the same conversation exported by several devices (each hop on the path) is counted once: the largest of the
    # exporters' figures per conversation and time bucket. "none" adds them up (per-device views are never deduplicated).
    "dedup": "max_across_exporters",
    # interface view: when flows are seen on LAG members and on the LAG itself, count the members ("members") or the
    # logical interface ("logical"), never both
    "lag_mode": "members",
    # authorised services (detections never flag these addresses / networks)
    "snmp_managers": [],          # SNMP pollers / trap receivers besides this server's own addresses
    "dns_resolvers": [],          # approved DNS resolvers (internal or external)
    "mqtt_brokers": [],           # approved MQTT brokers
    "mqtt_clients": [],           # networks allowed to speak MQTT (empty: any internal host may reach an approved broker)
    "detection_exclusions": [],   # networks excluded from every traffic detection
    # enrichment (background loop; API requests never wait for it)
    "enrich_dns": True,           # correlate destination addresses with DNS answers in collected DNS logs
    "enrich_firewall_apps": True,  # use firewall application-control results for the same destination
    "enrich_asn": True,           # local GeoIP / ASN databases (no network access)
    "enrich_rdns": False,         # reverse DNS (PTR) lookups through the server's resolver: off by default
    "rdns_per_run": 100,
    "enrich_top_n": 2000,         # destinations enriched per run (by bytes, last 2 hours)
    "enrich_refresh_hours": 6,
    "alert_new_vlan_pairs": False,  # new (never seen) VLAN pairs as informational detections
}
LIST_KEYS = ("snmp_managers", "dns_resolvers", "mqtt_brokers", "mqtt_clients", "detection_exclusions")


async def load_settings(s: AsyncSession) -> dict:
    row = (await s.execute(select(TrafficSetting).order_by(TrafficSetting.id).limit(1))).scalars().first()
    return {**DEFAULTS, **((row.data or {}) if row else {})}


async def save_settings(s: AsyncSession, data: dict, user: str) -> dict:
    row = (await s.execute(select(TrafficSetting).order_by(TrafficSetting.id).limit(1))).scalars().first()
    if row is None:
        row = TrafficSetting(data={})
        s.add(row)
    row.data = {**(row.data or {}), **data}
    row.updated_by = user
    await s.flush()
    return {**DEFAULTS, **row.data}


def validate(data: dict) -> dict:
    """Public settings only (keys starting with "_" are internal); networks are normalised CIDRs."""
    out: dict = {}
    for k, v in data.items():
        if k.startswith("_") or k not in DEFAULTS:
            raise ValueError(f"unknown setting {k}")
        d = DEFAULTS[k]
        if k in LIST_KEYS:
            if not isinstance(v, list) or len(v) > 500:
                raise ValueError(f"{k}: a list of at most 500 networks")
            nets = []
            for x in v:
                try:
                    nets.append(str(ipaddress.ip_network(str(x).strip(), strict=False)))
                except ValueError:
                    raise ValueError(f"{k}: not an IP address or network: {x}")
            out[k] = sorted(set(nets))
        elif k == "dedup":
            if v not in ("max_across_exporters", "none"):
                raise ValueError("dedup: max_across_exporters or none")
            out[k] = v
        elif k == "lag_mode":
            if v not in ("members", "logical"):
                raise ValueError("lag_mode: members or logical")
            out[k] = v
        elif isinstance(d, bool):
            if not isinstance(v, bool):
                raise ValueError(f"{k}: true or false")
            out[k] = v
        elif isinstance(d, int):
            if not isinstance(v, int) or isinstance(v, bool) or not 0 <= v <= 100_000:
                raise ValueError(f"{k}: a whole number 0–100000")
            out[k] = v
    return out


def public(data: dict) -> dict:
    return {k: v for k, v in data.items() if not k.startswith("_")}
