"""Read-only configuration snapshots and drift detection (GET requests only)."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .db.models import AlertRule, ConfigSnapshot, Firewall, FirewallPolicy
from .fortigate.client import FortiGateAuthError, FortiGateError, FortiGateNotSupported

# table -> (path, key field, kept fields). Secrets (passwords, keys) are never requested or stored.
TABLES = {
    "interface": ("/api/v2/cmdb/system/interface", "name", ["name", "role", "type", "mode", "ip", "allowaccess", "status", "vdom"]),
    "admin": ("/api/v2/cmdb/system/admin", "name", ["name", "accprofile", "vdom", "two-factor", *[f"trusthost{i}" for i in range(1, 11)],
                                                   *[f"ip6-trusthost{i}" for i in range(1, 11)]]),
    "global": ("/api/v2/cmdb/system/global", None, ["admin-sport", "admin-port", "admin-ssh-port", "admin-telnet-port", "admin-telnet",
                                                    "admin-https-redirect", "admintimeout", "admin-lockout-threshold", "strong-crypto",
                                                    "admin-maintainer", "hostname"]),
    "sslvpn": ("/api/v2/cmdb/vpn.ssl/settings", None, ["status", "port", "source-interface", "source-address", "servercert",
                                                       "login-attempt-limit", "login-block-time", "default-portal"]),
}
INSECURE_ACCESS = {"http", "telnet"}
MGMT_ACCESS = {"https", "ssh", "http", "telnet", "snmp", "fgfm"}


def _names(v):
    if isinstance(v, list):
        return sorted(x.get("name", str(x)) if isinstance(x, dict) else str(x) for x in v)
    return v


def _slim(item: dict, keep: list[str]) -> dict:
    out = {}
    for k in keep:
        if k in item:
            v = item[k]
            out[k] = _names(v) if isinstance(v, list) else v
    return out


async def collect(client, fw: Firewall, s: AsyncSession, vdom: str) -> tuple[dict, dict]:
    data, errors = {}, {}
    for table, (path, key, keep) in TABLES.items():
        try:
            res = (await client.get(path)).get("results")
            if key is None:
                obj = res[0] if isinstance(res, list) and res else (res or {})
                data[table] = _slim(obj, keep)
            else:
                data[table] = {str(r.get(key)): _slim(r, keep) for r in (res or []) if isinstance(r, dict)}
        except FortiGateNotSupported:
            errors[table] = "not_found"
        except FortiGateAuthError as e:
            if e.status == 401:
                raise
            errors[table] = "forbidden"
        except FortiGateError as e:
            errors[table] = f"error: {e}"[:200]
    pols = (await s.execute(select(FirewallPolicy).where(FirewallPolicy.firewall_id == fw.id, FirewallPolicy.vdom == vdom,
                                                         FirewallPolicy.deleted_at.is_(None)))).scalars().all()
    data["policy"] = {str(p.policyid): {k: p.config.get(k) for k in ("name", "status", "action", "srcintf", "dstintf", "srcaddr",
                      "dstaddr", "service", "schedule", "nat", "logtraffic", "seq")} for p in pols}
    return data, errors


def diff(old: dict, new: dict) -> list[dict]:
    changes = []
    for table in sorted(set(old) | set(new)):
        a, b = old.get(table), new.get(table)
        if a is None or b is None:
            continue
        keyed = all(isinstance(v, dict) for v in list(a.values()) + list(b.values())) and table not in ("global", "sslvpn")
        if not keyed:
            fields = sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))
            if fields:
                changes.append({"table": table, "key": "", "change": "modified", "fields": {f: [a.get(f), b.get(f)] for f in fields}})
            continue
        for k in sorted(set(a) | set(b)):
            if k not in a:
                changes.append({"table": table, "key": k, "change": "added", "new": b[k]})
            elif k not in b:
                changes.append({"table": table, "key": k, "change": "removed", "old": a[k]})
            else:
                fields = sorted(f for f in set(a[k]) | set(b[k]) if f != "seq" and a[k].get(f) != b[k].get(f))
                if fields:
                    changes.append({"table": table, "key": k, "change": "modified", "fields": {f: [a[k].get(f), b[k].get(f)] for f in fields}})
    return changes


def _access(v) -> set:
    if isinstance(v, list):
        return set(v)
    return set((v or "").split())


def _no_trusthost(admin: dict) -> bool:
    hosts = [v for k, v in admin.items() if "trusthost" in k]
    return not hosts or all(str(h).replace("0.0.0.0", "").replace("::/0", "").strip(" /0") == "" for h in hosts)


def assess_risks(snapshot: dict, changes: list[dict] | None) -> list[dict]:
    """With changes=None, report risky settings present in the snapshot (baseline). Otherwise only risks the changes introduced."""
    risks = []

    def add(sev, table, key, title, detail):
        risks.append({"severity": sev, "table": table, "key": key, "title": title, "detail": detail})

    targets = None
    if changes is not None:
        targets = {(c["table"], c["key"]) for c in changes if c["change"] in ("added", "modified")}

    def wanted(table, key=""):
        return targets is None or (table, key) in targets

    for pid, p in (snapshot.get("policy") or {}).items():
        if not wanted("policy", pid) or p.get("status") != "enable":
            continue
        if p.get("action") == "accept" and "all" in (p.get("srcaddr") or []) and "all" in (p.get("dstaddr") or []) \
                and "ALL" in (p.get("service") or []):
            add("high", "policy", pid, f"Policy {pid} ({p.get('name') or 'unnamed'}) accepts any source → any destination, all services",
                "Broad any/any/ALL accept rules bypass segmentation.")
        if p.get("logtraffic") == "disable" and p.get("action") == "accept":
            add("medium", "policy", pid, f"Policy {pid} ({p.get('name') or 'unnamed'}) has traffic logging disabled", "Traffic through it is invisible to the SIEM.")
    interfaces = snapshot.get("interface") or {}
    for name, i in interfaces.items():
        if not wanted("interface", name):
            continue
        acc = _access(i.get("allowaccess"))
        insecure = acc & INSECURE_ACCESS
        if insecure:
            add("high", "interface", name, f"Interface {name} allows insecure management ({', '.join(sorted(insecure))})", "HTTP/Telnet send credentials in clear text.")
        if i.get("role") == "wan" and acc & MGMT_ACCESS:
            add("high", "interface", name, f"WAN interface {name} allows management access ({', '.join(sorted(acc & MGMT_ACCESS))})",
                "Exposes the FortiGate management plane to the internet.")
    for name, a in (snapshot.get("admin") or {}).items():
        if not wanted("admin", name):
            continue
        if _no_trusthost(a):
            add("high", "admin", name, f"Administrator {name} has no trusted hosts", "The account can log in from any address.")
        if a.get("accprofile") == "super_admin" and a.get("two-factor") in (None, "", "disable"):
            add("medium", "admin", name, f"Super-admin {name} without two-factor authentication", "")
    if changes is not None:
        for c in changes:
            if c["table"] == "admin" and c["change"] == "added":
                add("medium", "admin", c["key"], f"New administrator account {c['key']}", f"Profile: {c['new'].get('accprofile')}")
    g = snapshot.get("global") or {}
    if wanted("global"):
        if g.get("admin-https-redirect") == "disable":
            add("low", "global", "", "HTTP→HTTPS admin redirect disabled", "")
        if g.get("strong-crypto") == "disable":
            add("medium", "global", "", "strong-crypto disabled", "Weak ciphers allowed for management and VPN.")
        if g.get("admin-telnet") == "enable":
            add("high", "global", "", "Telnet administration enabled globally", "")
    return risks


def config_hash(data: dict) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, default=str).encode()).hexdigest()[:24]


async def snapshot_firewall(s: AsyncSession, client, fw: Firewall, vdom: str) -> ConfigSnapshot | None:
    """Store a snapshot when configuration changed; raise alerts for risks introduced by the change."""
    try:
        data, errors = await collect(client, fw, s, vdom)
    except FortiGateError:
        return None
    h = config_hash(data)
    prev = (await s.execute(select(ConfigSnapshot).where(ConfigSnapshot.firewall_id == fw.id, ConfigSnapshot.vdom == vdom)
                            .order_by(ConfigSnapshot.collected_at.desc()).limit(1))).scalars().first()
    if prev and prev.config_hash == h:
        return None
    changes = diff(prev.data, data) if prev else []
    risks = assess_risks(data, changes if prev else None)
    snap = ConfigSnapshot(firewall_id=fw.id, vdom=vdom, collected_at=datetime.now(timezone.utc), config_hash=h, data=data,
                          changes=changes, risks=[{**r, "baseline": prev is None} for r in risks], errors=errors)
    s.add(snap)
    await s.commit()
    if prev and risks:
        await raise_risk_alerts(s, fw, vdom, risks, snap)
    return snap


async def raise_risk_alerts(s: AsyncSession, fw: Firewall, vdom: str, risks: list[dict], snap: ConfigSnapshot) -> None:
    from .alerts.engine import Detection, upsert_detections
    rule = (await s.execute(select(AlertRule).where(AlertRule.key == "risky_config_change"))).scalar_one_or_none()
    if not rule or not rule.enabled:
        return
    now = snap.collected_at
    dets = [Detection(group_key=f"{fw.id}|{vdom}|{r['table']}|{r['key']}|{r['title']}", count=1, first_seen=now, last_seen=now,
                      firewall_ids=[fw.id], sites=[fw.site] if fw.site else [], severity=r["severity"],
                      explanation=f"{fw.name}/{vdom}: {r['title']}. {r['detail']} Detected in configuration snapshot #{snap.id}.",
                      evidence={"snapshot_id": snap.id, **r}, event_filter={"firewall_id": [fw.id], "category": ["system"]})
            for r in risks]
    touched: list = []
    await upsert_detections(s, rule, dets, now, touched)
    from .incidents import correlate_alerts
    from .notify import alert_created
    await correlate_alerts(s, [a for a, _ in touched], now)
    for a, created in touched:
        if created:
            await alert_created(s, a)
    await s.commit()
