"""Read-only FortiGate policy collection (GET requests only).

Endpoints (FortiOS 6.4/7.x REST API):
  /api/v2/cmdb/firewall/policy            configured policies, returned in evaluation (sequence) order
  /api/v2/cmdb/firewall/address|addrgrp|address6|addrgrp6, firewall.service/custom|group, system/zone
  /api/v2/monitor/firewall/policy         per-policy statistics (hit_count, bytes, packets, first/last used) where the
                                          FortiOS version and access profile expose it; absence is recorded, never faked
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from ..db.ch import ClickHouse
from ..db.models import Firewall, PolicySync
from ..fortigate.client import FortiGateAuthError, FortiGateError, FortiGateNotSupported
from ..fortigate.service import build_client
from .model import normalize_policy
from .store import parse_counters, refresh_assessments, run_analysis, store_counters, store_objects, store_policies

log = logging.getLogger("policy.collector")
OBJECT_PATHS = {
    "address": "/api/v2/cmdb/firewall/address", "addrgrp": "/api/v2/cmdb/firewall/addrgrp",
    "address6": "/api/v2/cmdb/firewall/address6", "addrgrp6": "/api/v2/cmdb/firewall/addrgrp6",
    "service_custom": "/api/v2/cmdb/firewall.service/custom", "service_group": "/api/v2/cmdb/firewall.service/group",
    "zone": "/api/v2/cmdb/system/zone",
}


async def sync_firewall(s: AsyncSession, ch: ClickHouse, fw: Firewall, vdom: str | None = None) -> PolicySync:
    vdom = vdom or fw.vdom or "root"
    # capture identifiers now: a rollback in an error path expires ORM objects, and lazy loads fail under asyncio
    fw_id, fw_name = fw.id, fw.name
    st = await s.get(PolicySync, (fw_id, vdom))
    if st is None:
        st = PolicySync(firewall_id=fw.id, vdom=vdom, details={})
        s.add(st)
    st.last_attempt = datetime.now(timezone.utc)
    details: dict = {}
    client = build_client(fw)
    client.cfg.vdom = vdom
    try:
        body = await client.get("/api/v2/cmdb/firewall/policy")
        raw = [p for p in body.get("results") or [] if isinstance(p, dict) and p.get("policyid") is not None]
        policies = [normalize_policy(p, seq) for seq, p in enumerate(raw, start=1)]
        details["changes"] = await store_policies(s, fw.id, vdom, policies, "api")
        objects, errors = {}, {}
        for kind, path in OBJECT_PATHS.items():
            try:
                objects[kind] = (await client.get(path)).get("results") or []
            except FortiGateNotSupported:
                errors[kind] = "not_found"
            except FortiGateAuthError as e:
                if e.status == 401:
                    raise
                errors[kind] = "forbidden"
        await store_objects(s, fw.id, vdom, objects, errors)
        try:
            cbody = await client.get("/api/v2/monitor/firewall/policy")
            counters = parse_counters(cbody.get("results") if isinstance(cbody.get("results"), list) else [])
            st.counters_supported = bool(counters) and any(c["hit_count"] is not None for c in counters)
            if counters:
                await store_counters(ch, fw.id, vdom, counters, "api")
            details["counters"] = len(counters)
        except (FortiGateNotSupported, FortiGateAuthError) as e:
            if isinstance(e, FortiGateAuthError) and e.status == 401:
                raise
            st.counters_supported = False
            details["counters_error"] = str(e)
        try:  # configuration drift snapshot (read-only GETs); never blocks policy analytics
            from ..drift import snapshot_firewall
            snap = await snapshot_firewall(s, client, fw, vdom)
            if snap:
                details["config_snapshot"] = snap.id
        except Exception as e:
            await s.rollback()
            log.exception("config snapshot failed for %s/%s", fw_name, vdom)
            details["drift_error"] = f"{type(e).__name__}: {e}"[:300]
            st = await s.get(PolicySync, (fw_id, vdom))
        run = await run_analysis(s, fw.id, vdom)
        details["analysis_run"] = run.id
        try:
            await refresh_assessments(s, ch, fw.id, vdom, st.counters_supported)
        except Exception as e:  # configuration/counters are stored; report the assessment failure, don't hide it
            await s.rollback()
            log.exception("usage assessment failed for %s/%s", fw_name, vdom)
            details["assessment_error"] = f"{type(e).__name__}: {e}"[:500]
        st.policies = len(policies)
        st.status = "partial" if errors or not st.counters_supported or details.get("assessment_error") else "ok"
        st.error = "; ".join(filter(None, [f"objects unavailable: {errors}" if errors else None, details.get("assessment_error")])) or None
        st.last_success = datetime.now(timezone.utc)
    except FortiGateError as e:
        st.status, st.error = "error", str(e)[:1000]
        log.warning("policy sync failed for %s/%s: %s", fw_name, vdom, e)
    except Exception as e:  # never leave the status at "never" after an unexpected failure
        await s.rollback()
        st = await s.get(PolicySync, (fw_id, vdom)) or st
        st.last_attempt = datetime.now(timezone.utc)
        st.status, st.error = "error", f"{type(e).__name__}: {e}"[:1000]
        log.exception("policy sync crashed for %s/%s", fw_name, vdom)
    finally:
        await client.close()
    st.details = details
    await s.commit()
    return st
