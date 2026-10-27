"""Conservative shadow / redundancy analysis for FortiGate firewall policies.

Evaluation model: firewall policies are matched top-down in sequence order (the order returned by the cmdb API);
the first enabled policy whose interfaces, addresses, services and schedule match is applied. A later policy L is a
*potential full shadow* of an earlier policy E only when E's match space provably covers L's in every dimension.
Anything that cannot be evaluated statically (FQDN/dynamic/geo addresses, ISDB, user identity, negation, custom
schedules, missing objects) prevents a full-shadow conclusion and is reported as an assumption."""
from __future__ import annotations

from dataclasses import dataclass, field

from .objects import ObjectResolver, _names
from .sets import AddrSpace

FULL, PARTIAL, NONE, UNKNOWN = "full", "partial", "none", "unknown"


@dataclass
class Space:
    policy: dict
    srcintf: set | None  # None = any
    dstintf: set | None
    src: AddrSpace
    dst: AddrSpace
    svc: object
    src_unc: list = field(default_factory=list)
    dst_unc: list = field(default_factory=list)
    svc_unc: list = field(default_factory=list)
    other_unc: list = field(default_factory=list)  # identity / ISDB / negation
    missing: list = field(default_factory=list)


def _intf(names: list[str], zones: dict[str, list[str]]) -> set | None:
    if not names or "any" in names:
        return None
    out = set()
    for n in names:
        out |= set(zones.get(n, [n]))
    return out


def build_space(p: dict, res: ObjectResolver, zones: dict[str, list[str]]) -> Space:
    src, dst, svc = res.address(p["srcaddr"]), res.address(p["dstaddr"]), res.service(p["service"])
    other = []
    if p["identity"]:
        other.append(f"policy {p['policyid']} matches only specific users/devices ({', '.join(p['identity'])})")
    if p["isdb"]:
        other.append(f"policy {p['policyid']} uses Internet Service Database objects ({', '.join(p['isdb'])})")
    for k, on in p["negate"].items():
        if on:
            other.append(f"policy {p['policyid']} negates {k}")
    return Space(p, _intf(p["srcintf"], zones), _intf(p["dstintf"], zones), src.space, dst.space, svc.space,
                 src.uncertain, dst.uncertain, svc.uncertain, other, src.missing + dst.missing + svc.missing)


def _intf_cov(e: set | None, l: set | None) -> str:
    if e is None:
        return FULL
    if l is None:
        return PARTIAL  # later is "any", earlier is specific
    if l <= e:
        return FULL
    return PARTIAL if e & l else NONE


def _addr_cov(e: AddrSpace, l: AddrSpace, e_unc: list, l_unc: list) -> str:
    if e_unc:
        # earlier contains objects we cannot evaluate: coverage cannot be proven; intersection may exist
        return UNKNOWN
    if l_unc:
        return FULL if e.covers(AddrSpace.any4().union(AddrSpace.any6())) else UNKNOWN
    if e.covers(l):
        return FULL
    return PARTIAL if e.intersection(l) else NONE


def _svc_cov(e, l, e_unc, l_unc) -> str:
    if e_unc:
        return UNKNOWN
    from .sets import ServiceSpace
    if l_unc:
        return FULL if e.covers(ServiceSpace.any()) else UNKNOWN
    if e.covers(l):
        return FULL
    return PARTIAL if e.intersects(l) else NONE


def compare(e: Space, l: Space) -> dict:
    ep, lp = e.policy, l.policy
    dims = {
        "srcintf": _intf_cov(e.srcintf, l.srcintf),
        "dstintf": _intf_cov(e.dstintf, l.dstintf),
        "source": _addr_cov(e.src, l.src, e.src_unc, l.src_unc),
        "destination": _addr_cov(e.dst, l.dst, e.dst_unc, l.dst_unc),
        "service": _svc_cov(e.svc, l.svc, e.svc_unc, l.svc_unc),
        "schedule": FULL if ep["schedule"] in ("always", lp["schedule"]) else UNKNOWN,
    }
    if e.other_unc:  # earlier only matches a subset (identity/ISDB/negation): never provably covering
        dims = {k: (UNKNOWN if v == FULL else v) for k, v in dims.items()}
    return dims


def classify(dims: dict, e: Space, l: Space) -> tuple[str, str] | None:
    vals = set(dims.values())
    if NONE in vals:
        return None
    ep, lp = e.policy, l.policy
    action_differs = ep["action"] != lp["action"]
    if vals == {FULL}:
        same = (not action_differs and ep["profiles"] == lp["profiles"] and ep["nat"] == lp["nat"])
        if same:
            return "redundant", "low"
        return "full_shadow", "high" if action_differs else "medium"
    if UNKNOWN in vals:
        # report only strong candidates: every dimension we *can* evaluate is fully covered
        if all(v in (FULL, UNKNOWN) for v in vals):
            return "overlap", "low"
        return None
    # exact computation, at least one partial dimension
    n_partial = sum(1 for v in dims.values() if v == PARTIAL)
    if ep["action"] == "deny" and lp["action"] == "accept":
        return "partial_shadow", "medium"  # part of the intended allow is blocked earlier
    if not action_differs and n_partial == 1:
        return "partial_shadow", "low"  # near-duplicate: earlier rule already handles most of it
    # earlier specific accept above a broader deny is the normal "exception, then deny" pattern: not a finding
    return None


def _explain(kind: str, dims: dict, e: Space, l: Space) -> str:
    ep, lp = e.policy, l.policy
    label = {"full_shadow": "fully covers", "redundant": "fully covers (same action/profiles)",
             "partial_shadow": "partially covers", "overlap": "may cover (unverifiable conditions)"}[kind]
    s = (f"Earlier policy {ep['policyid']} ({ep['name'] or 'unnamed'}, seq {ep['seq']}, {ep['action']}) {label} the match space of "
         f"later policy {lp['policyid']} ({lp['name'] or 'unnamed'}, seq {lp['seq']}, {lp['action']}).")
    if kind == "full_shadow" and ep["action"] != lp["action"]:
        s += f" Traffic intended for policy {lp['policyid']} is {ep['action']}ed by policy {ep['policyid']} first."
    elif kind in ("full_shadow", "redundant"):
        s += f" Policy {lp['policyid']} should never receive new sessions while {ep['policyid']} stays above it."
    elif kind == "partial_shadow":
        partial = [k for k, v in dims.items() if v == PARTIAL]
        s += f" Overlap is partial in: {', '.join(partial)}; the overlapping part is handled by policy {ep['policyid']}."
    return s


def analyze(policies: list[dict], objects: dict, max_per_policy: int = 5) -> dict:
    """policies: normalized, in sequence order. Returns {"findings": [...], "policy_status": {policyid: {...}}}."""
    res = ObjectResolver(objects)
    zones = {z.get("name"): _names(z.get("interface")) for z in objects.get("zone", []) or []}
    spaces = [build_space(p, res, zones) for p in sorted(policies, key=lambda x: x["seq"])]
    findings, status = [], {}
    for idx, l in enumerate(spaces):
        lp = l.policy
        st = {"analysis": "analyzed", "uncertain": l.src_unc + l.dst_unc + l.svc_unc + l.other_unc, "missing": l.missing,
              "shadowed_by": None}
        if lp["status"] != "enable":
            st["analysis"] = "disabled"
            status[lp["policyid"]] = st
            continue
        if l.missing:
            st["analysis"] = "unknown"
        count = 0
        for e in spaces[:idx]:
            if e.policy["status"] != "enable":
                continue
            dims = compare(e, l)
            c = classify(dims, e, l)
            if not c:
                continue
            kind, sev = c
            assumptions = e.src_unc + e.dst_unc + e.svc_unc + e.other_unc + l.src_unc + l.dst_unc + l.svc_unc + l.other_unc
            if dims["schedule"] == UNKNOWN:
                assumptions.append(f"schedules differ ('{e.policy['schedule']}' vs '{lp['schedule']}'); time overlap not evaluated")
            confidence = "low" if kind == "overlap" else ("medium" if any("assumed" in a for a in assumptions) else "high")
            ep = e.policy
            findings.append({
                "earlier_policyid": ep["policyid"], "earlier_name": ep["name"], "earlier_seq": ep["seq"], "earlier_action": ep["action"],
                "later_policyid": lp["policyid"], "later_name": lp["name"], "later_seq": lp["seq"], "later_action": lp["action"],
                "classification": kind, "severity": sev, "confidence": confidence, "dimensions": dims,
                "explanation": _explain(kind, dims, e, l),
                "evidence": {"earlier": {"source": e.src.describe(), "destination": e.dst.describe(), "service": e.svc.describe(),
                                         "srcintf": ep["srcintf"], "dstintf": ep["dstintf"], "schedule": ep["schedule"]},
                             "later": {"source": l.src.describe(), "destination": l.dst.describe(), "service": l.svc.describe(),
                                       "srcintf": lp["srcintf"], "dstintf": lp["dstintf"], "schedule": lp["schedule"]}},
                "assumptions": sorted(set(assumptions)),
                "verification": [
                    "In the FortiGate GUI open Policy & Objects > Firewall Policy (sequence view) and confirm the order.",
                    f"Use Policy Lookup (or 'diagnose firewall iprope lookup') with traffic intended for policy {lp['policyid']} "
                    f"and confirm which policy matches.",
                    f"Compare hit counters of policy {lp['policyid']} over a long period before changing anything.",
                ],
            })
            if kind in ("full_shadow", "redundant") and st["shadowed_by"] is None:
                st["shadowed_by"] = ep["policyid"]
            count += 1
            if count >= max_per_policy:
                break
        status[lp["policyid"]] = st
    return {"findings": findings, "policy_status": status, "policies_analyzed": len(spaces)}
