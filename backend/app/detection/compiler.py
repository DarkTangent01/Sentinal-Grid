"""Compile a YAML rule into one parameterised ClickHouse query.

Safety: field names come only from schema.FIELDS (validated twice: at load and here), operators from a fixed table,
and every value — strings, numbers, lists, CIDRs, regexes, time zones — is passed as a bound query parameter. Nothing
from rule content is ever concatenated into the SQL text except allow-listed column names.

The same SQL runs against the `events` table (production) or against inline JSON rows through ClickHouse's
`format(JSONEachRow, …)` table function (rule tests), so tests exercise exactly what runs in production.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .schema import FIELDS, IP_FIELDS, NUMERIC, WEEKDAYS, Rule


@dataclass
class Compiled:
    sql: str
    params: dict[str, Any] = field(default_factory=dict)


class _Params:
    def __init__(self):
        self.values: dict[str, Any] = {}

    def add(self, value: Any, typ: str) -> str:
        name = f"p{len(self.values)}"
        self.values[name] = value
        return f"{{{name}:{typ}}}"


def _col(name: str) -> str:
    if name not in FIELDS:          # defence in depth: schema validation already rejects these
        raise ValueError(f"unknown field {name!r}")
    return f"`{name}`"


def _ipexpr(col: str) -> str:
    return f"if(isIPv4String({col}) OR isIPv6String({col}), {col}, '::')"


def _scalar_type(fname: str, v: Any) -> tuple[Any, str]:
    if fname in NUMERIC:
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            try:
                v = float(v) if "." in str(v) else int(str(v))
            except ValueError:
                raise ValueError(f"{fname} is numeric; {v!r} is not a number")
        return v, ("Float64" if isinstance(v, float) else "Int64")
    return str(v), "String"


def _clause(fname: str, spec: Any, p: _Params, cidrs_ref: str) -> str:
    col = _col(fname)
    if isinstance(spec, list):
        spec = {"in": spec}
    elif not isinstance(spec, dict):
        spec = {"eq": spec}
    parts = []
    for op, val in spec.items():
        if op == "eq":
            v, t = _scalar_type(fname, val)
            parts.append(f"{col} = {p.add(v, t)}")
        elif op == "ne":
            v, t = _scalar_type(fname, val)
            parts.append(f"{col} != {p.add(v, t)}")
        elif op in ("in", "not_in"):
            vals = [_scalar_type(fname, x) for x in val]
            t = "Float64" if any(tt == "Float64" for _, tt in vals) else vals[0][1]
            parts.append(f"{col} {'NOT IN' if op == 'not_in' else 'IN'} {p.add([v for v, _ in vals], f'Array({t})')}")
        elif op == "contains":
            parts.append(f"positionCaseInsensitive({col}, {p.add(str(val), 'String')}) > 0")
        elif op == "startswith":
            parts.append(f"startsWith(lower({col}), {p.add(str(val).lower(), 'String')})")
        elif op == "endswith":
            parts.append(f"endsWith(lower({col}), {p.add(str(val).lower(), 'String')})")
        elif op == "regex":
            parts.append(f"match({col}, {p.add(str(val), 'String')})")
        elif op in ("gt", "gte", "lt", "lte"):
            sym = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[op]
            parts.append(f"{col} {sym} {p.add(float(val), 'Float64')}")
        elif op in ("cidr", "not_cidr"):
            expr = f"arrayExists(c -> isIPAddressInRange({_ipexpr(col)}, c), {p.add([str(c) for c in val], 'Array(String)')})"
            parts.append(f"NOT {expr}" if op == "not_cidr" else expr)
        elif op == "internal":
            if fname not in IP_FIELDS:
                raise ValueError(f"{fname}: internal applies to IP fields")
            expr = f"((isIPv4String({col}) OR isIPv6String({col})) AND arrayExists(c -> isIPAddressInRange({_ipexpr(col)}, c), {cidrs_ref}))"
            parts.append(expr if val else f"((isIPv4String({col}) OR isIPv6String({col})) AND NOT {expr})")
        elif op == "exists":
            null = FIELDS[fname].startswith("Nullable")
            present = f"isNotNull({col})" if null else (f"{col} != ''" if fname not in NUMERIC else f"{col} != 0")
            parts.append(present if val else f"NOT ({present})")
        else:
            raise ValueError(f"unknown operator {op!r}")
    return "(" + " AND ".join(parts) + ")"


def _block(sel: dict | list | None, p: _Params, cidrs_ref: str) -> str | None:
    if not sel:
        return None
    blocks = sel if isinstance(sel, list) else [sel]
    ors = []
    for b in blocks:
        ands = [_clause(f, spec, p, cidrs_ref) for f, spec in b.items()]
        if ands:
            ors.append("(" + " AND ".join(ands) + ")")
    return "(" + " OR ".join(ors) + ")" if ors else None


def compile_rule(rule: Rule, *, t0: datetime, t1: datetime, cidrs: list[str], threshold: float | None = None,
                 source: str = "events", source_params: dict | None = None, limit: int = 200) -> Compiled:
    """SELECT one row per group that reaches the threshold in [t0, t1)."""
    p = _Params()
    p.values.update(source_params or {})
    cidrs_ref = p.add(list(cidrs), "Array(String)")
    d, c = rule.detection, rule.detection.condition
    where = [f"`category` = {p.add(rule.log_source.category, 'String')}",
             f"`event_time` >= {p.add(t0, 'DateTime64(3)')}",
             f"`event_time` < {p.add(t1, 'DateTime64(3)')}"]
    if rule.log_source.event_type:
        where.append(f"`event_type` = {p.add(rule.log_source.event_type, 'String')}")
    sel = _block(d.selection, p, cidrs_ref)
    if sel:
        where.append(sel)
    flt = _block(d.filter, p, cidrs_ref)
    if flt:
        where.append(f"NOT {flt}")
    for fname, vals in rule.allowlist.items():
        if fname in IP_FIELDS:
            nets = [str(v) for v in vals]
            where.append(f"NOT arrayExists(c -> isIPAddressInRange({_ipexpr(_col(fname))}, c), {p.add(nets, 'Array(String)')})")
        else:
            where.append(f"NOT {_clause(fname, {'in': vals}, p, cidrs_ref)}")
    if d.outside_hours:
        oh = d.outside_hours
        tz = p.add(oh.timezone, "String")
        mod = f"(toHour(`event_time`, {tz}) * 60 + toMinute(`event_time`, {tz}))"
        days = p.add([WEEKDAYS[x] for x in oh.days], "Array(UInt8)")
        s, e = p.add(oh.minutes("start"), "UInt16"), p.add(oh.minutes("end"), "UInt16")
        where.append(f"NOT (has({days}, toDayOfWeek(`event_time`, 0, {tz})) AND {mod} >= {s} AND {mod} < {e})")
    if c.count is not None:
        metric, sample = "count()", "groupUniqArray(5)(`msg`)"
    elif c.distinct_count:
        col = _col(c.distinct_count.field)
        metric, sample = f"uniqExact({col})", f"arraySlice(groupUniqArray(50)(toString({col})), 1, 20)"
    else:
        col = _col(c.sum.field)  # type: ignore[union-attr]
        metric, sample = f"sum({col})", "groupUniqArray(5)(`dst_ip`)"
    groups = ", ".join(_col(g) for g in c.group_by)
    thr = p.add(float(threshold if threshold is not None else c.threshold), "Float64")
    sql = (f"SELECT {', '.join(f'toString({_col(g)}) AS `g_{g}`' for g in c.group_by)}, toFloat64({metric}) AS metric, count() AS events, "
           f"min(`event_time`) AS first_seen, max(`event_time`) AS last_seen, {sample} AS samples, "
           f"arraySlice(groupUniqArray(10)(`firewall_id`), 1, 10) AS firewall_ids, arraySlice(groupUniqArray(10)(`site`), 1, 10) AS sites "
           f"FROM {source} WHERE {' AND '.join(where)} GROUP BY {groups} HAVING metric >= {thr} "
           f"ORDER BY metric DESC LIMIT {int(limit)}")
    return Compiled(sql, p.values)


def inline_source() -> tuple[str, dict]:
    """`format(JSONEachRow, <structure>, {data})` covering event_time and every allowed column."""
    structure = ", ".join(["`event_time` DateTime64(3, 'UTC')"] + [f"`{k}` {t}" for k, t in FIELDS.items()])
    return "format(JSONEachRow, {structure:String}, {data:String})", {"structure": structure}
