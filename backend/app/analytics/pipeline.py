"""Pipeline query language (SPL / KQL style) → one parameterized ClickHouse query.

    <filter> | where <expr> | eval x=<expr> | stats count, dc(dst_ip) as dsts by src_ip | sort -count | head 20

The leading filter is the SIEM query language (analytics/ql.py), applied together with the time window and the
page filters. Commands:

    where <expr>                          keep rows where expr is true
    eval name=<expr>[, name=<expr>]       computed columns
    stats <agg>[ as n][, ...] [by f, ...] aggregate: count, count(f), dc, sum, avg, min, max, median, p50..p99,
                                          values, list, earliest, latest, range, stdev, var, countif, sumif
    timechart [span=5m] [limit=10] <agg>[ as n][, ...] [by f]
    top [N] f[, f2] [limit=N]  /  rare ...   most / least frequent values with percent
    sort [-]f[, ...]   head N   fields [-] f, ...   table f, ...   dedup f[, ...]   rename a as b[, ...]
    lookup <watchlist> <field> [as <prefix>]  adds <prefix>_match (0/1) and <prefix>_label
    where inwatchlist(field, "name")          watchlist membership inside any expression

Identifiers are allow-listed (event columns, query-language aliases, or columns produced by earlier commands),
functions come from a fixed table, and every literal is bound as a query parameter."""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ..db.ch_schema import EVENT_COLUMNS as SCHEMA_COLUMNS
from .ql import FIELDS as QL_FIELDS


class PipelineError(ValueError):
    pass


EVENT_COLUMNS = SCHEMA_COLUMNS
# query-language aliases that map to one column or expression (src → src_ip, bytes → sent+rcvd, ...)
ALIASES = {k: v[1] for k, v in QL_FIELDS.items() if isinstance(v[1], str) and k not in EVENT_COLUMNS}
ALIASES.update({"_time": "event_time", "bytes": "(sent_bytes + rcvd_bytes)", "fw": "firewall_name"})
DEFAULT_FIELDS = ["event_time", "firewall_name", "category", "event_type", "action", "src_ip", "src_port", "dst_ip", "dst_port",
                  "proto_name", "app", "hostname", "dns_qname", "policy_id", "user", "sent_bytes", "rcvd_bytes", "msg"]
MAX_ROWS = 10_000
DEFAULT_ROWS = 1_000
IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
IP_GUARD = "if(isIPv4String(toString({x})) OR isIPv6String(toString({x})), toString({x}), '::')"
PRIVATE_NETS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "100.64.0.0/10", "fc00::/7")

# ------------------------------------------------------------------ tokenizer
_TOK = re.compile(r"""\s*(?:
    (?P<num>\d+(?:\.\d+)?(?![A-Za-z_0-9.]))|
    (?P<str>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')|
    (?P<op>==|!=|<>|<=|>=|\|\||&&|[=<>+\-*/%(),])|
    (?P<ident>[A-Za-z_][A-Za-z0-9_]*|\d+[smhdw](?![A-Za-z0-9_]))
)""", re.X)


@dataclass
class Tok:
    kind: str
    value: str
    pos: int


def tokenize(text: str, base: int = 0) -> list[Tok]:
    out, i = [], 0
    while i < len(text):
        if text[i:].strip() == "":
            break
        m = _TOK.match(text, i)
        if not m or m.end() == i:
            raise PipelineError(f"unexpected character {text[i]!r} at position {base + i}")
        kind = m.lastgroup
        val = m.group(kind)
        if kind == "str":
            val = re.sub(r"\\(.)", r"\1", val[1:-1])
        out.append(Tok(kind, val, base + m.start(kind)))
        i = m.end()
    return out


def split_pipes(q: str) -> list[tuple[str, int]]:
    """Split on | outside quotes into (segment, offset) pairs; '||' is the boolean operator, not a pipe."""
    parts, cur, start, quote, i = [], [], 0, None, 0
    while i < len(q):
        c = q[i]
        if quote:
            cur.append(c)
            if c == "\\" and i + 1 < len(q):
                cur.append(q[i + 1])
                i += 1
            elif c == quote:
                quote = None
        elif c in "\"'":
            quote = c
            cur.append(c)
        elif c == "|" and q[i + 1:i + 2] == "|":
            cur.append("||")
            i += 1
        elif c == "|":
            parts.append(("".join(cur), start))
            cur, start = [], i + 1
        else:
            cur.append(c)
        i += 1
    if quote:
        raise PipelineError("unterminated string")
    parts.append(("".join(cur), start))
    return parts


def _q(name: str) -> str:
    return f"`{name}`"


# ------------------------------------------------------------------ relation being built
@dataclass
class Rel:
    """One SELECT. `cols` maps every name a later command may reference to an expression valid inside this SELECT."""
    source: str
    cols: dict[str, str]
    base: bool = False                                   # reads the events table directly
    where: list[str] = field(default_factory=list)
    select: list[tuple[str, str]] | None = None          # explicit projection; None = all (or default fields when shown)
    extras: list[tuple[str, str]] = field(default_factory=list)  # computed columns added to the implicit projection
    group_by: list[str] = field(default_factory=list)
    order_by: list[str] = field(default_factory=list)
    limit: int | None = None
    limit_by: tuple[int, list[str]] | None = None
    aggregated: bool = False
    display: list[str] | None = None                     # columns shown for raw events when nothing was projected

    def busy(self) -> bool:
        return bool(self.group_by or self.order_by or self.limit is not None or self.limit_by or self.aggregated)

    def output(self, final: bool = False) -> list[str]:
        if self.select is not None:
            return [a for _, a in self.select]
        extra = [a for _, a in self.extras]
        if final and self.display:
            return [c for c in self.display if c not in extra] + extra
        if self.base:
            return EVENT_COLUMNS + extra
        return [c for c in self.cols if c not in extra] + extra

    def expr_for(self, name: str) -> str:
        for e, a in (self.select or []) + self.extras:
            if a == name:
                return e
        if name in self.cols:
            return self.cols[name]
        if self.base and name in ALIASES:
            return ALIASES[name]
        raise PipelineError(f"unknown field '{name}'")


class Compiler:
    def __init__(self, watchlists: dict[str, dict] | None = None):
        self.params: dict[str, Any] = {}
        self.n = 0
        self.watchlists = watchlists or {}
        self.kind = "events"
        self.timechart: dict | None = None

    def param(self, value, typ: str) -> str:
        name = f"pl{self.n}"
        self.n += 1
        self.params[name] = value
        return f"{{{name}:{typ}}}"

    @staticmethod
    def name(tok: Tok | None) -> str:
        if tok is None or tok.kind != "ident" or not IDENT.match(tok.value):
            raise PipelineError(f"invalid name {tok.value if tok else '<end>'!r}" + (f" at position {tok.pos}" if tok else ""))
        return tok.value

    # -------------------------------------------------- rendering
    def render(self, r: Rel, final: bool = False, cap: int | None = None, probe: bool = True) -> str:
        if r.select is not None:
            items = [e if e == _q(a) else f"{e} AS {_q(a)}" for e, a in r.select]
        elif final and r.display:
            extra = {a for _, a in r.extras}
            items = [r.cols[c] if r.cols[c] in (c, _q(c)) else f"{r.cols[c]} AS {_q(c)}" for c in r.display if c in r.cols and c not in extra]
            items += [f"{e} AS {_q(a)}" for e, a in r.extras]
        else:
            items = ["*"] + [f"{e} AS {_q(a)}" for e, a in r.extras]
        sql = f"SELECT {', '.join(items)} FROM {r.source}"
        if r.where:
            sql += " WHERE " + " AND ".join(f"({w})" for w in r.where)
        if r.group_by:
            sql += " GROUP BY " + ", ".join(r.group_by)
        if r.order_by:
            sql += " ORDER BY " + ", ".join(r.order_by)
        if r.limit_by:
            sql += f" LIMIT {r.limit_by[0]} BY " + ", ".join(r.limit_by[1])
        if final:
            sql += f" LIMIT {cap + 1 if probe else cap}"
        elif r.limit is not None:
            sql += f" LIMIT {r.limit}"
        return sql

    def wrap(self, r: Rel) -> Rel:
        out = r.output()
        display = (r.display + [a for _, a in r.extras]) if r.select is None and r.display else None
        return Rel(source=f"({self.render(r)})", cols={c: _q(c) for c in out}, display=display)

    def free(self, r: Rel, projection_ok: bool = True) -> Rel:
        """A relation a new clause can be added to without changing the meaning of what is already there."""
        if r.busy() or (not projection_ok and (r.select is not None or r.extras)):
            return self.wrap(r)
        return r

    # -------------------------------------------------- expressions
    def _kw(self, toks, i, *words) -> bool:
        return i < len(toks) and toks[i].kind == "ident" and toks[i].value.upper() in words

    def _op(self, toks, i, *ops) -> bool:
        return i < len(toks) and toks[i].kind == "op" and toks[i].value in ops

    @staticmethod
    def _at(toks, i) -> str:
        return f"position {toks[i].pos}" if i < len(toks) else "end of command"

    def expr(self, toks, i, r):
        left, i = self._and(toks, i, r)
        while self._kw(toks, i, "OR") or self._op(toks, i, "||"):
            right, i = self._and(toks, i + 1, r)
            left = f"({left} OR {right})"
        return left, i

    def _and(self, toks, i, r):
        left, i = self._not(toks, i, r)
        while self._kw(toks, i, "AND") or self._op(toks, i, "&&"):
            right, i = self._not(toks, i + 1, r)
            left = f"({left} AND {right})"
        return left, i

    def _not(self, toks, i, r):
        if self._kw(toks, i, "NOT"):
            inner, i = self._not(toks, i + 1, r)
            return f"(NOT {inner})", i
        return self._cmp(toks, i, r)

    def _cmp(self, toks, i, r):
        left, i = self._add(toks, i, r)
        if self._op(toks, i, "=", "==", "!=", "<>", "<", "<=", ">", ">="):
            op = {"==": "=", "<>": "!="}.get(toks[i].value, toks[i].value)
            right, i = self._add(toks, i + 1, r)
            return f"({left} {op} {right})", i
        neg = False
        if self._kw(toks, i, "NOT") and (self._kw(toks, i + 1, "IN") or self._kw(toks, i + 1, "LIKE")):
            neg, i = True, i + 1
        if self._kw(toks, i, "IN"):
            if not self._op(toks, i + 1, "("):
                raise PipelineError(f"expected '(' after IN at {self._at(toks, i + 1)}")
            items, i = self._args(toks, i + 2, r)
            if not items:
                raise PipelineError("IN () needs at least one value")
            return f"({left} {'NOT IN' if neg else 'IN'} ({', '.join(items)}))", i
        if self._kw(toks, i, "LIKE"):
            pat, i = self._add(toks, i + 1, r)
            return f"({'NOT ' if neg else ''}toString({left}) ILIKE replaceAll({pat}, '*', '%'))", i
        return left, i

    def _add(self, toks, i, r):
        left, i = self._mul(toks, i, r)
        while self._op(toks, i, "+", "-"):
            op = toks[i].value
            right, i = self._mul(toks, i + 1, r)
            left = f"({left} {op} {right})"
        return left, i

    def _mul(self, toks, i, r):
        left, i = self._unary(toks, i, r)
        while self._op(toks, i, "*", "/", "%"):
            op = toks[i].value
            right, i = self._unary(toks, i + 1, r)
            left = f"({left} {op} {right})"
        return left, i

    def _unary(self, toks, i, r):
        if self._op(toks, i, "-"):
            inner, i = self._unary(toks, i + 1, r)
            return f"(-{inner})", i
        return self._primary(toks, i, r)

    def _args(self, toks, i, r) -> tuple[list[str], int]:
        args = []
        if self._op(toks, i, ")"):
            return args, i + 1
        while True:
            e, i = self.expr(toks, i, r)
            args.append(e)
            if self._op(toks, i, ","):
                i += 1
                continue
            if self._op(toks, i, ")"):
                return args, i + 1
            raise PipelineError(f"expected ',' or ')' at {self._at(toks, i)}")

    def _primary(self, toks, i, r):
        if i >= len(toks):
            raise PipelineError("unexpected end of expression")
        t = toks[i]
        if t.kind == "num":
            v = float(t.value) if "." in t.value else int(t.value)
            return self.param(v, "Float64" if isinstance(v, float) else "Int64"), i + 1
        if t.kind == "str":
            return self.param(t.value, "String"), i + 1
        if self._op(toks, i, "("):
            e, i = self.expr(toks, i + 1, r)
            if not self._op(toks, i, ")"):
                raise PipelineError(f"expected ')' at {self._at(toks, i)}")
            return f"({e})", i + 1
        if t.kind == "ident":
            low = t.value.lower()
            if low in ("true", "false"):
                return ("1" if low == "true" else "0"), i + 1
            if self._op(toks, i + 1, "("):
                if low == "inwatchlist":
                    return self._inwatchlist(toks, i + 2, r)
                args, j = self._args(toks, i + 2, r)
                return self.func(low, args, t.pos), j
            return self.col(t, r), i + 1
        raise PipelineError(f"unexpected {t.value!r} at position {t.pos}")

    def col(self, t: Tok, r: Rel) -> str:
        try:
            return r.expr_for(t.value) if t.kind == "ident" else self._bad(t)
        except PipelineError:
            hint = "" if r.base else " (after stats/top/timechart only their output columns are available)"
            raise PipelineError(f"unknown field '{t.value}' at position {t.pos}{hint}") from None

    @staticmethod
    def _bad(t: Tok):
        raise PipelineError(f"expected a field name at position {t.pos}")

    def func(self, name: str, a: list[str], pos: int) -> str:
        def need(lo, hi=None):
            hi = lo if hi is None else hi
            if not lo <= len(a) <= hi:
                raise PipelineError(f"{name}() takes {lo if lo == hi else f'{lo}-{hi}'} argument(s) (position {pos})")
        simple = {"lower": "lower", "upper": "upper", "len": "lengthUTF8", "abs": "abs", "floor": "floor", "ceil": "ceil",
                  "tostring": "toString", "tonumber": "toFloat64OrZero", "trim": "trimBoth", "log": "log", "sqrt": "sqrt",
                  "domain": "cutToFirstSignificantSubdomain", "isempty": "empty", "isnotempty": "notEmpty",
                  "hour": "toHour", "dayofweek": "toDayOfWeek", "mvcount": "length", "date": "toDate"}
        stringy = {"len", "tonumber", "domain", "trim", "lower", "upper", "isempty", "isnotempty"}
        if name in simple:
            need(1)
            return f"{simple[name]}({'toString(' + a[0] + ')' if name in stringy else a[0]})"
        if name == "round":
            need(1, 2)
            return f"round({a[0]}, {a[1] if len(a) > 1 else 0})"
        if name == "if":
            need(3)
            return f"if({a[0]}, {a[1]}, {a[2]})"
        if name == "case":
            if len(a) < 2:
                raise PipelineError("case(cond1, value1[, cond2, value2 ...][, default]) needs at least 2 arguments")
            return f"multiIf({', '.join(a + ([] if len(a) % 2 else ['NULL']))})"
        if name == "coalesce":
            need(1, 8)
            return f"coalesce({', '.join(a)})"
        if name in ("isnull", "isnotnull"):
            need(1)
            e = f"(isNull({a[0]}) OR toString({a[0]}) = '')"
            return e if name == "isnull" else f"(NOT {e})"
        if name == "concat":
            need(1, 8)
            return "concat(" + ", ".join(f"toString({x})" for x in a) + ")"
        if name == "substr":
            need(2, 3)
            return f"substringUTF8(toString({a[0]}), {', '.join(a[1:])})"
        if name == "contains":
            need(2)
            return f"(positionCaseInsensitive(toString({a[0]}), {a[1]}) > 0)"
        if name in ("startswith", "endswith"):
            need(2)
            return f"{'startsWith' if name == 'startswith' else 'endsWith'}(lower(toString({a[0]})), lower({a[1]}))"
        if name == "match":
            need(2)
            return f"match(toString({a[0]}), {a[1]})"
        if name == "cidrmatch":
            need(2)
            return f"isIPAddressInRange({IP_GUARD.format(x=a[1])}, {a[0]})"
        if name == "isprivate":
            need(1)
            g = IP_GUARD.format(x=a[0])
            return "(" + " OR ".join(f"isIPAddressInRange({g}, '{c}')" for c in PRIVATE_NETS) + ")"
        if name in ("least", "greatest"):
            need(2)
            return f"{name}({a[0]}, {a[1]})"
        if name == "pow":
            need(2)
            return f"pow({a[0]}, {a[1]})"
        if name == "now":
            need(0)
            return "now64(3)"
        if name == "strftime":
            need(2)
            return f"formatDateTime({a[0]}, {a[1]})"
        if name == "mvjoin":
            need(2)
            return f"arrayStringConcat(arrayMap(x -> toString(x), {a[0]}), {a[1]})"
        raise PipelineError(f"unknown function '{name}' (position {pos})")

    # -------------------------------------------------- watchlists
    def wl(self, name: str, pos: int) -> dict:
        w = self.watchlists.get(name)
        if w is None:
            raise PipelineError(f"unknown watchlist '{name}' (position {pos})")
        return w

    def wl_match(self, w: dict, x: str) -> str:
        kind = w.get("kind", "string")
        if kind == "ip":
            exact = self.param([v for v in w["values"] if "/" not in v], "Array(String)")
            nets = self.param([v for v in w["values"] if "/" in v], "Array(String)")
            g = IP_GUARD.format(x=x)
            return f"(has({exact}, toString({x})) OR arrayExists(c -> isIPAddressInRange({g}, c), {nets}))"
        vals = self.param([v.lower() for v in w["values"]], "Array(String)")
        if kind == "domain":
            return f"arrayExists(d -> (lower(toString({x})) = d OR endsWith(lower(toString({x})), concat('.', d))), {vals})"
        return f"has({vals}, lower(toString({x})))"

    def wl_label(self, w: dict, x: str) -> str:
        values = w["values"]
        labels = list(w.get("labels") or [""] * len(values))
        if w.get("kind") == "ip":
            ex = [(v, l) for v, l in zip(values, labels) if "/" not in v]
            nt = [(v, l) for v, l in zip(values, labels) if "/" in v]
            ek, el = self.param([v for v, _ in ex], "Array(String)"), self.param([l for _, l in ex], "Array(String)")
            nk, nl = self.param([v for v, _ in nt], "Array(String)"), self.param([l for _, l in nt], "Array(String)")
            g = IP_GUARD.format(x=x)
            return (f"if(has({ek}, toString({x})), {el}[indexOf({ek}, toString({x}))], "
                    f"arrayElement({nl}, arrayFirstIndex(c -> isIPAddressInRange({g}, c), {nk})))")
        keys = self.param([v.lower() for v in values], "Array(String)")
        lab = self.param(labels, "Array(String)")
        if w.get("kind") == "domain":
            return (f"arrayElement({lab}, arrayFirstIndex(d -> (lower(toString({x})) = d OR "
                    f"endsWith(lower(toString({x})), concat('.', d))), {keys}))")
        return f"arrayElement({lab}, indexOf({keys}, lower(toString({x}))))"

    def _inwatchlist(self, toks, i, r):
        x, i = self.expr(toks, i, r)
        if not self._op(toks, i, ",") or i + 1 >= len(toks) or toks[i + 1].kind not in ("str", "ident"):
            raise PipelineError('usage: inwatchlist(field, "watchlist name")')
        w = self.wl(toks[i + 1].value, toks[i + 1].pos)
        if not self._op(toks, i + 2, ")"):
            raise PipelineError("expected ')' after inwatchlist arguments")
        return self.wl_match(w, x), i + 3

    # -------------------------------------------------- aggregations
    AGG = {"dc": "uniqExact", "distinct_count": "uniqExact", "sum": "sum", "avg": "avg", "mean": "avg", "min": "min",
           "max": "max", "median": "median", "stdev": "stddevPop", "var": "varPop", "values": "groupUniqArray(50)",
           "list": "groupArray(50)"}

    def agg(self, toks, i, r) -> tuple[str, str, int]:
        t = toks[i]
        if t.kind != "ident":
            raise PipelineError(f"expected an aggregation at position {t.pos}")
        fn = t.value.lower()
        i += 1
        args, raw = [], []
        if self._op(toks, i, "("):
            start = i + 1
            args, i = self._args(toks, i + 1, r)
            raw = [x.value for x in toks[start:i - 1] if x.kind == "ident"]
        pm = re.fullmatch(r"p(?:erc)?(\d{1,2})", fn)

        def one():
            if len(args) != 1:
                raise PipelineError(f"{fn}() takes one argument (position {t.pos})")
            return args[0]
        if fn == "count":
            sql = "count()" if not args else f"countIf(NOT (isNull({one()}) OR toString({one()}) = ''))"
        elif fn in self.AGG:
            sql = f"{self.AGG[fn]}({one()})"
        elif pm:
            sql = f"quantile({int(pm.group(1)) / 100})({one()})"
        elif fn in ("earliest", "first", "latest", "last"):
            try:
                tcol = r.expr_for("event_time")
            except PipelineError:
                raise PipelineError(f"{fn}() needs event_time") from None
            sql = f"{'argMin' if fn in ('earliest', 'first') else 'argMax'}({one()}, {tcol})"
        elif fn == "range":
            x = one()
            sql = f"(max({x}) - min({x}))"
        elif fn == "countif":
            sql = f"countIf({one()})"
        elif fn == "sumif":
            if len(args) != 2:
                raise PipelineError("sumif(field, condition) takes two arguments")
            sql = f"sumIf({args[0]}, {args[1]})"
        else:
            raise PipelineError(f"unknown aggregation '{fn}' at position {t.pos}")
        alias = (fn if not raw else f"{fn}_{'_'.join(re.sub(r'[^A-Za-z0-9_]', '_', x) for x in raw[:2])}")[:60]
        if self._kw(toks, i, "AS"):
            alias, i = self.name(toks[i + 1] if i + 1 < len(toks) else None), i + 2
        return sql, alias, i

    def agg_list(self, toks, i, r) -> tuple[list[tuple[str, str]], int]:
        aggs: list[tuple[str, str]] = []
        while i < len(toks) and not self._kw(toks, i, "BY") and not self._opt_at(toks, i):
            sql, alias, i = self.agg(toks, i, r)
            if alias in [a for _, a in aggs]:
                raise PipelineError(f"duplicate output name '{alias}'; use 'as' to rename")
            aggs.append((sql, alias))
            if self._op(toks, i, ","):
                i += 1
        if not aggs:
            raise PipelineError("expected at least one aggregation, e.g. count or sum(sent_bytes)")
        return aggs, i

    def _opt_at(self, toks, i) -> bool:
        return i < len(toks) and toks[i].kind == "ident" and toks[i].value.lower() in ("span", "limit") and self._op(toks, i + 1, "=")

    def field_list(self, toks, i, r) -> tuple[list[tuple[str, str]], int]:
        out: list[tuple[str, str]] = []
        while i < len(toks):
            if self._op(toks, i, ","):
                i += 1
                continue
            t = toks[i]
            if t.kind != "ident" or self._opt_at(toks, i) or self._kw(toks, i, "AS"):
                break
            out.append((self.col(t, r), self.name(t)))
            i += 1
        return out, i

    def options(self, toks, i) -> tuple[dict, int]:
        opts = {}
        while self._opt_at(toks, i):
            if i + 2 >= len(toks):
                raise PipelineError(f"missing value for {toks[i].value}")
            opts[toks[i].value.lower()] = toks[i + 2].value
            i += 3
        return opts, i

    @staticmethod
    def done(toks, i):
        if i < len(toks):
            raise PipelineError(f"unexpected {toks[i].value!r} at position {toks[i].pos}")

    # -------------------------------------------------- commands
    def cmd_where(self, toks, r):
        r = self.free(r)
        e, i = self.expr(toks, 0, r)
        self.done(toks, i)
        r.where.append(e)
        return r

    def cmd_eval(self, toks, r):
        r = self.free(r)
        i = 0
        while i < len(toks):
            name = self.name(toks[i])
            if not self._op(toks, i + 1, "="):
                raise PipelineError(f"expected '=' after '{name}' in eval")
            e, i = self.expr(toks, i + 2, r)
            if r.select is not None:
                r.select = [(x, a) for x, a in r.select if a != name] + [(e, name)]
            else:
                r.extras = [(x, a) for x, a in r.extras if a != name] + [(e, name)]
            r.cols = {**r.cols, name: _q(name)}
            if self._op(toks, i, ","):
                i += 1
            elif i < len(toks):
                raise PipelineError(f"expected ',' between eval assignments at {self._at(toks, i)}")
        return r

    def cmd_stats(self, toks, r):
        r = self.free(r, projection_ok=False)
        aggs, i = self.agg_list(toks, 0, r)
        by: list[tuple[str, str]] = []
        if self._kw(toks, i, "BY"):
            by, i = self.field_list(toks, i + 1, r)
            if not by:
                raise PipelineError("expected field names after 'by'")
        self.done(toks, i)
        r.select, r.extras, r.display = by + aggs, [], None
        r.group_by = [_q(n) for _, n in by]
        r.aggregated = True
        r.base = False
        r.cols = {n: _q(n) for _, n in r.select}
        self.kind = "table"
        return r

    def cmd_timechart(self, toks, r):
        r = self.free(r, projection_ok=False)
        try:
            tcol = r.expr_for("event_time")
        except PipelineError:
            raise PipelineError("timechart needs event_time: put it before stats") from None
        opts, i = self.options(toks, 0)
        aggs, i = self.agg_list(toks, i, r)
        by: list[tuple[str, str]] = []
        if self._kw(toks, i, "BY"):
            by, i = self.field_list(toks, i + 1, r)
            if len(by) != 1:
                raise PipelineError("timechart supports exactly one 'by' field")
        more, i = self.options(toks, i)
        opts.update(more)
        self.done(toks, i)
        span = parse_span(opts.get("span", "auto"))
        bucket = f"toStartOfInterval({tcol}, INTERVAL {span} SECOND)" if span else f"toStartOfInterval({tcol}, INTERVAL __SPAN__ SECOND)"
        r.select, r.extras, r.display = [(bucket, "_time")] + by + aggs, [], None
        r.group_by = ["`_time`"] + [_q(n) for _, n in by]
        r.order_by = ["`_time` ASC"]
        r.aggregated = True
        r.base = False
        r.cols = {n: _q(n) for _, n in r.select}
        self.kind = "timechart"
        try:
            lim = int(opts.get("limit", 10))
        except ValueError:
            raise PipelineError("timechart limit must be a number") from None
        self.timechart = {"by": by[0][1] if by else None, "values": [a for _, a in aggs], "limit": lim, "span": span}
        return r

    def cmd_top(self, toks, r, rare=False):
        r = self.free(r, projection_ok=False)
        i, n = 0, 10
        if i < len(toks) and toks[i].kind == "num":
            n, i = int(float(toks[i].value)), i + 1
        opts, i = self.options(toks, i)
        fields, i = self.field_list(toks, i, r)
        more, i = self.options(toks, i)
        opts.update(more)
        self.done(toks, i)
        if not fields:
            raise PipelineError(f"{'rare' if rare else 'top'} needs at least one field")
        try:
            n = int(opts.get("limit", n))
        except ValueError:
            raise PipelineError("limit must be a number") from None
        r.select, r.extras, r.display = fields + [("count()", "count"), ("round(100 * count() / sum(count()) OVER (), 2)", "percent")], [], None
        r.group_by = [_q(nm) for _, nm in fields]
        r.order_by = [f"`count` {'ASC' if rare else 'DESC'}"]
        r.limit = max(1, min(n, MAX_ROWS))
        r.aggregated = True
        r.base = False
        r.cols = {nm: _q(nm) for _, nm in r.select}
        self.kind = "table"
        return r

    def cmd_rare(self, toks, r):
        return self.cmd_top(toks, r, rare=True)

    def cmd_sort(self, toks, r):
        if r.limit is not None or r.limit_by:
            r = self.wrap(r)
        i, order = 0, []
        while i < len(toks):
            if self._op(toks, i, ","):
                i += 1
                continue
            desc = False
            if self._op(toks, i, "-", "+"):
                desc, i = toks[i].value == "-", i + 1
            if i >= len(toks):
                raise PipelineError("sort: expected a field name")
            e = self.col(toks[i], r)
            i += 1
            if self._kw(toks, i, "DESC", "ASC"):
                desc, i = toks[i].value.upper() == "DESC", i + 1
            order.append(f"{e} {'DESC' if desc else 'ASC'}")
        if not order:
            raise PipelineError("sort: expected a field name")
        r.order_by = order
        return r

    def cmd_head(self, toks, r):
        n = 10
        if toks:
            if toks[0].kind != "num" or len(toks) > 1:
                raise PipelineError("head takes a single number")
            n = int(float(toks[0].value))
        n = max(1, min(n, MAX_ROWS))
        r.limit = n if r.limit is None else min(r.limit, n)
        return r

    def cmd_fields(self, toks, r):
        exclude = self._op(toks, 0, "-")
        fields, i = self.field_list(toks, 1 if exclude else 0, r)
        self.done(toks, i)
        if not fields:
            raise PipelineError("fields needs at least one field name")
        names = [n for _, n in fields]
        keep = [c for c in r.output(final=True) if c not in names] if exclude else names
        r.select = [(r.expr_for(n), n) for n in keep]
        r.extras, r.display = [], None
        if not r.base:
            r.cols = {n: _q(n) for n in keep}
        return r

    def cmd_rename(self, toks, r):
        i, mapping = 0, {}
        while i < len(toks):
            if self._op(toks, i, ","):
                i += 1
                continue
            if not self._kw(toks, i + 1, "AS") or i + 2 >= len(toks):
                raise PipelineError("usage: rename <field> as <new name>[, ...]")
            self.col(toks[i], r)
            mapping[toks[i].value] = self.name(toks[i + 2])
            i += 3
        if not mapping:
            raise PipelineError("usage: rename <field> as <new name>[, ...]")
        r = self.wrap(r) if r.busy() else r
        current = r.output(final=True)
        r.select = [(r.expr_for(c), mapping.get(c, c)) for c in current]
        r.extras = []
        r.display = None
        return self.wrap(r)

    def cmd_dedup(self, toks, r):
        if r.limit is not None or r.limit_by:
            r = self.wrap(r)
        fields, i = self.field_list(toks, 0, r)
        self.done(toks, i)
        if not fields:
            raise PipelineError("dedup needs at least one field")
        r.limit_by = (1, [e for e, _ in fields])
        if not r.order_by and "event_time" in r.cols:
            r.order_by = [f"{r.cols['event_time']} DESC"]
        return r

    def cmd_lookup(self, toks, r):
        if len(toks) < 2 or toks[0].kind not in ("ident", "str"):
            raise PipelineError("usage: lookup <watchlist> <field> [as <prefix>]")
        w = self.wl(toks[0].value, toks[0].pos)
        r = self.free(r)
        x = self.col(toks[1], r)
        prefix = re.sub(r"[^A-Za-z0-9_]", "_", toks[0].value)[:40] or "wl"
        if not IDENT.match(prefix):
            prefix = f"wl_{prefix}"
        i = 2
        if self._kw(toks, i, "AS"):
            prefix, i = self.name(toks[i + 1] if i + 1 < len(toks) else None), i + 2
        self.done(toks, i)
        new = [(f"toUInt8({self.wl_match(w, x)})", f"{prefix}_match"), (self.wl_label(w, x), f"{prefix}_label")]
        if r.select is not None:
            r.select = r.select + new
        else:
            r.extras = r.extras + new
        r.cols = {**r.cols, **{a: _q(a) for _, a in new}}
        return r


COMMANDS = {"where", "eval", "stats", "timechart", "top", "rare", "sort", "head", "limit", "fields", "table", "rename",
            "dedup", "lookup"}
_DISPATCH = {"limit": "head", "table": "fields"}


def parse_span(s: str) -> int | None:
    if s in ("", "auto"):
        return None
    m = re.fullmatch(r"(\d+)([smhdw])", s.strip())
    if not m:
        raise PipelineError(f"invalid span '{s}' (use e.g. 30s, 5m, 1h, 1d)")
    v = int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[m.group(2)]
    if v < 10:
        raise PipelineError("span must be at least 10s")
    return v


@dataclass
class Plan:
    search: str          # leading query-language filter
    sql: str             # contains {base_where} (time window + filters) and possibly __SPAN__
    params: dict
    kind: str            # events | table | timechart
    timechart: dict | None
    cap: int             # rows returned
    probe: bool          # the query fetches cap + 1 rows to detect that the system row cap truncated the result


def watchlist_names(q: str) -> set[str]:
    out = set()
    for a, b, c in re.findall(r"\|\s*lookup\s+(?:\"([^\"]+)\"|'([^']+)'|([A-Za-z0-9_]+))", q, re.I):
        out.add(a or b or c)
    for a, b in re.findall(r"inwatchlist\s*\([^,]+,\s*(?:\"([^\"]+)\"|'([^']+)')", q, re.I):
        out.add(a or b)
    return out


def compile_pipeline(q: str, watchlists: dict[str, dict] | None = None, max_rows: int | None = None) -> Plan:
    q = (q or "").strip()
    if len(q) > 4000:
        raise PipelineError("query too long (max 4000 characters)")
    segs = split_pipes(q)
    search = segs[0][0].strip()
    if search.lower().startswith("search "):
        search = search[7:].strip()
    if len(segs) > 21:
        raise PipelineError("too many commands (max 20)")
    c = Compiler(watchlists)
    r = Rel(source="events", cols={x: x for x in EVENT_COLUMNS}, where=["{base_where}"], base=True, display=list(DEFAULT_FIELDS))
    for text, off in segs[1:]:
        toks = tokenize(text, off)
        if not toks:
            raise PipelineError(f"empty command after '|' at position {off}")
        cmd = toks[0].value.lower()
        if toks[0].kind != "ident" or cmd not in COMMANDS:
            raise PipelineError(f"unknown command '{toks[0].value}' at position {toks[0].pos} (available: {', '.join(sorted(COMMANDS))})")
        r = getattr(c, f"cmd_{_DISPATCH.get(cmd, cmd)}")(toks[1:], r)
    if c.kind == "events" and not r.order_by and not r.limit_by and "event_time" in r.cols and not r.aggregated:
        r.order_by = [f"{r.cols['event_time']} DESC"]
    hard = min(max_rows or MAX_ROWS, MAX_ROWS)
    default = hard if c.kind != "events" else min(DEFAULT_ROWS, hard)
    probe = r.limit is None or r.limit > hard
    cap = default if r.limit is None else min(r.limit, hard)
    return Plan(search=search, sql=c.render(r, final=True, cap=cap, probe=probe), params=c.params, kind=c.kind,
                timechart=c.timechart, cap=cap, probe=probe)


def _jsonable(v):
    if isinstance(v, datetime):
        return v.isoformat()
    if isinstance(v, float) and v != v:
        return None
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v]
    return v


async def run_pipeline(ch, q: str, f, watchlists: dict[str, dict] | None = None, max_rows: int | None = None) -> dict:
    """Execute a pipeline over the events selected by EventFilter f (time window, firewalls, ...)."""
    from .filters import bucket_seconds, build_where
    plan = compile_pipeline(q, watchlists, max_rows)
    f.ql = plan.search or None
    where, wparams = build_where(f)
    sql = plan.sql.replace("{base_where}", where)
    if "__SPAN__" in sql:
        t0, t1 = f.window()
        span = bucket_seconds(t0, t1, 120)
        sql = sql.replace("__SPAN__", str(span))
        plan.timechart["span"] = span
    started = time.monotonic()
    rows = await ch.aquery(sql, {**wparams, **plan.params})
    elapsed = int((time.monotonic() - started) * 1000)
    truncated = plan.probe and len(rows) > plan.cap
    rows = [{k: _jsonable(v) for k, v in r.items()} for r in rows[:plan.cap]]
    out = {"kind": plan.kind, "columns": list(rows[0].keys()) if rows else [], "rows": rows, "elapsed_ms": elapsed,
           "truncated": truncated, "search": plan.search}
    if plan.kind == "timechart" and plan.timechart:
        out.update(pivot_timechart(rows, plan.timechart))
    return out


def pivot_timechart(rows: list[dict], tc: dict) -> dict:
    """Long rows (_time, by, value) → one row per bucket with a column per series (top `limit` + OTHER)."""
    by, values, limit = tc["by"], tc["values"], max(1, min(int(tc.get("limit") or 10), 50))
    if not by:
        return {"series": values, "span": tc.get("span")}
    val = values[0]
    totals: dict[str, float] = {}
    for r in rows:
        k = "" if r.get(by) is None else str(r.get(by))
        totals[k] = totals.get(k, 0) + float(r.get(val) or 0)
    keep = [k for k, _ in sorted(totals.items(), key=lambda kv: -kv[1])[:limit]]
    other = len(totals) > len(keep)
    label = {k: (k or "(empty)") for k in keep}
    pivot: dict[str, dict] = {}
    for r in rows:
        k = "" if r.get(by) is None else str(r.get(by))
        s = label.get(k, "OTHER")
        row = pivot.setdefault(r["_time"], {})
        row[s] = row.get(s, 0) + float(r.get(val) or 0)
    series = [label[k] for k in keep] + (["OTHER"] if other else [])
    out_rows = [{"_time": t, **{s: v.get(s, 0) for s in series}} for t, v in sorted(pivot.items())]
    return {"rows": out_rows, "columns": ["_time", *series], "series": series, "span": tc.get("span"), "value": val}
