"""SIEM query language → parameterized ClickHouse WHERE clause.

    query   := orexpr
    orexpr  := andexpr ( OR andexpr )*
    andexpr := unary ( [AND] unary )*          (adjacent terms are ANDed)
    unary   := (NOT | -) unary | '(' orexpr ')' | field (':' | '>' | '>=' | '<' | '<=' | '!=') value | text
    value   := "quoted string" | bare-token     (* wildcards; a-b ranges and CIDR where the field allows)

Only allow-listed fields are accepted; every value is bound as a query parameter."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field


class QLError(ValueError):
    def __init__(self, msg: str, pos: int):
        super().__init__(f"{msg} (at position {pos})")
        self.pos = pos


PROTO = {"icmp": 1, "tcp": 6, "udp": 17, "gre": 47, "esp": 50, "icmpv6": 58, "sctp": 132}
# field -> (kind, column(s))
FIELDS: dict[str, tuple[str, object]] = {
    "src_ip": ("ip", "src_ip"), "src": ("ip", "src_ip"), "dst_ip": ("ip", "dst_ip"), "dst": ("ip", "dst_ip"),
    "ip": ("ip", ("src_ip", "dst_ip")), "nat_ip": ("ip", "nat_src_ip"),
    "src_port": ("int", "src_port"), "dst_port": ("int", "dst_port"), "port": ("int", "dst_port"),
    "proto": ("proto", "proto"), "policy": ("int", "policy_id"), "asn": ("int", "dst_asn"),
    "bytes": ("int", "(sent_bytes + rcvd_bytes)"), "sent": ("int", "sent_bytes"), "rcvd": ("int", "rcvd_bytes"),
    "duration": ("int", "duration"),
    "action": ("str", "action"), "category": ("str", "category"), "severity": ("str", "severity"),
    "type": ("str", "event_type"), "subtype": ("str", "event_subtype"), "source": ("str", "source"), "vdom": ("str", "vdom"),
    "qtype": ("str", "dns_qtype"), "rcode": ("str", "dns_rcode"), "tunnel": ("str", "vpn_tunnel"),
    "app": ("str", "app"), "service": ("str", "service"), "user": ("str", "user"), "firewall": ("str", "firewall_name"),
    "site": ("str", "site"), "src_country": ("str", "src_country"), "dst_country": ("str", "dst_country"),
    "country": ("str", ("src_country", "dst_country")), "as_org": ("str", "dst_as_org"), "os": ("str", "src_os"),
    "mac": ("str", "src_mac"), "name": ("str", "src_name"), "url_category": ("str", "url_category"),
    "ti": ("str", "ti_match"), "ti_category": ("str", "ti_category"),
    "domain": ("domain", None), "hostname": ("domain", None),
    "url": ("text", "url"), "qname": ("text", "dns_qname"), "query": ("text", "dns_qname"), "threat": ("text", "threat"),
    "msg": ("text", "msg"), "raw": ("text", "raw"),
}
TOKEN = re.compile(r'\s*(?:(?P<lp>\()|(?P<rp>\))|(?P<str>"(?:[^"\\]|\\.)*")|(?P<op>>=|<=|!=|:|>|<)|(?P<word>[^\s()":<>!=]+(?:[=!][^\s()":<>]+)*))')


@dataclass
class Tok:
    kind: str
    value: str
    pos: int


def tokenize(q: str) -> list[Tok]:
    out, i = [], 0
    while i < len(q):
        m = TOKEN.match(q, i)
        if not m or m.end() == i:
            if q[i:].strip() == "":
                break
            raise QLError(f"unexpected character {q[i]!r}", i)
        kind = m.lastgroup
        val = m.group(kind)
        if kind == "str":
            val = val[1:-1].replace('\\"', '"').replace("\\\\", "\\")
        out.append(Tok(kind, val, m.start(kind)))
        i = m.end()
    return out


@dataclass
class Compiled:
    sql: str
    params: dict = field(default_factory=dict)


class _P:
    def __init__(self, toks: list[Tok], prefix: str):
        self.t, self.i, self.params, self.prefix, self.n = toks, 0, {}, prefix, 0

    def peek(self, k: int = 0) -> Tok | None:
        return self.t[self.i + k] if self.i + k < len(self.t) else None

    def take(self) -> Tok:
        tok = self.peek()
        if tok is None:
            raise QLError("unexpected end of query", self.t[-1].pos if self.t else 0)
        self.i += 1
        return tok

    def param(self, value, typ: str) -> str:
        name = f"{self.prefix}{self.n}"
        self.n += 1
        self.params[name] = value
        return f"{{{name}:{typ}}}"

    def kw(self, word: str) -> bool:
        tok = self.peek()
        return bool(tok and tok.kind == "word" and tok.value.upper() == word)

    def orexpr(self) -> str:
        parts = [self.andexpr()]
        while self.kw("OR"):
            self.take()
            parts.append(self.andexpr())
        return parts[0] if len(parts) == 1 else "(" + " OR ".join(parts) + ")"

    def andexpr(self) -> str:
        parts = [self.unary()]
        while True:
            tok = self.peek()
            if tok is None or tok.kind == "rp" or self.kw("OR"):
                break
            if self.kw("AND"):
                self.take()
            parts.append(self.unary())
        return parts[0] if len(parts) == 1 else "(" + " AND ".join(parts) + ")"

    def unary(self) -> str:
        tok = self.peek()
        if tok is None:
            raise QLError("expected a term", self.t[-1].pos if self.t else 0)
        if self.kw("NOT"):
            self.take()
            return f"NOT ({self.unary()})"
        if tok.kind == "word" and tok.value.startswith("-") and len(tok.value) > 1:
            tok.value = tok.value[1:]
            return f"NOT ({self.unary()})"
        if tok.kind == "lp":
            self.take()
            inner = self.orexpr()
            closing = self.take()
            if closing.kind != "rp":
                raise QLError("expected ')'", closing.pos)
            return f"({inner})"
        if tok.kind == "word" and self.peek(1) and self.peek(1).kind == "op":
            name = tok.value.lower()
            if name not in FIELDS:
                raise QLError(f"unknown field '{tok.value}' (allowed: {', '.join(sorted(FIELDS))})", tok.pos)
            self.take()
            op = self.take().value
            v = self.take()
            if v.kind not in ("word", "str"):
                raise QLError("expected a value", v.pos)
            return self.term(name, op, v)
        if tok.kind in ("word", "str"):
            self.take()
            return f"positionCaseInsensitive(raw, {self.param(tok.value, 'String')}) > 0"
        raise QLError(f"unexpected {tok.value!r}", tok.pos)

    def term(self, name: str, op: str, v: Tok) -> str:
        kind, col = FIELDS[name]
        val = v.value
        neg = op == "!="
        if op == "!=":
            op = ":"
        cols = col if isinstance(col, tuple) else (col,)

        def any_of(fn):
            exprs = [fn(c) for c in cols]
            e = exprs[0] if len(exprs) == 1 else "(" + " OR ".join(exprs) + ")"
            return f"NOT {e}" if neg else e

        if val == "*" and op == ":":
            return any_of(lambda c: f"({c} IS NOT NULL AND toString({c}) NOT IN ('', '0'))")
        if kind == "ip":
            if op != ":":
                raise QLError(f"'{name}' supports ':' only", v.pos)
            try:
                if "/" in val:
                    net = str(ipaddress.ip_network(val, strict=False))
                    p = self.param(net, "String")
                    return any_of(lambda c: f"isIPAddressInRange(if(isIPv4String({c}) OR isIPv6String({c}), {c}, '::'), {p})")
                p = self.param(str(ipaddress.ip_address(val)), "String")
            except ValueError:
                raise QLError(f"invalid IP or CIDR '{val}'", v.pos) from None
            return any_of(lambda c: f"{c} = {p}")
        if kind in ("int", "proto"):
            if kind == "proto" and not val.isdigit():
                if val.lower() not in PROTO:
                    raise QLError(f"unknown protocol '{val}'", v.pos)
                val = str(PROTO[val.lower()])
            m = re.fullmatch(r"(\d+)-(\d+)", val)
            if m and op == ":":
                a, b = self.param(int(m.group(1)), "Int64"), self.param(int(m.group(2)), "Int64")
                return any_of(lambda c: f"({c} >= {a} AND {c} <= {b})")
            if not val.isdigit():
                raise QLError(f"'{name}' expects a number or range", v.pos)
            p = self.param(int(val), "Int64")
            sqlop = {":": "=", ">": ">", ">=": ">=", "<": "<", "<=": "<="}[op]
            return any_of(lambda c: f"{c} {sqlop} {p}")
        if op != ":":
            raise QLError(f"'{name}' supports ':' and '!=' only", v.pos)
        if kind == "domain":
            d = self.param(val.lower().lstrip("*.").rstrip("."), "String")
            e = (f"(lower(hostname) = {d} OR endsWith(lower(hostname), concat('.', {d})) OR dns_qname = {d} "
                 f"OR endsWith(dns_qname, concat('.', {d})))")
            return f"NOT {e}" if neg else e
        if kind == "text":
            p = self.param(val.replace("*", ""), "String")
            return any_of(lambda c: f"positionCaseInsensitive({c}, {p}) > 0")
        if "*" in val:  # wildcard → case-insensitive LIKE with escaped metacharacters
            like = val.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_").replace("*", "%")
            p = self.param(like, "String")
            return any_of(lambda c: f"{c} ILIKE {p}")
        p = self.param(val, "String")
        return any_of(lambda c: f"lower({c}) = lower({p})")


def compile_ql(q: str, prefix: str = "ql") -> Compiled:
    q = (q or "").strip()
    if not q:
        return Compiled("1")
    if len(q) > 2000:
        raise QLError("query too long", 2000)
    toks = tokenize(q)
    if not toks:
        return Compiled("1")
    p = _P(toks, prefix)
    sql = p.orexpr()
    if p.peek() is not None:
        raise QLError(f"unexpected {p.peek().value!r}", p.peek().pos)
    return Compiled(sql, p.params)
