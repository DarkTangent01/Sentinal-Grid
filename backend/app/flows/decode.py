"""Flow export decoders: NetFlow v5, NetFlow v9, IPFIX (v10) and sFlow v5. Pure Python, no dependency.

Every decoder returns normalised records:
  {"ts", "version" (netflow5 | netflow9 | ipfix | sflow5), "in_if", "out_if", "src_ip", "dst_ip", "src_port", "dst_port", "proto", "bytes", "packets", "vlan", "sampling",
   "src_mac", "dst_mac", "tcp_flags", "dst_vlan", "l7"} (MACs / flags / destination VLAN only when the export carries them;
   l7 = protocol evidence from a sampled packet's payload head, sFlow only: quic-v1 | quic-v2 | quic-draft | quic-long | tls | http | ssh)
with bytes / packets already multiplied by the sampling rate when the exporter reports one (sFlow always does; NetFlow
v5 in its header; v9 / IPFIX when the template carries a sampling field), so totals estimate the real traffic.

Malformed input never raises out of decode(): a truncated or inconsistent packet yields the records parsed so far and
an error count. Templates (v9 / IPFIX) are cached per (exporter, observation domain, template id), bounded in size.
"""
from __future__ import annotations

import ipaddress
import struct
from collections import OrderedDict
from datetime import datetime, timezone

# information elements (NetFlow v9 field types = IPFIX IE ids for these)
IE = {1: "bytes", 2: "packets", 4: "proto", 6: "tcp_flags", 7: "src_port", 8: "src_ip", 10: "in_if", 11: "dst_port", 12: "dst_ip",
      14: "out_if", 21: "last", 22: "first", 23: "out_bytes", 24: "out_packets", 27: "src_ip", 28: "dst_ip", 34: "sampling",
      56: "src_mac", 58: "vlan", 59: "dst_vlan", 80: "dst_mac", 85: "bytes_total", 86: "packets_total", 152: "start_ms", 153: "end_ms", 305: "sampling_ipfix"}
MAX_TEMPLATES = 4096


class Templates:
    def __init__(self, limit: int = MAX_TEMPLATES):
        self.t: OrderedDict = OrderedDict()
        self.limit = limit

    def put(self, key: tuple, fields: list[tuple[int, int]]) -> None:
        self.t[key] = fields
        self.t.move_to_end(key)
        while len(self.t) > self.limit:
            self.t.popitem(last=False)

    def get(self, key: tuple):
        return self.t.get(key)


def _ip(b: bytes) -> str:
    return str(ipaddress.ip_address(b)) if len(b) in (4, 16) else ""


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b) if len(b) == 6 and any(b) else ""


def _uint(b: bytes) -> int:
    return int.from_bytes(b, "big") if b else 0


def _rec(ts: datetime, version: str, **kw) -> dict:
    r = {"ts": ts, "version": version, "in_if": 0, "out_if": 0, "src_ip": "", "dst_ip": "", "src_port": 0, "dst_port": 0, "proto": 0,
         "bytes": 0, "packets": 0, "vlan": 0, "sampling": 1, "src_mac": "", "dst_mac": "", "tcp_flags": 0, "dst_vlan": 0, "l7": ""}
    r.update(kw)
    return r


# ------------------------------------------------------------------ NetFlow v5
def netflow_v5(data: bytes) -> tuple[list[dict], int]:
    if len(data) < 24:
        return [], 1
    _, count, _uptime, secs, _nsecs, _seq, _etype, _eid, samp = struct.unpack("!HHIIIIBBH", data[:24])
    rate = (samp & 0x3FFF) or 1
    ts = datetime.fromtimestamp(secs, tz=timezone.utc)
    out, errors = [], 0
    for i in range(count):
        off = 24 + 48 * i
        if off + 48 > len(data):
            errors += 1
            break
        (src, dst, _nh, inp, outp, pk, octs, _first, _last, sport, dport, _p1, flags, proto, _tos, _sas, _das, _sm, _dm, _p2) = \
            struct.unpack("!4s4s4sHHIIIIHHBBBBHHBBH", data[off:off + 48])
        out.append(_rec(ts, "netflow5", in_if=inp, out_if=outp, src_ip=_ip(src), dst_ip=_ip(dst), src_port=sport, dst_port=dport, proto=proto,
                        bytes=octs * rate, packets=pk * rate, sampling=rate, tcp_flags=flags if proto == 6 else 0))
    return out, errors


# ------------------------------------------------------------------ NetFlow v9 / IPFIX
def _data_record(fields: list[tuple[int, int]], buf: bytes, off: int, ipfix: bool) -> tuple[dict, int]:
    vals: dict = {}
    for fid, flen in fields:
        if flen == 65535:                       # IPFIX variable length
            ln = buf[off]
            off += 1
            if ln == 255:
                ln = struct.unpack("!H", buf[off:off + 2])[0]
                off += 2
            flen = ln
        raw = buf[off:off + flen]
        if len(raw) < flen:
            raise ValueError("truncated record")
        off += flen
        name = IE.get(fid)
        if name in ("src_ip", "dst_ip"):
            vals[name] = _ip(raw)
        elif name in ("src_mac", "dst_mac"):
            vals[name] = _mac(raw)
        elif name:
            vals[name] = _uint(raw)
    return vals, off


def _normalise(vals: dict, ts: datetime, version: str, default_rate: int) -> dict | None:
    if not vals.get("src_ip") and not vals.get("dst_ip"):
        return None                              # not an IP flow (e.g. a layer-2 or options record)
    rate = vals.get("sampling") or vals.get("sampling_ipfix") or default_rate or 1
    b = vals.get("bytes") or vals.get("bytes_total") or vals.get("out_bytes") or 0
    p = vals.get("packets") or vals.get("packets_total") or vals.get("out_packets") or 0
    if vals.get("end_ms"):
        ts = datetime.fromtimestamp(vals["end_ms"] / 1000, tz=timezone.utc)
    return _rec(ts, version, in_if=vals.get("in_if", 0), out_if=vals.get("out_if", 0), src_ip=vals.get("src_ip", ""),
                dst_ip=vals.get("dst_ip", ""), src_port=vals.get("src_port", 0), dst_port=vals.get("dst_port", 0), proto=vals.get("proto", 0),
                bytes=b * rate, packets=p * rate, vlan=vals.get("vlan") or vals.get("dst_vlan") or 0, sampling=rate,
                src_mac=vals.get("src_mac", ""), dst_mac=vals.get("dst_mac", ""), tcp_flags=(vals.get("tcp_flags", 0) & 0xFF) if vals.get("proto") == 6 else 0,
                dst_vlan=vals.get("dst_vlan", 0) & 0x0FFF)


def _templates_v9(body: bytes, key0: tuple, cache: Templates, ipfix: bool) -> None:
    off = 0
    while off + 4 <= len(body):
        tid, count = struct.unpack("!HH", body[off:off + 4])
        off += 4
        fields = []
        for _ in range(count):
            if off + 4 > len(body):
                return
            fid, flen = struct.unpack("!HH", body[off:off + 4])
            off += 4
            if ipfix and fid & 0x8000:           # enterprise-specific element: skip its enterprise number, keep the length
                fid = 0x8000 | (fid & 0x7FFF)
                off += 4
            fields.append((fid, flen))
        if count:
            cache.put(key0 + (tid,), fields)


def _flowsets(data: bytes, start: int, end: int, exporter: str, domain: int, cache: Templates, ts: datetime, version: int,
              template_ids: tuple[int, int]) -> tuple[list[dict], int, int]:
    out, errors, missing = [], 0, 0
    off = start
    ipfix = version == 10
    while off + 4 <= end:
        sid, slen = struct.unpack("!HH", data[off:off + 4])
        if slen < 4 or off + slen > end:
            errors += 1
            break
        body = data[off + 4:off + slen]
        if sid == template_ids[0]:
            _templates_v9(body, (exporter, domain), cache, ipfix)
        elif sid >= 256:
            fields = cache.get((exporter, domain, sid))
            if fields is None:
                missing += 1                       # data before its template: dropped until the exporter resends it
            else:
                fixed = sum(f[1] for f in fields if f[1] != 65535)
                p = 0
                while p < len(body) and (len(body) - p) >= max(fixed, 1):
                    try:
                        vals, p = _data_record(fields, body, p, ipfix)
                    except (ValueError, IndexError, struct.error):
                        errors += 1
                        break
                    r = _normalise(vals, ts, "ipfix" if ipfix else "netflow9", 1)
                    if r:
                        out.append(r)
        off += slen
    return out, errors, missing


def netflow_v9(data: bytes, exporter: str, cache: Templates) -> tuple[list[dict], int, int]:
    if len(data) < 20:
        return [], 1, 0
    _, _count, _uptime, secs, _seq, source_id = struct.unpack("!HHIIII", data[:20])
    ts = datetime.fromtimestamp(secs, tz=timezone.utc)
    return _flowsets(data, 20, len(data), exporter, source_id, cache, ts, 9, (0, 1))


def ipfix(data: bytes, exporter: str, cache: Templates) -> tuple[list[dict], int, int]:
    if len(data) < 16:
        return [], 1, 0
    _, length, export_time, _seq, domain = struct.unpack("!HHIII", data[:16])
    ts = datetime.fromtimestamp(export_time, tz=timezone.utc)
    return _flowsets(data, 16, min(length, len(data)), exporter, domain, cache, ts, 10, (2, 3))


# ------------------------------------------------------------------ sFlow v5
def _packet_header(h: bytes) -> dict:
    """Ethernet (802.1Q) → IPv4 / IPv6 → TCP / UDP ports, from a sampled packet header."""
    out: dict = {}
    if len(h) < 14:
        return out
    out["dst_mac"], out["src_mac"] = _mac(h[0:6]), _mac(h[6:12])
    et, off = struct.unpack("!H", h[12:14])[0], 14
    if et == 0x8100 and len(h) >= 18:
        out["vlan"] = struct.unpack("!H", h[14:16])[0] & 0x0FFF
        et, off = struct.unpack("!H", h[16:18])[0], 18
    if et == 0x0800 and len(h) >= off + 20:
        ihl = (h[off] & 0x0F) * 4
        out.update(proto=h[off + 9], src_ip=_ip(h[off + 12:off + 16]), dst_ip=_ip(h[off + 16:off + 20]))
        l4 = off + ihl
    elif et == 0x86DD and len(h) >= off + 40:
        out.update(proto=h[off + 6], src_ip=_ip(h[off + 8:off + 24]), dst_ip=_ip(h[off + 24:off + 40]))
        l4 = off + 40
    else:
        return out
    if out.get("proto") in (6, 17) and len(h) >= l4 + 4:
        out["src_port"], out["dst_port"] = struct.unpack("!HH", h[l4:l4 + 4])
    if out.get("proto") == 6 and len(h) >= l4 + 14:
        out["tcp_flags"] = h[l4 + 13]
    hint = _l7_hint(out, h, l4)
    if hint:
        out["l7"] = hint
    return out


HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ")


def _l7_hint(f: dict, h: bytes, l4: int) -> str:
    """Protocol evidence from the first payload bytes of a sampled packet (sFlow carries the packet's head). Only
    what the bytes prove: a QUIC long header (and its version), a TLS record, an HTTP/1.x request or response line, an
    SSH banner. Nothing is inferred about the application behind it."""
    proto = f.get("proto")
    if proto == 6:
        if len(h) < l4 + 13:
            return ""
        pay = h[l4 + ((h[l4 + 12] >> 4) * 4):]
    elif proto == 17:
        pay = h[l4 + 8:]
    else:
        return ""
    if len(pay) < 5:
        return ""
    if proto == 17 and 443 in (f.get("src_port"), f.get("dst_port")):
        if pay[0] & 0xC0 == 0xC0 and len(pay) >= 5:        # long header: form bit + fixed bit, then the version
            v = struct.unpack("!I", pay[1:5])[0]
            return "quic-v1" if v == 1 else "quic-v2" if v == 0x6B3343CF else "quic-draft" if v >> 8 == 0xFF0000 else "quic-long"
        return ""
    if proto == 6:
        if pay[0] == 0x16 and pay[1] == 0x03 and pay[2] <= 0x04:
            return "tls"
        if pay.startswith(HTTP_METHODS) or pay.startswith(b"HTTP/1."):
            return "http"
        if pay.startswith(b"SSH-"):
            return "ssh"
    return ""


def sflow_v5(data: bytes, now: datetime | None = None) -> tuple[list[dict], int]:
    ts = now or datetime.now(timezone.utc)
    try:
        version, atype = struct.unpack("!II", data[:8])
        off = 8 + (4 if atype == 1 else 16)
        _sub, _seq, _uptime, nsamples = struct.unpack("!IIII", data[off:off + 16])
        off += 16
    except struct.error:
        return [], 1
    out, errors = [], 0
    for _ in range(nsamples):
        try:
            fmt, slen = struct.unpack("!II", data[off:off + 8])
            body = data[off + 8:off + 8 + slen]
            off += 8 + slen
            kind = fmt & 0xFFF
            if (fmt >> 12) != 0 or kind not in (1, 3):
                continue                             # counter samples and vendor formats
            if kind == 1:
                _sseq, _src, rate, _pool, _drops, inp, outp, nrec = struct.unpack("!IIIIIIII", body[:32])
                p = 32
            else:
                _sseq, _st, _si, rate, _pool, _drops, _if, inp, _of, outp, nrec = struct.unpack("!IIIIIIIIIII", body[:44])
                p = 44
            f, frame_len, sw = None, 0, None
            for _r in range(nrec):
                rfmt, rlen = struct.unpack("!II", body[p:p + 8])
                rec = body[p + 8:p + 8 + rlen]
                p += 8 + rlen
                if rfmt == 1001 and len(rec) >= 16:  # extended switch data: the sampled port's input / output VLAN
                    src_vlan, _sp, dst_vlan, _dp = struct.unpack("!IIII", rec[:16])
                    sw = (src_vlan & 0x0FFF, dst_vlan & 0x0FFF)
                    continue
                if rfmt != 1:
                    continue                         # other flow records (extended router / gateway / user …) are not used
                proto_hdr, frame_len, _stripped, hlen = struct.unpack("!IIII", rec[:16])
                if proto_hdr != 1:
                    continue                         # not Ethernet
                f = _packet_header(rec[16:16 + hlen])
            if f and f.get("src_ip"):
                if sw:                               # weaker than a tag or the client's MAC: see flows/server.py vlan_of
                    f["_sw_vlan"], f["_sw_dst_vlan"] = sw
                out.append(_rec(ts, "sflow5", in_if=inp & 0x3FFFFFFF, out_if=outp & 0x3FFFFFFF, bytes=frame_len * (rate or 1), packets=rate or 1,
                                sampling=rate or 1, **f))
        except (struct.error, IndexError):
            errors += 1
            break
    if version != 5:
        return [], errors + 1
    return out, errors


def decode(data: bytes, exporter: str, cache: Templates, *, port_kind: str = "netflow") -> tuple[list[dict], dict]:
    """Decode one datagram. port_kind: 'netflow' (v5 / v9 / IPFIX by version field) or 'sflow'."""
    stats = {"errors": 0, "missing_template": 0, "version": None}
    try:
        if port_kind == "sflow":
            recs, err = sflow_v5(data)
            stats.update(errors=err, version="sflow5")
            return recs, stats
        if len(data) < 2:
            stats["errors"] = 1
            return [], stats
        v = struct.unpack("!H", data[:2])[0]
        stats["version"] = v
        if v == 5:
            recs, err = netflow_v5(data)
            stats["errors"] = err
            return recs, stats
        if v in (9, 10):
            recs, err, miss = (netflow_v9 if v == 9 else ipfix)(data, exporter, cache)
            stats.update(errors=err, missing_template=miss)
            return recs, stats
        stats["errors"] = 1
        return [], stats
    except Exception:                                # never let one datagram stop the receiver
        stats["errors"] += 1
        return [], stats

