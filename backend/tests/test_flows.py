"""Flow decoders on hand-built datagrams (NetFlow v5, v9, IPFIX, sFlow v5), the collector's exporter allowlist, and
storage → rollups → API on embedded ClickHouse."""
import socket
import struct
import time

import pytest

from app.db.models import Switch, SwitchInterface
from app.flows import decode as D
from app.flows.server import FLOW_COLS, Collector

from .test_api import api  # noqa: F401  (fixture)

NOW = int(time.time()) - 60


def ip(a: str) -> bytes:
    return socket.inet_aton(a)


def v5(n_samp: int = 10) -> bytes:
    hdr = struct.pack("!HHIIIIBBH", 5, 2, 1000, NOW, 0, 1, 0, 0, (1 << 14) | n_samp)
    recs = b""
    for src, dst, sp, dp, octs in (("10.1.1.10", "8.8.8.8", 51000, 53, 120), ("10.1.1.11", "10.2.2.2", 40000, 443, 9000)):
        recs += struct.pack("!4s4s4sHHIIIIHHBBBBHHBBH", ip(src), ip(dst), ip("0.0.0.0"), 3, 7, 2, octs, 0, 0, sp, dp, 0, 0, 17 if dp == 53 else 6,
                            0, 0, 0, 0, 0, 0)
    return hdr + recs


def v9() -> bytes:
    fields = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 4), (2, 4), (10, 2), (14, 2), (58, 2)]
    tmpl = struct.pack("!HH", 256, len(fields)) + b"".join(struct.pack("!HH", a, b) for a, b in fields)
    tfs = struct.pack("!HH", 0, 4 + len(tmpl)) + tmpl
    data = b""
    for src, dst, dp, by in (("10.1.1.20", "1.1.1.1", 443, 5000), ("10.1.1.21", "1.0.0.1", 80, 700)):
        data += ip(src) + ip(dst) + struct.pack("!HHBIIHHH", 50000, dp, 6, by, 4, 5, 9, 40)
    pad = (4 - (4 + len(data)) % 4) % 4
    dfs = struct.pack("!HH", 256, 4 + len(data) + pad) + data + b"\0" * pad
    orphan = struct.pack("!HH", 300, 8) + b"\0" * 4                       # data for an unknown template
    return struct.pack("!HHIIII", 9, 3, 1000, NOW, 1, 7) + tfs + dfs + orphan


def ipfix() -> bytes:
    fields = [(8, 4), (12, 4), (4, 1), (7, 2), (11, 2), (85, 8), (86, 8), (0x8000 | 100, 4)]
    tmpl = struct.pack("!HH", 400, len(fields))
    for fid, ln in fields:
        tmpl += struct.pack("!HH", fid, ln) + (struct.pack("!I", 9) if fid & 0x8000 else b"")
    tset = struct.pack("!HH", 2, 4 + len(tmpl)) + tmpl
    rec = ip("10.1.1.30") + ip("9.9.9.9") + struct.pack("!BHHQQI", 17, 5353, 123, 2000, 10, 0xDEADBEEF)
    dset = struct.pack("!HH", 400, 4 + len(rec)) + rec
    body = tset + dset
    return struct.pack("!HHIII", 10, 16 + len(body), NOW, 1, 3) + body


def sflow() -> bytes:
    eth = b"\x00" * 12 + struct.pack("!HH", 0x8100, 30) + struct.pack("!H", 0x0800)
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0, 64, 6, 0, ip("10.1.1.40"), ip("10.3.3.3"))
    tcp = struct.pack("!HH", 43210, 22) + b"\0" * 16
    header = eth + iph + tcp
    rec = struct.pack("!IIII", 1, 1500, 4, len(header)) + header
    rec += b"\0" * ((4 - len(rec) % 4) % 4)
    flow_rec = struct.pack("!II", 1, len(rec)) + rec
    sample = struct.pack("!IIIIIIII", 1, 5, 100, 1000, 0, 12, 13, 1) + flow_rec
    return struct.pack("!II4sIIII", 5, 1, ip("192.0.2.30"), 0, 1, 1000, 1) + struct.pack("!II", 1, len(sample)) + sample


def test_netflow_v5_applies_sampling():
    recs, st = D.decode(v5(), "192.0.2.1", D.Templates())
    assert st["errors"] == 0 and [r["dst_port"] for r in recs] == [53, 443]
    assert recs[0]["bytes"] == 1200 and recs[0]["packets"] == 20 and recs[0]["sampling"] == 10 and recs[0]["proto"] == 17
    assert recs[1]["in_if"] == 3 and recs[1]["out_if"] == 7 and recs[0]["version"] == "netflow5"


def test_netflow_v9_templates_and_missing_template():
    cache = D.Templates()
    recs, st = D.decode(v9(), "192.0.2.1", cache)
    assert [(r["src_ip"], r["dst_port"], r["bytes"], r["vlan"]) for r in recs] == [("10.1.1.20", 443, 5000, 40), ("10.1.1.21", 80, 700, 40)]
    assert st["missing_template"] == 1 and st["errors"] == 0
    # the same data from another exporter without its template: not decoded with someone else's template
    only_data = v9()[:20] + v9()[20 + 4 + 4 + 40:]
    recs2, st2 = D.decode(only_data, "192.0.2.2", cache)
    assert recs2 == [] and st2["missing_template"] >= 1


def test_ipfix_with_enterprise_field_and_sflow_header_parsing():
    recs, st = D.decode(ipfix(), "192.0.2.1", D.Templates())
    assert st["errors"] == 0 and len(recs) == 1
    assert (recs[0]["src_ip"], recs[0]["dst_ip"], recs[0]["proto"], recs[0]["bytes"], recs[0]["packets"]) == ("10.1.1.30", "9.9.9.9", 17, 2000, 10)
    recs, st = D.decode(sflow(), "192.0.2.30", D.Templates(), port_kind="sflow")
    (r,) = recs
    assert (r["src_ip"], r["dst_ip"], r["dst_port"], r["vlan"], r["bytes"], r["packets"], r["in_if"]) == ("10.1.1.40", "10.3.3.3", 22, 30, 150000, 100, 12)


def test_malformed_input_never_raises():
    for junk in (b"", b"\x00", b"\x00\x05" + b"\xff" * 10, v9()[:31], ipfix()[:20], b"\x00\x0a\x00\xff" + b"\x00" * 12, sflow()[:40]):
        recs, st = D.decode(junk, "x", D.Templates())
        recs2, st2 = D.decode(junk, "x", D.Templates(), port_kind="sflow")
        assert isinstance(recs, list) and isinstance(recs2, list)


@pytest.fixture
def fch(ch):
    for t in ("flows", "flows_if_hourly", "flows_talkers_hourly"):
        ch.command(f"TRUNCATE TABLE {t}")
    return ch


async def test_collector_allowlist_storage_and_api(api, db, fch):  # noqa: F811
    from .test_iac import As
    sw = Switch(name="CORE", address="192.0.2.1", capabilities={}, group_state={}, health={}, thresholds={})
    db.add(sw)
    await db.flush()
    db.add_all([SwitchInterface(switch_id=sw.id, ifindex=3, name="Gi1/0/3", present=True), SwitchInterface(switch_id=sw.id, ifindex=7, name="Te1/1/1", present=True)])
    await db.commit()
    c = Collector(fch)
    await c.exporters.load()
    c.handle(v5(), "192.0.2.1", "netflow")
    c.handle(v5(), "203.0.113.9", "netflow")                     # not an inventory device: dropped
    assert c.stats["unknown_exporter"] == 1 and c.queue.qsize() == 2
    rows = [c.queue.get_nowait() for _ in range(2)]
    fch.insert("flows", rows, FLOW_COLS)
    N = await As.login(api, "analyst1")
    s = (await N.get("/api/nms/flows/summary", params={"range": "1h"})).json()
    assert s["totals"]["bytes"] == 91200 and s["sampled"] and s["exporters"][0]["name"] == "CORE"
    t = (await N.get("/api/nms/flows/top", params={"by": "talkers", "range": "1h"})).json()
    assert t["items"][0]["src_ip"] == "10.1.1.11" and t["items"][0]["bytes"] == 90000
    sv = (await N.get("/api/nms/flows/top", params={"by": "services", "range": "24h"})).json()       # hourly rollup
    assert {x["label"] for x in sv["items"]} == {"TCP/443 (https)", "UDP/53 (dns)"} and sv["source"] == "hourly rollups"
    ifs = (await N.get("/api/nms/flows/top", params={"by": "interfaces", "range": "1h"})).json()
    assert ifs["items"][0]["in_name"] == "Gi1/0/3" and ifs["items"][0]["out_name"] == "Te1/1/1" and ifs["items"][0]["device"] == "CORE"
    assert (await N.get("/api/nms/flows/top", params={"by": "evil"})).status_code == 422
