"""Flow collector service (`python -m app.flows`): NetFlow v5 / v9 and IPFIX on one UDP port, sFlow v5 on another.

Same safety model as the trap receiver:
  * only datagrams from inventory devices (a monitored switch / controller management address, or a registered
    firewall) are decoded; anything else is counted and dropped;
  * the published ports are bound to loopback until FLOW_BIND_IP is set (docker-compose.yml);
  * decoding errors and a full queue are counted, never fatal; a heartbeat file carries the counters.
Rows go to ClickHouse `flows` (30 days) and its hourly rollups (400 / 90 days).
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time

from .decode import Templates, decode

log = logging.getLogger("flows")
FLOW_COLS = ["ts", "exporter", "device_id", "version", "in_if", "out_if", "src_ip", "dst_ip", "src_port", "dst_port", "proto", "bytes", "packets",
             "vlan", "sampling", "src_mac", "dst_mac", "tcp_flags", "dst_vlan", "l7"]
HEARTBEAT = "/tmp/flows.heartbeat"


class Exporters:
    """Management address → (device kind, id, name), refreshed every minute."""

    def __init__(self):
        self.by_ip: dict[str, dict] = {}
        self.mac_vlan: dict[str, int] = {}    # MAC → its only VLAN in the switches' MAC tables


    async def load(self) -> int:
        from sqlalchemy import select

        from ..db.models import Firewall, Switch
        from ..db.pg import session_factory
        async with session_factory()() as s:
            sws = (await s.execute(select(Switch.id, Switch.address, Switch.name))).all()
            fws = (await s.execute(select(Firewall.id, Firewall.host, Firewall.name).where(Firewall.is_demo.is_(False)))).all()
        out = {a: {"kind": "switch", "id": i, "name": n} for i, a, n in sws if a}
        out.update({h: {"kind": "firewall", "id": i, "name": n} for i, h, n in fws if h and h not in out})
        self.by_ip = out
        await self.load_mac_vlans()
        return len(out)

    async def load_mac_vlans(self) -> int:
        """VLAN of each MAC from the MAC address tables the SNMP poller collects. A MAC learned in more than one VLAN
        (a gateway / router MAC is learned in every VLAN it serves) is ambiguous and never used."""
        from sqlalchemy import select

        from ..db.models import SwitchMac
        from ..db.pg import session_factory
        seen: dict[str, set] = {}
        async with session_factory()() as s:
            for mac, v in (await s.execute(select(SwitchMac.mac, SwitchMac.vlan_id).where(SwitchMac.present.is_(True), SwitchMac.vlan_id > 0))).all():
                seen.setdefault(mac.lower(), set()).add(int(v))
        self.mac_vlan = {m: next(iter(v)) for m, v in seen.items() if len(v) == 1}
        return len(self.mac_vlan)


def vlan_of(r: dict, mac_vlan: dict[str, int]) -> None:
    """A record's VLANs, strongest evidence first:
      1. an 802.1Q tag in the sampled frame, or NetFlow / IPFIX VLAN fields (already in vlan / dst_vlan);
      2. the client's VLAN from the switches' MAC tables: the source MAC, else the destination MAC. On an uplink one side
         is the gateway MAC, learned in every VLAN and so absent from mac_vlan; the client's MAC decides;
      3. the sFlow extended switch record (_sw_vlan / _sw_dst_vlan): the VLAN of the *sampled port*, which on a routed
         uplink is the uplink's VLAN, not the client's;
    `vlan` is the flow's (internal endpoint's) VLAN, `dst_vlan` the destination's."""
    sw_s, sw_d = r.pop("_sw_vlan", 0), r.pop("_sw_dst_vlan", 0)
    d = mac_vlan.get(r.get("dst_mac") or "", 0)
    if not r.get("dst_vlan"):
        r["dst_vlan"] = d or sw_d
    if not r.get("vlan"):
        r["vlan"] = mac_vlan.get(r.get("src_mac") or "", 0) or d or sw_s


class _Proto(asyncio.DatagramProtocol):
    def __init__(self, rx: "Collector", kind: str):
        self.rx, self.kind = rx, kind

    def datagram_received(self, data: bytes, addr):
        self.rx.handle(data, addr[0], self.kind)


class Collector:
    def __init__(self, ch, netflow_port: int = 2055, ipfix_port: int = 4739, sflow_port: int = 6343, host: str = "0.0.0.0",
                 queue_rows: int = 100_000):
        self.ch, self.host = ch, host
        self.ports = {"netflow": netflow_port, "ipfix": ipfix_port, "sflow": sflow_port}
        self.exporters = Exporters()
        self.templates = Templates()
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=queue_rows)
        self.stats = {"datagrams": 0, "records": 0, "stored": 0, "unknown_exporter": 0, "decode_errors": 0, "missing_template": 0,
                      "dropped_queue_full": 0, "insert_errors": 0}
        self.unknown: dict[str, int] = {}

    def handle(self, data: bytes, src: str, kind: str) -> None:
        self.stats["datagrams"] += 1
        dev = self.exporters.by_ip.get(src)
        if dev is None:
            self.stats["unknown_exporter"] += 1
            if len(self.unknown) < 100:
                self.unknown[src] = self.unknown.get(src, 0) + 1
            return
        recs, st = decode(data, src, self.templates, port_kind="sflow" if kind == "sflow" else "netflow")
        self.stats["decode_errors"] += st["errors"]
        self.stats["missing_template"] += st["missing_template"]
        mv = self.exporters.mac_vlan
        for r in recs:
            r["exporter"], r["device_id"] = src, dev["id"]
            vlan_of(r, mv)
            try:
                self.queue.put_nowait(r)
                self.stats["records"] += 1
            except asyncio.QueueFull:
                self.stats["dropped_queue_full"] += 1

    async def _writer(self):
        batch: list[dict] = []
        last = time.monotonic()
        while True:
            try:
                batch.append(await asyncio.wait_for(self.queue.get(), timeout=2))
            except asyncio.TimeoutError:
                pass
            if batch and (len(batch) >= 5000 or time.monotonic() - last > 2):
                try:
                    await self.ch.ainsert("flows", batch, FLOW_COLS)
                    self.stats["stored"] += len(batch)
                except Exception:
                    self.stats["insert_errors"] += len(batch)
                    log.exception("clickhouse insert into flows failed")
                batch, last = [], time.monotonic()

    async def run(self, stop: asyncio.Event):
        await self.exporters.load()
        loop = asyncio.get_running_loop()
        transports = []
        for kind, port in self.ports.items():
            if port:
                t, _ = await loop.create_datagram_endpoint(lambda k=kind: _Proto(self, k), local_addr=(self.host, port))
                transports.append(t)
        writer = asyncio.create_task(self._writer())
        log.info("flow collector listening on udp %s (netflow / ipfix / sflow) for %d exporter(s)", self.ports, len(self.exporters.by_ip))
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=60)
            except asyncio.TimeoutError:
                pass
            try:
                with open(HEARTBEAT, "w") as f:
                    f.write(json.dumps({**self.stats, "unknown_exporters": dict(sorted(self.unknown.items(), key=lambda x: -x[1])[:20])}))
            except OSError:
                pass
            try:
                await self.exporters.load()
            except Exception:
                log.exception("flow exporter reload failed")
            log.info("flows: %s", self.stats)
            try:   # counters for the traffic module's collector status (app/selfmon.py, service "flows")
                from .. import selfmon
                for k, v in self.stats.items():
                    selfmon.put(f"flows_{k}", v)
                selfmon.put("flows_queue_depth", self.queue.qsize())
                selfmon.put("flows_exporters_known", len(self.exporters.by_ip))
                selfmon.put("flows_unknown_senders", len(self.unknown))
                for ip, n in sorted(self.unknown.items(), key=lambda x: -x[1])[:20]:
                    selfmon.put(f"flows_unknown:{ip}", n)   # senders that are not inventory devices (dropped)
                selfmon.put("flows_last_beat", time.time())
                await selfmon.flush(self.ch)
            except Exception:
                log.warning("flow collector self-metrics not written", exc_info=True)
        for t in transports:
            t.close()
        writer.cancel()


async def main():
    import signal

    from ..config import get_settings
    from ..db.ch import get_ch
    from ..db.pg import init_engine
    from ..logging_setup import setup_logging
    st = get_settings()
    setup_logging(st.log_level)
    os.environ.setdefault("SELFMON_SERVICE", "flows")
    init_engine(st.database_url)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    await Collector(get_ch(), netflow_port=int(os.environ.get("FLOW_NETFLOW_PORT", "2055")), ipfix_port=int(os.environ.get("FLOW_IPFIX_PORT", "4739")),
                    sflow_port=int(os.environ.get("FLOW_SFLOW_PORT", "6343"))).run(stop)
