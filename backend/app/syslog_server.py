"""FortiGate syslog receiver (UDP + TCP, default key=value format). Usage: python -m app.syslog_server

FortiGate configuration (CLI), per log destination:
    config log syslogd setting
        set status enable
        set server <SIEM-IP>
        set port 514              # mapped to this service by Docker
        set mode udp              # or reliable (TCP, RFC 6587 octet counting)
        set format default
    end
"""
import asyncio
import ipaddress
import logging
import multiprocessing as mp
import os
import queue
import signal
import time
from pathlib import Path

from .config import get_settings
from .db.ch import get_ch
from .ingest.pipeline import DeviceRegistry, EventSink, merge_stats, persist_stats
from .logging_setup import setup_logging

log = logging.getLogger("syslog")
HEARTBEAT = Path("/tmp/syslog.heartbeat")
MAX_MSG = 64 * 1024


class UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, sink):
        self.out = sink if hasattr(sink, "submit") else InlineSink(sink)

    def datagram_received(self, data: bytes, addr):
        self.out.submit(data[:MAX_MSG], addr[0])


_tcp_sessions = 0


class RelayTrust:
    """Addresses allowed to send relay frames: SYSLOG_RELAY_HOSTS resolved now and then (the ingress container's IP
    can change when it is recreated)."""

    def __init__(self, hosts: str):
        self.hosts = [h.strip() for h in hosts.split(",") if h.strip()]
        self.ips: set[str] = set()

    async def refresh(self) -> None:
        loop = asyncio.get_running_loop()
        ips = set()
        for h in self.hosts:
            try:
                ipaddress.ip_address(h)
                ips.add(h)
                continue
            except ValueError:
                pass
            try:
                for *_, sa in await loop.getaddrinfo(h, None):
                    ips.add(sa[0])
            except OSError:
                continue  # ingress not running (dev, tests): relay frames are refused until it resolves
        self.ips = ips

    async def allowed(self, peer: str) -> bool:
        if peer not in self.ips:
            await self.refresh()
        return peer in self.ips


def split_relay(msg: str) -> tuple[str | None, str]:
    """'<sender-ip> <original syslog line>' → (sender ip, line); (None, msg) when the prefix is not an IP address."""
    ip, _, rest = msg.partition(" ")
    try:
        return str(ipaddress.ip_address(ip)), rest
    except ValueError:
        return None, msg


class Framer:
    """Splits a TCP byte stream into syslog messages: RFC 6587 octet counting ("<len> <msg>") or newline framing."""

    def __init__(self):
        self.buf = bytearray()

    def feed(self, data: bytes) -> list[bytes]:
        b = self.buf
        b += data
        out, i, n = [], 0, len(b)
        while i < n:
            if 48 <= b[i] <= 57:  # digit: octet-counted frame
                sp = b.find(b" ", i, i + 8)
                if sp < 0:
                    if n - i >= 8:
                        raise ValueError("bad octet count")
                    break
                size = int(b[i:sp])
                if size > MAX_MSG:
                    raise ValueError("frame too large")
                end = sp + 1 + size
                if end > n:
                    break
                out.append(bytes(b[sp + 1:end]))
                i = end
            else:
                nl = b.find(b"\n", i)
                if nl < 0:
                    if n - i > MAX_MSG:
                        raise ValueError("frame too large")
                    break
                if nl - i > 1 or b[i] not in b"\r\n":  # skip blank keep-alive lines
                    out.append(bytes(b[i:nl + 1]))
                i = nl + 1
        del b[:i]
        return out


class InlineSink:
    """Receiver-side adapter that parses in this process (dev server, tests, SYSLOG_WORKERS=1)."""

    def __init__(self, sink: EventSink):
        self.sink = sink

    def submit(self, msg: bytes, peer: str | None) -> None:
        text = msg.decode("utf-8", "replace")
        if peer is None:  # relay frame: "<sender-ip> <line>"
            peer, text = split_relay(text)
            if peer is None:
                self.sink.counters["parse_errors"] += 1
                return
        self.sink.add_line(text, source="syslog", peer_ip=peer)

    async def pressure(self) -> None:
        if self.sink.should_flush():
            await self.sink.flush()


async def handle_tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, sink, relay: RelayTrust | None = None):
    """One TCP syslog session. With `relay`, frames carry the original sender's IP and the session must come from the
    ingress relay. `sink` is an EventSink (parsed here) or a WorkerPool (parsed by worker processes)."""
    global _tcp_sessions
    st = get_settings()
    out = sink if isinstance(sink, WorkerPool) else InlineSink(sink)
    peer = writer.get_extra_info("peername")[0]
    if relay is not None and not await relay.allowed(peer):
        log.warning("relay session from %s refused: not one of %s", peer, relay.hosts)
        writer.close()
        return
    if _tcp_sessions >= st.syslog_tcp_max_connections:  # idle/abusive clients must not exhaust file descriptors
        log.warning("tcp session from %s refused: %d sessions open", peer, _tcp_sessions)
        writer.close()
        return
    _tcp_sessions += 1
    idle = st.syslog_tcp_idle_seconds
    sender = None if relay is not None else peer
    framer = Framer()
    try:
        while True:
            data = await asyncio.wait_for(reader.read(256 * 1024), idle)  # one await per chunk, not per message
            if not data:
                break
            for msg in framer.feed(data):
                out.submit(msg, sender)
            await out.pressure()  # backpressure: stop reading while the parsers are behind (the relay queues on disk)
    except (asyncio.TimeoutError, ValueError, ConnectionError) as e:
        log.debug("tcp session %s closed: %s", peer, type(e).__name__)
    finally:
        _tcp_sessions -= 1
        writer.close()


# ------------------------------------------------------------------ parser worker processes
CHUNK = 500             # messages per hand-off to a worker
QUEUE_CHUNKS = 40       # per-worker queue depth (20k messages)
MAX_PENDING = 50_000    # receiver-side buffer before UDP is dropped and TCP reads pause


def worker_count(setting: int) -> int:
    if setting > 0:
        return setting
    try:
        cpus = len(os.sched_getaffinity(0))
    except AttributeError:
        cpus = os.cpu_count() or 2
    return max(1, min(4, cpus - 1))


class WorkerPool:
    """Receiver side of the multi-process pipeline: frames are handed round-robin, in chunks, to parser processes
    that normalise, enrich and insert into ClickHouse themselves. Workers send their ingest stats back here so the
    per-firewall counters in Postgres are written by one process."""

    def __init__(self, n: int):
        self.ctx = mp.get_context("spawn")
        self.n = n
        self.queues = [self.ctx.Queue(QUEUE_CHUNKS) for _ in range(n)]
        self.stats_q = self.ctx.Queue()
        self.procs: list = [None] * n
        self.pending: list = []
        self.rr = 0
        self.stats: dict = {}
        self.counters: dict[int, dict] = {}
        self.dropped = 0

    def start(self) -> None:
        for i in range(self.n):
            self._spawn(i)

    def _spawn(self, i: int) -> None:
        p = self.ctx.Process(target=worker_main, args=(i, self.queues[i], self.stats_q), name=f"syslog-parser-{i}", daemon=True)
        p.start()
        self.procs[i] = p

    def check(self) -> bool:
        """Restart dead workers (their queue survives, so queued chunks are not lost). False if any had died."""
        ok = True
        for i, p in enumerate(self.procs):
            if not p.is_alive():
                log.error("parser worker %d exited (code %s); restarting", i, p.exitcode)
                self._spawn(i)
                ok = False
        return ok

    def submit(self, msg: bytes, peer: str | None) -> None:
        if len(self.pending) >= MAX_PENDING:
            self.dropped += 1  # only reachable by UDP: TCP sessions wait in pressure()
            return
        self.pending.append((msg, peer))
        if len(self.pending) >= CHUNK:
            self.dispatch()

    def dispatch(self) -> None:
        while self.pending:
            chunk = self.pending[:CHUNK]
            for _ in range(self.n):
                q = self.queues[self.rr]
                self.rr = (self.rr + 1) % self.n
                try:
                    q.put_nowait(chunk)
                    break
                except queue.Full:
                    continue
            else:
                return  # every worker is full: keep the rest pending
            del self.pending[:len(chunk)]

    async def pressure(self) -> None:
        self.dispatch()
        while len(self.pending) >= CHUNK * 4:
            await asyncio.sleep(0.02)
            self.dispatch()

    def collect(self) -> None:
        while True:
            try:
                idx, stats, counters = self.stats_q.get_nowait()
            except queue.Empty:
                return
            merge_stats(self.stats, stats)
            self.counters[idx] = counters

    def totals(self) -> dict:
        t: dict = {"dropped": self.dropped, "pending": len(self.pending)}
        for c in self.counters.values():
            for k, v in c.items():
                t[k] = t.get(k, 0) + v
        return t

    def stop(self) -> None:
        self.dispatch()
        for q in self.queues:
            q.put(None)  # after any queued chunks: each worker drains, flushes and exits
        for p in self.procs:
            p.join(timeout=25)
        self.collect()


def worker_main(idx: int, q, stats_q) -> None:
    signal.signal(signal.SIGINT, signal.SIG_IGN)  # the receiver coordinates shutdown through the queue
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    s = get_settings()
    setup_logging(s.log_level)
    asyncio.run(_worker(idx, q, stats_q))


async def _worker(idx: int, q, stats_q) -> None:
    s = get_settings()
    registry = DeviceRegistry()
    await registry.refresh()
    from .enrich.enricher import Enricher
    enricher = Enricher()
    try:
        await enricher.refresh_ti(force=True)
    except Exception:
        log.exception("threat-intel load failed; continuing without TI enrichment")
    sink = EventSink(get_ch(), registry, enricher=enricher,
                     stats_hook=lambda st: stats_q.put((idx, st, dict(sink.counters))))
    inline = InlineSink(sink)
    last_flush = last_refresh = time.monotonic()
    while True:
        try:
            chunk = await asyncio.to_thread(q.get, True, 0.5)
        except queue.Empty:
            chunk = []
        if chunk is None:
            break
        for msg, peer in chunk:
            inline.submit(msg, peer)
        now = time.monotonic()
        if sink.should_flush() or (sink.buffer and now - last_flush >= s.syslog_worker_flush_seconds):
            await sink.flush()
            last_flush = now
        if now - last_refresh > 30:
            try:
                await registry.refresh()
                await enricher.refresh_ti()
            except Exception:
                log.exception("registry/threat-intel refresh failed")
            last_refresh = now
    await sink.flush()
    stats_q.put((idx, {}, dict(sink.counters)))


async def main():
    s = get_settings()
    setup_logging(s.log_level)
    n = worker_count(s.syslog_workers)
    registry = enricher = pool = None
    if n > 1:
        pool = WorkerPool(n)
        pool.start()
        sink = pool
        udp_sink = pool
    else:
        registry = DeviceRegistry()
        await registry.refresh()
        from .enrich.enricher import Enricher
        enricher = Enricher()
        try:
            await enricher.refresh_ti(force=True)
        except Exception:
            log.exception("threat-intel load failed; continuing without TI enrichment")
        sink = EventSink(get_ch(), registry, enricher=enricher)
        udp_sink = InlineSink(sink)
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(lambda: UDPProtocol(udp_sink), local_addr=("0.0.0.0", s.syslog_udp_port))
    server = await asyncio.start_server(lambda r, w: handle_tcp(r, w, sink), "0.0.0.0", s.syslog_tcp_port, limit=MAX_MSG)
    relay_server = None
    if s.syslog_relay_port:
        trust = RelayTrust(s.syslog_relay_hosts)
        await trust.refresh()
        relay_server = await asyncio.start_server(lambda r, w: handle_tcp(r, w, sink, trust), "0.0.0.0", s.syslog_relay_port, limit=MAX_MSG)
    log.info("syslog listening udp/%d tcp/%d relay/%s, %d parser process(es)", s.syslog_udp_port, s.syslog_tcp_port,
             s.syslog_relay_port or "off", n)

    stop = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    last_refresh = time.monotonic()
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=s.syslog_flush_seconds)
        except asyncio.TimeoutError:
            pass
        healthy = True
        if pool is not None:
            pool.dispatch()
            pool.collect()
            if pool.stats:
                stats, pool.stats = pool.stats, {}
                await persist_stats(stats)
            healthy = pool.check()
        else:
            await sink.flush()
        if time.monotonic() - last_refresh > 30:
            if pool is None:
                try:
                    await registry.refresh()
                    await enricher.refresh_ti()
                except Exception:
                    log.exception("registry/threat-intel refresh failed")
            last_refresh = time.monotonic()
            log.info("syslog counters %s", pool.totals() if pool is not None else sink.counters)
        if healthy:
            HEARTBEAT.write_text(str(time.time()))
    transport.close()
    server.close()
    if relay_server is not None:
        relay_server.close()
    if pool is not None:  # graceful shutdown: workers drain their queues and flush
        await asyncio.to_thread(pool.stop)
        if pool.stats:
            await persist_stats(pool.stats)
        log.info("syslog stopped; final counters %s", pool.totals())
    else:
        await sink.flush()
        log.info("syslog stopped; final counters %s", sink.counters)


if __name__ == "__main__":
    asyncio.run(main())
