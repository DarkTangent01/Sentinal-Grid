"""Syslog relay path: frames from the ingress container carry the original sender's IP; others are refused."""
import asyncio

from app.ingest.pipeline import EventSink
from app.syslog_server import RelayTrust, handle_tcp, split_relay

from .conftest import fixture_lines
from .test_storage_analytics import registry


def test_split_relay():
    assert split_relay("10.1.0.1 <189>date=x msg=y") == ("10.1.0.1", "<189>date=x msg=y")
    assert split_relay("not-an-ip <189>x") == (None, "not-an-ip <189>x")


async def _serve(sink, trust):
    server = await asyncio.start_server(lambda r, w: handle_tcp(r, w, sink, trust), "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def _send(port, frames: list[bytes]):
    _, w = await asyncio.open_connection("127.0.0.1", port)
    for f in frames:
        w.write(str(len(f)).encode() + b" " + f)
    await w.drain()
    w.close()
    await w.wait_closed()
    await asyncio.sleep(0.2)


async def test_relay_frames_use_original_sender(clean_ch):
    sink = EventSink(clean_ch, registry())
    server, port = await _serve(sink, RelayTrust("127.0.0.1"))
    line = fixture_lines()[0]
    await _send(port, [f"10.1.0.1 {line}".encode(),          # registered firewall address → accepted
                       f"192.0.2.99 {line}".encode(),        # same device fields from the wrong sender → rejected
                       b"garbage-without-ip"])
    server.close()
    assert sink.counters["parsed"] == 1 and sink.counters["source_mismatch"] == 1 and sink.counters["parse_errors"] == 1


async def test_relay_refuses_untrusted_peer(clean_ch):
    sink = EventSink(clean_ch, registry())
    server, port = await _serve(sink, RelayTrust("ingress-host-that-does-not-resolve.invalid"))
    await _send(port, [f"10.1.0.1 {fixture_lines()[0]}".encode()])
    server.close()
    assert sink.counters["received"] == 0


def test_framer_mixed_and_split_frames():
    from app.syslog_server import Framer
    f = Framer()
    a, b = b"<189>one msg", b"<189>two"
    stream = str(len(a)).encode() + b" " + a + b"<190>newline framed\n\r\n" + str(len(b)).encode() + b" " + b
    got = []
    for i in range(0, len(stream), 7):  # arbitrary TCP segmentation
        got += f.feed(stream[i:i + 7])
    assert got == [a, b"<190>newline framed\n", b]
    assert not f.buf


def test_framer_rejects_oversized():
    import pytest
    from app.syslog_server import MAX_MSG, Framer
    with pytest.raises(ValueError):
        Framer().feed(str(MAX_MSG + 1).encode() + b" x")


def test_merge_stats():
    from datetime import datetime, timezone
    from app.ingest.pipeline import merge_stats
    t1, t2 = datetime(2026, 1, 1, tzinfo=timezone.utc), datetime(2026, 1, 2, tzinfo=timezone.utc)
    acc: dict = {}
    merge_stats(acc, {(1, "syslog"): {"events": 3, "errors": 0, "last_event": t2, "last_error": None}})
    merge_stats(acc, {(1, "syslog"): {"events": 2, "errors": 1, "last_event": t1, "last_error": "bad"}})
    assert acc[(1, "syslog")] == {"events": 5, "errors": 1, "last_event": t2, "last_error": "bad"}
