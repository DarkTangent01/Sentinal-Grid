"""Minimal TACACS+ server for tests only (RFC 8907 framing and body obfuscation via the tacacs_plus packet helpers).

Supports PAP authentication START (PASS / FAIL against a user table) and accounting REQUEST (SUCCESS), and records what
it received. It exists to exercise the SIEM's client code over a real TCP socket; production uses tac_plus-ng."""
from __future__ import annotations

import asyncio
import struct

from tacacs_plus.packet import TACACSHeader, crypt

AUTHEN, ACCT = 0x01, 0x03


class SimServer:
    def __init__(self, key: str, users: dict[str, str], reply_key: str | None = None):
        self.key, self.users, self.reply_key = key, users, reply_key or key
        self.received: list[dict] = []
        self.server = None
        self.port = None

    async def start(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def stop(self):
        self.server.close()
        await self.server.wait_closed()

    async def _handle(self, r: asyncio.StreamReader, w: asyncio.StreamWriter):
        try:
            raw = await r.readexactly(12)
            hdr = TACACSHeader.unpacked(raw)
            body = crypt(hdr, await r.readexactly(hdr.length), self.key)
            if hdr.type == AUTHEN:
                _action, _priv, _atype, _svc, ulen, plen, rlen, dlen = struct.unpack("B" * 8, body[:8])
                off = 8
                user = body[off:off + ulen].decode(errors="replace")
                off += ulen + plen + rlen
                pw = body[off:off + dlen].decode(errors="replace")
                ok = self.users.get(user) == pw
                self.received.append({"type": "authen", "user": user, "ok": ok})
                reply = struct.pack("BB", 1 if ok else 2, 0) + struct.pack("!HH", 0, 0)
            elif hdr.type == ACCT:
                self.received.append({"type": "acct", "raw": body})
                reply = struct.pack("!HH", 0, 0) + struct.pack("B", 1)
            else:
                w.close()
                return
            rh = TACACSHeader(hdr.version, hdr.type, hdr.session_id, len(reply), seq_no=hdr.seq_no + 1, flags=hdr.flags)
            w.write(rh.packed + crypt(rh, reply, self.reply_key))
            await w.drain()
        except (asyncio.IncompleteReadError, ConnectionError, struct.error):
            pass
        finally:
            w.close()
