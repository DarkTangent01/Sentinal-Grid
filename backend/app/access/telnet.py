"""Minimal Telnet client (RFC 854) for legacy devices and console-server reverse Telnet.

Telnet sends everything, including the login, in clear text. It is therefore off unless ACCESS_TELNET_ENABLED is set
and an administrator enables it per device (switches.access_telnet) or per console server (method "telnet").

Option negotiation: we accept the server's ECHO and SUPPRESS-GO-AHEAD, offer NAWS (window size) and refuse everything
else. IAC sequences are removed from what reaches the browser; a 0xFF byte the user types is escaped.
"""
from __future__ import annotations

import asyncio
import re
import time

IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
ECHO, SGA, NAWS = 1, 3, 31
_LOGIN = re.compile(r"(user\s*name|login)\s*:\s*$", re.I)
_PASSWORD = re.compile(r"password\s*:\s*$", re.I)
_FAIL = re.compile(r"(login invalid|authentication failed|access denied|login incorrect|% bad passwords)", re.I)
_PROMPT = re.compile(r"[\w\-.()@/:~\]\[]+\s?[#>$%]\s?$")


class TelnetError(Exception):
    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind, self.message = kind, message


class TelnetChannel:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, cols: int = 120, rows: int = 32):
        self.r, self.w = reader, writer
        self.size = (cols, rows)
        self._naws = False
        self._pending = b""

    @classmethod
    async def open(cls, host: str, port: int, timeout: float, cols: int = 120, rows: int = 32) -> "TelnetChannel":
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        except (OSError, asyncio.TimeoutError) as e:
            raise TelnetError("connect_failed", f"Telnet connection to port {port} failed: {type(e).__name__}")
        return cls(r, w, cols, rows)

    def _send_naws(self) -> None:
        c, r = self.size
        payload = bytes([c >> 8, c & 0xFF, r >> 8, r & 0xFF]).replace(b"\xff", b"\xff\xff")
        self.w.write(bytes([IAC, SB, NAWS]) + payload + bytes([IAC, SE]))

    def _negotiate(self, data: bytes) -> bytes:
        """Strip IAC sequences from `data`, answering option requests; returns the payload bytes."""
        data = self._pending + data
        self._pending = b""
        out = bytearray()
        i = 0
        while i < len(data):
            b = data[i]
            if b != IAC:
                out.append(b)
                i += 1
                continue
            if i + 1 >= len(data):
                self._pending = data[i:]
                break
            cmd = data[i + 1]
            if cmd == IAC:
                out.append(IAC)
                i += 2
                continue
            if cmd in (DO, DONT, WILL, WONT):
                if i + 2 >= len(data):
                    self._pending = data[i:]
                    break
                opt = data[i + 2]
                if cmd == DO:
                    if opt == NAWS:
                        self.w.write(bytes([IAC, WILL, NAWS]))
                        self._naws = True
                        self._send_naws()
                    else:
                        self.w.write(bytes([IAC, WONT, opt]))
                elif cmd == WILL:
                    self.w.write(bytes([IAC, DO if opt in (ECHO, SGA) else DONT, opt]))
                i += 3
                continue
            if cmd == SB:
                end = data.find(bytes([IAC, SE]), i + 2)
                if end < 0:
                    self._pending = data[i:]
                    break
                i = end + 2
                continue
            i += 2                                   # NOP, GA and other two-byte commands
        return bytes(out)

    async def read(self) -> str:
        while True:
            chunk = await self.r.read(32768)
            if not chunk:
                return ""
            payload = self._negotiate(chunk)
            if payload:
                return payload.decode("utf-8", errors="replace")

    def write(self, text: str) -> None:
        self.w.write(text.encode("utf-8", errors="replace").replace(b"\xff", b"\xff\xff"))

    def resize(self, cols: int, rows: int) -> None:
        self.size = (cols, rows)
        if self._naws:
            self._send_naws()

    def close(self) -> None:
        try:
            self.w.close()
        except Exception:
            pass

    async def login(self, username: str, password: str, timeout: float, wake: bool = False) -> str:
        """Answer the login prompts with the vault credential; returns everything the device printed. The password is
        sent only after a password prompt; nothing is echoed back to the browser by us."""
        buf, sent_user, sent_pw = "", False, False
        deadline = time.monotonic() + timeout
        if wake:
            self.write("\r")                          # a console line shows its prompt after Enter
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TelnetError("timeout", "no login prompt from the device in time")
            try:
                part = await asyncio.wait_for(self.read(), min(left, 2.0))
            except asyncio.TimeoutError:
                if not buf and not sent_user:
                    self.write("\r")
                continue
            if part == "":
                raise TelnetError("connect_failed", "the device closed the Telnet connection")
            buf += part
            tail = buf.replace("\r", "").split("\n")[-1]
            if _FAIL.search(buf):
                raise TelnetError("auth_failed", "the device rejected the Telnet login (check the credential)")
            if _PASSWORD.search(tail) and not sent_pw:
                self.write(password + "\r")
                sent_pw = True
                buf += "\n"
            elif _LOGIN.search(tail) and not sent_user:
                self.write(username + "\r")
                sent_user = True
                buf += "\n"
            elif _PROMPT.search(tail) and (sent_pw or not sent_user):
                return buf
            elif _LOGIN.search(tail) and sent_user and sent_pw:
                raise TelnetError("auth_failed", "the device asked for the login again (credential rejected)")
