"""ClickHouse access layer.

mode=server   -> clickhouse-connect over HTTP with server-side parameter binding (production).
mode=embedded -> chdb in-process engine (development and automated tests only).
Queries use ClickHouse `{name:Type}` placeholders in both modes.
"""
import asyncio
import json
import queue
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

from ..config import get_settings

_PARAM = re.compile(r"\{(\w+):([^}]+)\}")


def _literal(value: Any, typ: str) -> str:
    if value is None:
        return "NULL"
    if typ.startswith("Array("):
        inner = typ[6:-1]
        return "[" + ",".join(_literal(v, inner) for v in value) + "]"
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, float)) and not typ.startswith(("String", "DateTime")):
        return repr(value)
    if isinstance(value, datetime):
        value = value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    s = str(value).replace("\\", "\\\\").replace("'", "\\'").replace("\x00", "\\0").replace("\n", "\\n")
    if typ.startswith("DateTime"):
        return f"toDateTime64('{s}', 3, 'UTC')"
    if typ.startswith(("UInt", "Int", "Float")):
        float(s)  # validate numeric
        return s
    return f"'{s}'"


def render_params(sql: str, params: dict | None) -> str:
    params = params or {}

    def sub(m: re.Match) -> str:
        name, typ = m.group(1), m.group(2)
        if name not in params:
            raise KeyError(f"missing query parameter {name}")
        return _literal(params[name], typ)

    return _PARAM.sub(sub, sql)


class ClickHouse:
    def __init__(self, mode: str | None = None, embedded_path: str | None = None):
        s = get_settings()
        self.mode = mode or s.clickhouse_mode
        self.database = s.clickhouse_database
        self._lock = threading.Lock()
        if self.mode == "embedded":
            import os
            # chdb probes stdin on every INSERT, even with inline data: with stdin left open as a pipe (process
            # supervisors, IDE launchers) the insert blocks forever while holding the session lock. Embedded mode never
            # reads stdin, so detach it.
            if not os.isatty(0):
                fd = os.open(os.devnull, os.O_RDONLY)
                os.dup2(fd, 0)
                os.close(fd)
            from chdb import session as chs

            self._sess = chs.Session(embedded_path or s.clickhouse_embedded_path or None)
            self._sess.query(f"CREATE DATABASE IF NOT EXISTS {self.database}")
            self._sess.query(f"USE {self.database}")
            self._sess.query("SET output_format_json_quote_64bit_integers=0")
            self._sess.query("SET output_format_json_quote_64bit_floats=0")
            self._sess.query("SET date_time_input_format='best_effort'")  # accept ms precision for DateTime columns
        else:
            import clickhouse_connect

            def new_client():
                return clickhouse_connect.get_client(
                    host=s.clickhouse_host, port=s.clickhouse_port, username=s.clickhouse_user,
                    password=s.clickhouse_password, database=s.clickhouse_database,
                    settings={"max_execution_time": 60}, connect_timeout=10, send_receive_timeout=120,
                )
            size = max(1, s.clickhouse_pool_size)
            self._new_client = new_client
            self._idle: queue.LifoQueue = queue.LifoQueue()
            self._idle.put(new_client())  # connect once up front so a bad host/credential fails at startup, as before
            self._slots = threading.BoundedSemaphore(size)
            # own threads: blocking ClickHouse calls must not occupy the default executor other code relies on
            self._executor = ThreadPoolExecutor(max_workers=size, thread_name_prefix="clickhouse")

    @contextmanager
    def _client(self):
        """One client per concurrent request (a clickhouse-connect client is not safe for concurrent use)."""
        with self._slots:
            try:
                c = self._idle.get_nowait()
            except queue.Empty:
                c = self._new_client()
            try:
                yield c
            finally:
                self._idle.put(c)

    # --- sync API -------------------------------------------------------
    def query(self, sql: str, params: dict | None = None) -> list[dict]:
        if self.mode == "embedded":
            with self._lock:
                res = self._sess.query(render_params(sql, params), "JSONEachRow")
            text = res.bytes().decode() if hasattr(res, "bytes") else str(res)
            return [json.loads(line) for line in text.splitlines() if line.strip()]
        with self._client() as c:
            r = c.query(sql, parameters=params or {})
        return [dict(zip(r.column_names, row)) for row in r.result_rows]

    def command(self, sql: str, params: dict | None = None) -> None:
        if self.mode == "embedded":
            with self._lock:
                self._sess.query(render_params(sql, params))
            return
        with self._client() as c:
            c.command(sql, parameters=params or {})

    def insert(self, table: str, rows: list[dict], columns: list[str]) -> None:
        if not rows:
            return
        if self.mode == "embedded":
            def enc(v):
                if isinstance(v, datetime):
                    return v.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                return v
            body = "\n".join(json.dumps({c: enc(r.get(c)) for c in columns}) for r in rows)
            with self._lock:
                self._sess.query(f"INSERT INTO {table} ({','.join(columns)}) FORMAT JSONEachRow\n{body}")
            return
        data = [[r.get(c) for c in columns] for r in rows]
        with self._client() as c:
            c.insert(table, data, column_names=columns)

    # --- async wrappers -------------------------------------------------
    async def _run(self, fn, *args):
        if self.mode == "embedded":
            return await asyncio.to_thread(fn, *args)
        return await asyncio.get_running_loop().run_in_executor(self._executor, fn, *args)

    async def aquery(self, sql: str, params: dict | None = None) -> list[dict]:
        return await self._run(self.query, sql, params)

    async def acommand(self, sql: str, params: dict | None = None) -> None:
        await self._run(self.command, sql, params)

    async def ainsert(self, table: str, rows: list[dict], columns: list[str]) -> None:
        await self._run(self.insert, table, rows, columns)


_ch: ClickHouse | None = None


def get_ch() -> ClickHouse:
    global _ch
    if _ch is None:
        _ch = ClickHouse()
    return _ch


def set_ch(ch: ClickHouse | None) -> None:
    global _ch
    _ch = ch
