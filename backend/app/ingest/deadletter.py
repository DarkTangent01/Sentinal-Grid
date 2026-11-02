"""Dead-letter spool for event chunks ClickHouse keeps rejecting while it accepts everything else.

A rejected chunk used to sit at the head of the buffer forever, blocking every later event. It is now written here
(one JSON line per event, datetimes tagged) so ingestion continues and nothing is lost silently. After fixing the
cause (for example a device clock years off, which can exceed ClickHouse's partitions-per-insert limit):

    python -m app.ingest.deadletter list
    python -m app.ingest.deadletter replay            # re-insert every spooled file; a file is removed once it lands

Mount a volume at INGEST_DEADLETTER_DIR to keep the spool across container recreation.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

from ..config import get_settings

_DT = "$dt"


def _enc(v):
    if isinstance(v, datetime):
        return {_DT: v.isoformat()}
    raise TypeError(f"not JSON serializable: {type(v).__name__}")


def _dec(obj: dict):
    return datetime.fromisoformat(obj[_DT]) if set(obj) == {_DT} else obj


def spool_dir() -> Path:
    return Path(get_settings().ingest_deadletter_dir)


def write(events: list[dict]) -> Path:
    d = spool_dir()
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"events-{time.strftime('%Y%m%dT%H%M%S')}-{os.getpid()}-{time.monotonic_ns()}.jsonl"
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev, default=_enc, separators=(",", ":")) + "\n")
    os.replace(tmp, path)  # a reader never sees a half-written file
    return path


def read(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line, object_hook=_dec) for line in f if line.strip()]


def files() -> list[Path]:
    d = spool_dir()
    return sorted(d.glob("events-*.jsonl")) if d.is_dir() else []


def replay(ch, batch: int = 10_000) -> tuple[int, int]:
    """Re-insert spooled files. Returns (events inserted, files still failing)."""
    from ..db.ch_schema import EVENT_COLUMNS
    done = failing = 0
    for path in files():
        events = read(path)
        try:
            for i in range(0, len(events), batch):
                ch.insert("events", events[i:i + batch], EVENT_COLUMNS)
        except Exception as e:
            failing += 1
            print(f"{path.name}: still rejected ({type(e).__name__}: {str(e)[:200]})", file=sys.stderr)
            continue
        path.unlink()
        done += len(events)
    return done, failing


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.ingest.deadletter")
    ap.add_argument("action", choices=["list", "replay"])
    a = ap.parse_args(argv)
    if a.action == "list":
        for p in files():
            print(f"{p.name}\t{sum(1 for _ in open(p, encoding='utf-8'))} events")
        return 0
    from ..db.ch import get_ch
    n, failing = replay(get_ch())
    print(f"replayed {n} events; {failing} file(s) still rejected")
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
