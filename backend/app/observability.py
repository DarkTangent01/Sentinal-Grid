"""Request correlation and in-process API metrics.

Every API request gets an id (a caller's X-Request-ID is reused only if it is a short safe token, so a client cannot
inject log content). The id is returned in the response, attached to every log record written while the request runs,
and printed on one access-log line per request. Metrics are per process (each uvicorn worker has its own) and served
in Prometheus text format at /api/metrics to administrators; labels are route templates, never raw paths or queries.
"""
from __future__ import annotations

import contextvars
import logging
import re
import threading
import time
import uuid
from collections import defaultdict

request_id: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="")
_SAFE_ID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.2, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)  # seconds

access_log = logging.getLogger("api.access")


def new_request_id(incoming: str | None) -> str:
    return incoming if incoming and _SAFE_ID.match(incoming) else uuid.uuid4().hex


class RequestIdFilter(logging.Filter):
    """Adds request_id to every record (the JSON formatter prints it when set)."""

    def filter(self, record: logging.LogRecord) -> bool:
        rid = request_id.get()
        if rid and not hasattr(record, "request_id"):
            record.request_id = rid
        return True


class ApiMetrics:
    def __init__(self):
        self._lock = threading.Lock()
        self.count: dict[tuple[str, str, str], int] = defaultdict(int)      # (method, route, status class)
        self.hist: dict[tuple[str, str], list[int]] = {}                    # (method, route) -> bucket counts (+Inf last)
        self.total_s: dict[tuple[str, str], float] = defaultdict(float)
        self.started = time.time()

    def observe(self, method: str, route: str, status: int, seconds: float) -> None:
        key = (method, route)
        with self._lock:
            self.count[(method, route, f"{status // 100}xx")] += 1
            h = self.hist.setdefault(key, [0] * (len(BUCKETS) + 1))
            for i, b in enumerate(BUCKETS):
                if seconds <= b:
                    h[i] += 1
                    break
            else:
                h[-1] += 1
            self.total_s[key] += seconds

    def render(self, extra: dict[str, float] | None = None) -> str:
        def esc(v: str) -> str:
            return v.replace("\\", "\\\\").replace('"', '\\"')
        out = ["# HELP api_requests_total API requests by route template and status class.", "# TYPE api_requests_total counter"]
        with self._lock:
            for (m, r, sc), n in sorted(self.count.items()):
                out.append(f'api_requests_total{{method="{m}",route="{esc(r)}",status="{sc}"}} {n}')
            out += ["# HELP api_request_duration_seconds API latency.", "# TYPE api_request_duration_seconds histogram"]
            for (m, r), h in sorted(self.hist.items()):
                lbl = f'method="{m}",route="{esc(r)}"'
                cum = 0
                for b, n in zip(BUCKETS, h):
                    cum += n
                    out.append(f'api_request_duration_seconds_bucket{{{lbl},le="{b}"}} {cum}')
                cum += h[-1]
                out.append(f'api_request_duration_seconds_bucket{{{lbl},le="+Inf"}} {cum}')
                out.append(f"api_request_duration_seconds_sum{{{lbl}}} {self.total_s[(m, r)]:.6f}")
                out.append(f"api_request_duration_seconds_count{{{lbl}}} {cum}")
        out += ["# TYPE process_uptime_seconds gauge", f"process_uptime_seconds {time.time() - self.started:.0f}"]
        for name, value in (extra or {}).items():
            out += [f"# TYPE {name} gauge", f"{name} {value}"]
        return "\n".join(out) + "\n"


METRICS = ApiMetrics()


def route_of(request) -> str:
    """Route template ("/api/switches/{sid}"), so ids and query strings never become metric labels."""
    route = request.scope.get("route")
    return getattr(route, "path", None) or "unmatched"
