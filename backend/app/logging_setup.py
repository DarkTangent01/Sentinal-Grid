"""Structured JSON logging with token redaction."""
import json
import logging
import re
import sys
from datetime import datetime, timezone

_REDACT = re.compile(r"(?i)(authorization:\s*bearer\s+|access_token=|api[_-]?token[\"']?\s*[:=]\s*[\"']?)[A-Za-z0-9._\-]+")


def redact(text: str) -> str:
    return _REDACT.sub(r"\1[REDACTED]", text)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": redact(record.getMessage()),
        }
        for key in ("request_id", "firewall_id", "component", "count", "duration_ms", "status"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        if record.exc_info:
            payload["exc"] = redact(self.formatException(record.exc_info))
        return json.dumps(payload)


def setup_logging(level: str = "INFO") -> None:
    from .observability import RequestIdFilter
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RequestIdFilter())  # API requests: every line carries the request id
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    logging.getLogger("httpx").setLevel("WARNING")
    try:  # once per process: secrets still passed as environment variables (names only, never values)
        from .config import get_settings
        from .secret_files import warn_plain_env
        warn_plain_env(get_settings().environment)
    except Exception:  # configuration errors surface where the settings are first used, with their own message
        pass
