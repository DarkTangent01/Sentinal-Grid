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
        for key in ("firewall_id", "component", "count", "duration_ms"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        if record.exc_info:
            payload["exc"] = redact(self.formatException(record.exc_info))
        return json.dumps(payload)


def setup_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    logging.getLogger("httpx").setLevel("WARNING")
