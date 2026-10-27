"""FortiOS version handling."""
import re

SUPPORTED_MAJOR_MINOR = {(6, 4), (7, 0), (7, 2), (7, 4), (7, 6)}


def parse_version(v: str | None) -> tuple[int, int, int] | None:
    if not v:
        return None
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", v)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def support_level(v: str | None) -> str:
    p = parse_version(v)
    if p is None:
        return "unknown"
    if p[:2] in SUPPORTED_MAJOR_MINOR:
        return "documented" if p[:2] >= (7, 0) else "best-effort"
    return "untested"
