"""FortiGate syslog parsing (default key=value format, RFC3164/RFC5424 envelope tolerant)."""
import re

_PRI = re.compile(r"^\s*<\d{1,3}>")
# RFC5424: <pri>1 TIMESTAMP HOST APP PROCID MSGID [SD|-] MSG
_RFC5424 = re.compile(r"^1 \S+ \S+ \S+ \S+ \S+ (?:-|\[.*?\]) ?")
_KV = re.compile(r'([A-Za-z0-9_\-\.]+)=(?:"((?:[^"\\]|\\.)*)"|(\S*))')


class ParseError(ValueError):
    pass


def strip_envelope(line: str) -> str:
    line = _PRI.sub("", line, count=1)
    m = _RFC5424.match(line)
    if m:
        line = line[m.end():]
    # RFC3164-style "Mmm dd hh:mm:ss host " prefix before the first key=value
    idx = line.find("=")
    if idx > 0:
        start = line.rfind(" ", 0, idx)
        prefix = line[: start + 1] if start >= 0 else ""
        if prefix and "=" not in prefix:
            line = line[start + 1:]
    return line.strip()


def _unescape(v: str) -> str:
    return v.replace('\\"', '"').replace("\\\\", "\\")


def parse_kv(line: str) -> dict[str, str]:
    """Parse FortiGate key=value log text into a dict. Quoted values may contain spaces and escaped quotes."""
    body = strip_envelope(line)
    if "=" not in body:
        raise ParseError("not a key=value FortiGate log")
    out: dict[str, str] = {}
    for key, quoted, bare in _KV.findall(body):
        if bare:
            if len(bare) >= 2 and bare[0] == '"' and bare[-1] == '"':  # e.g. an unterminated escape: legacy handling
                bare = _unescape(bare[1:-1])
            out[key] = bare
        else:
            out[key] = _unescape(quoted) if "\\" in quoted else quoted
    if "type" not in out and "logid" not in out:
        raise ParseError("missing FortiGate type/logid fields")
    return out
