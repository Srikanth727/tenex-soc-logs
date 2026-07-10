import html
from datetime import datetime
from typing import Optional

# Default Zscaler NSS Web Proxy pipe-delimited feed field order. Zscaler NSS feeds
# use an admin-defined custom format string; this matches a typical layout:
#   datetime|cip|login|url|respcode|action|urlcat|threatname|reqmethod|reqsize|respsize|malwarecat|riskscore
FIELD_ORDER = [
    "timestamp",
    "cip",
    "login",
    "url",
    "respcode",
    "action",
    "urlcat",
    "threatname",
    "reqmethod",
    "reqsize",
    "respsize",
    "malwarecat",
    "riskscore",
]

TIMESTAMP_FORMATS = [
    "%a %b %d %H:%M:%S %Y",  # Thu Jul 10 14:32:01 2026
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
]

INT_FIELDS = {"reqsize", "respsize", "riskscore"}


def _sanitize(value: str) -> str:
    """Escape HTML-significant characters so untrusted log content is safe to
    store and later render in the dashboard without risk of stored XSS."""
    return html.escape(value.strip(), quote=True)


def _parse_timestamp(value: str) -> Optional[datetime]:
    value = value.strip()
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def parse_zscaler_line(line: str) -> Optional[dict]:
    """Parse a single pipe-delimited Zscaler NSS Web Proxy log line into a dict
    of LogEntry field values. Returns None for blank lines or comments."""
    line = line.rstrip("\r\n")
    if not line.strip() or line.lstrip().startswith("#"):
        return None

    raw_parts = line.split("|")
    fields: dict = {}

    for name, raw_value in zip(FIELD_ORDER, raw_parts):
        raw_value = raw_value.strip()
        if name == "timestamp":
            fields[name] = _parse_timestamp(raw_value)
        elif name in INT_FIELDS:
            try:
                fields[name] = int(raw_value) if raw_value else 0
            except ValueError:
                fields[name] = 0
        else:
            fields[name] = _sanitize(raw_value) if raw_value else None

    for name in FIELD_ORDER:
        fields.setdefault(name, None)

    fields["raw_line"] = _sanitize(line)
    return fields


def parse_zscaler_file(content: str) -> list[dict]:
    """Parse the full text content of a Zscaler NSS log file into a list of
    LogEntry-ready field dicts, skipping blank lines and comments."""
    entries = []
    for line in content.splitlines():
        parsed = parse_zscaler_line(line)
        if parsed is not None:
            entries.append(parsed)
    return entries
