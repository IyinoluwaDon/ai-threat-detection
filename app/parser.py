import re
from typing import Optional

LOG_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<proto>[^"]*)" '
    r'(?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<referrer>[^"]*)" "(?P<ua>[^"]*)"'
)


def parse_line(line: str) -> Optional[dict]:
    m = LOG_RE.match(line)
    return m.groupdict() if m else None
