import re
from urllib.parse import unquote_plus

RULES = {
    "sqli": [
        r"(?i)\bunion\b.+\bselect\b",
        r"(?i)\b(or|and)\b\s+\d+\s*=\s*\d+",
        r"(?i)'\s*(or|and)\s+'?\w",
        r"(?i)'\s*(--|#)",
        r"(?i)\bsleep\s*\(",
        r"(?i)information_schema",
    ],
    "xss": [
        r"(?i)<script",
        r"(?i)\bon(error|load|click|mouseover)\s*=",
        r"(?i)javascript:",
    ],
    "path_traversal": [
        r"\.\./",
        r"(?i)/etc/(passwd|shadow)",
        r"(?i)\\windows\\",
    ],
    "ssrf": [
        r"(?i)[?&](url|uri|dest|redirect|next|target)=https?://"
        r"(127\.|localhost|0\.0\.0\.0|169\.254\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)",
        r"(?i)(file|gopher)://",
    ],
    "log4shell": [
        r"(?i)\$\{jndi:",
        r"(?i)\$\{\$\{",
    ],
}
COMPILED = {k: [re.compile(p) for p in v] for k, v in RULES.items()}


def _normalize(s: str) -> str:
    # decode twice to catch double-encoded payloads
    return unquote_plus(unquote_plus(s))


def detect(record: dict) -> list[str]:
    """Return the rule categories that match a parsed log record."""
    text = _normalize(f'{record.get("path", "")} {record.get("ua", "")}')
    return [cat for cat, pats in COMPILED.items() if any(p.search(text) for p in pats)]
