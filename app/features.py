import math
import re
from collections import Counter
from urllib.parse import unquote_plus

SQL_KW = re.compile(r"(?i)\b(select|union|insert|update|delete|drop|sleep|benchmark|where|from|having|waitfor|exec|cast|concat|substring|version)\b")
XSS_KW = re.compile(r"(?i)(script|javascript|onerror|onload|onfocus|ontoggle|onpageshow|<svg|<img|<iframe)")
TOOL_UA = re.compile(r"(?i)(curl|sqlmap|nikto|wget|python-requests|hydra|nmap|gobuster|masscan|zgrab|dirbuster)")
SENSITIVE = re.compile(r"(?i)(\.env|\.git|wp-login|wp-admin|wp-content|phpmyadmin|cgi-bin|actuator|\.php|passwd|boot\.ini|etc/|credentials|xmlrpc|backup|server-status|solr|vendor/|\.ds_store|web-inf|jmx-console|heapdump|struts|id_rsa|dump\.sql)")
NOSQL = re.compile(r"(?i)(\[\$\w+\]|\$(ne|gt|gte|lt|lte|regex|where|in|nin|or|and)\b)")

FEATURES = [
    "path_len", "query_len", "num_params", "max_param_len",
    "special_ratio", "digit_ratio", "upper_ratio", "entropy",
    "pct_count", "double_enc", "dotdot", "quotes", "angles",
    "sql_kw", "xss_kw", "sql_comment", "sensitive_path",
    "is_post", "depth", "ua_len", "ua_tool", "ua_empty",
    "nosql_op", "scheme_in_query", "proto_rel", "at_sign", "enc_ratio", "semicolon",
]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in Counter(s).values())


def extract(record: dict) -> list[float]:
    raw = record.get("path", "") or ""
    ua = record.get("ua", "") or ""
    method = record.get("method", "GET") or "GET"
    dec = unquote_plus(unquote_plus(raw))
    path_part, _, query = raw.partition("?")
    n = max(len(dec), 1)
    values = [p.partition("=")[2] for p in query.split("&")] if query else []
    vals = {
        "path_len": len(path_part),
        "query_len": len(query),
        "num_params": len(values),
        "max_param_len": max((len(v) for v in values), default=0),
        "special_ratio": sum(1 for c in dec if not c.isalnum() and c not in "/.") / n,
        "digit_ratio": sum(c.isdigit() for c in dec) / n,
        "upper_ratio": sum(c.isupper() for c in dec) / n,
        "entropy": _entropy(dec),
        "pct_count": raw.count("%"),
        "double_enc": int("%25" in raw),
        "dotdot": dec.count(".."),
        "quotes": dec.count("'") + dec.count('"'),
        "angles": dec.count("<") + dec.count(">"),
        "sql_kw": len(SQL_KW.findall(dec)),
        "xss_kw": len(XSS_KW.findall(dec)),
        "sql_comment": dec.count("--") + dec.count("/*") + dec.count("#"),
        "sensitive_path": int(bool(SENSITIVE.search(dec))),
        "is_post": int(method.upper() == "POST"),
        "depth": path_part.count("/"),
        "ua_len": len(ua),
        "ua_tool": int(bool(TOOL_UA.search(ua))),
        "ua_empty": int(ua in ("", "-")),
        "nosql_op": len(NOSQL.findall(dec)),
        "scheme_in_query": dec.partition("?")[2].count("://"),
        "proto_rel": int(bool(re.search(r"=\s*//", dec))),
        "at_sign": dec.count("@"),
        "enc_ratio": raw.count("%") / max(len(raw), 1),
        "semicolon": dec.count(";"),
    }
    return [float(vals[f]) for f in FEATURES]
