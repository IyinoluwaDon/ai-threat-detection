import pytest

from app.rules import detect


def r(p, ua="Mozilla/5.0"):
    return {"path": p, "ua": ua}


@pytest.mark.parametrize("path,cat", [
    ("/api/x?a[$ne]=1", "nosql_injection"),
    ("/go?next=//evil.example/x", "open_redirect"),
    ("/go?url=https://a.example@b.example", "open_redirect"),
    ("/.svn/entries", "recon"),
    ("/jenkins/script", "recon"),
    ("/wp-includes/x.js", "recon"),
    ("/.env", "recon"),
    ("/db.sql", "recon"),
    ("/i?id=1;DROP TABLE t", "sqli"),
    ("/p?id=5 AND 1=CONVERT(int,@@version)", "sqli"),
    ("/f?url=http://[::1]/", "ssrf"),
    ("/f?url=http://2130706433/", "ssrf"),
])
def test_new_rules_fire(path, cat):
    assert cat in detect(r(path))


@pytest.mark.parametrize("path", [
    "/login?next=%2Fdashboard%2Fsettings",
    "/search?q=drop+shipping+nigeria",
    "/blog/benchmark-results-2026",
    "/redirect?url=https://www.jumia.com.ng/phones",
    "/search?q=how+to+order+by+phone",
    "/wp-content/uploads/2026/10/cover.jpg",
    "/api/v1/users/12/orders?sort=-id",
    "/static/old/app.css",
    "/search?q=update+profile+settings",
])
def test_new_rules_no_false_positives(path):
    assert detect(r(path)) == []
