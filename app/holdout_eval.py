"""Hand-written requests that are NOT in the training templates."""
from app.engine import Engine

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36"

BENIGN = [
    "/search?q=select+the+best+laptop+from+jumia",
    "/api/v1/users/1042/orders?status=shipped&sort=-created_at",
    "/static/js/app.min.js?v=3.2.1",
    "/blog/2026/10/how-to-secure-ssh-keys",
    "/login?next=%2Fdashboard%2Fsettings",
    "/search?q=C%2B%2B+tutorial",
    "/products?category=laptops&price_min=100000&price_max=500000",
    "/images/photo_2026-10-14_08.31.jpg",
    "/api/health",
    "/search?q=union+of+nigerian+students",
    "/docs/api#authentication",
    "/search?q=what%27s+the+weather+in+lagos",
]

ATTACKS = [
    "/rest/products/search?q=%27))%20UNION%20SELECT%20username,password%20FROM%20users--",
    "/index.php?page=php://filter/convert.base64-encode/resource=config",
    "/?name=%3Csvg/onload=alert(1)%3E",
    "/api/users?id=1;DROP%20TABLE%20users",
    "/admin/../../../../windows/win.ini",
    "/wp-content/plugins/x/readme.txt",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/.git/HEAD",
    "/solr/admin/info/system",
    "/api/v1/users?filter[$ne]=null",
    "/redirect?url=//evil.example.com",
    "/download?file=....//....//etc/passwd",
]


def run(engine, paths, label):
    hits = 0
    print(f"\n{label}")
    for p in paths:
        a = engine.analyze({"ip": "10.0.0.9", "path": p, "ua": UA, "method": "GET"})
        hits += bool(a)
        tag = f"ALERT {a['source']:<5} {a['score']:.2f}" if a else "ok"
        print(f"  {tag:<18} {p}")
    return hits


if __name__ == "__main__":
    e = Engine()
    fp = run(e, BENIGN, "BENIGN (want: ok)")
    tp = run(e, ATTACKS, "ATTACKS (want: ALERT)")
    print(f"\nfalse positives: {fp}/{len(BENIGN)}   detected: {tp}/{len(ATTACKS)}")
