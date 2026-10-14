"""Holdout v3: written BEFORE the round-3 rule changes. Frozen after the first run."""
from app.engine import Engine
from app.holdout_eval import run

BENIGN = [
    "/login?next=%2Faccount%2Fbilling",
    "/search?q=update+your+profile+settings",
    "/shop?cat=books&sort=price_asc&page=3",
    "/blog/benchmark-results-2026",
    "/api/v1/orders/9921/track",
    "/redirect?url=https://www.jumia.com.ng/phones",
    "/search?q=how+to+order+by+phone",
    "/images/hero%20banner.png",
    "/profile/edit?tab=notifications&saved=1",
    "/wp-content/uploads/2026/10/cover.jpg",
    "/api/search?q=select+committee+report",
    "/docs/getting-started#install",
]

ATTACKS = [
    # families the round-3 rules target (new instances)
    "/api/orders?status[$in][]=paid",
    "/search?q[$where]=this.password.length>0",
    "/auth?return=//phish.example/login",
    "/click?url=https://good.example.org@evil.example.io/x",
    "/blog/wp-admin/install.php",
    "/.hg/store/data",
    "/web-console/",
    "/database.sql",
    "/item?id=3;SHUTDOWN--",
    "/proxy?url=http://2852039166/latest/meta-data",
    # families deliberately NOT covered (expected misses)
    "/greet?name={{7*7}}",
    "/ping?host=8.8.8.8%7Cid",
    "/lookup?user=*)(uid=*))(|(uid=*",
    "/set?lang=en%0d%0aSet-Cookie:%20admin=true",
]

if __name__ == "__main__":
    e = Engine()
    fp = run(e, BENIGN, "BENIGN v3 (want: ok)")
    tp = run(e, ATTACKS, "ATTACKS v3 (want: ALERT)")
    print(f"\nfalse positives: {fp}/{len(BENIGN)}   detected: {tp}/{len(ATTACKS)}")
