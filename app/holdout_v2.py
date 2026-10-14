"""Holdout v2: fresh hand-written requests, written before the round-2 model changes."""
from app.engine import Engine
from app.holdout_eval import run

BENIGN = [
    "/search?q=caf%C3%A9+near+yaba",
    "/login?redirect=%2Fprofile%2Fedit",
    "/api/v2/products?filter=category%3Dphones&sort=price",
    "/cart/add?sku=NG-4410&qty=2",
    "/articles/2026/10/intro-to-zero-trust",
    "/search?q=insert+coupon+code+at+checkout",
    "/static/fonts/inter-var.woff2",
    "/account/orders/88213/invoice.pdf",
    "/api/search?term=drop+shipping+nigeria",
    "/events?date=2026-10-20&city=Ikeja",
    "/download/report-q3-2026.pdf",
    "/profile?id=77&tab=security",
]

ATTACKS = [
    "/api/users?username[$regex]=^adm",
    "/api/login?user[$ne]=x&pass[$ne]=x",
    "/go?next=//attacker.example/login",
    "/out?target=https://evil.example.net@trusted.example",
    "/wp-includes/wlwmanifest.xml",
    "/jenkins/script",
    "/manager/html",
    "/.svn/entries",
    "/product?id=5%20AND%201=CONVERT(int,(SELECT%20@@version))",
    "/search?q=%22%3E%3Cscript%3Eprompt(document.domain)%3C/script%3E",
    "/static/..%2f..%2f..%2fetc%2fshadow",
    "/preview?url=http://[::ffff:127.0.0.1]/",
]

if __name__ == "__main__":
    e = Engine()
    fp = run(e, BENIGN, "BENIGN v2 (want: ok)")
    tp = run(e, ATTACKS, "ATTACKS v2 (want: ALERT)")
    print(f"\nfalse positives: {fp}/{len(BENIGN)}   detected: {tp}/{len(ATTACKS)}")
