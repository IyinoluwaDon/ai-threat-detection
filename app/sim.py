"""Send a mix of benign and attack requests to the stub server."""
import random
import sys
import time
import urllib.request

from app import gen_dataset as g

random.seed()  # gen_dataset seeds on import; reseed so each run differs
TARGET = "http://localhost:8080"


def pick():
    if random.random() < 0.7:
        method, path, ua = random.choice(g.BENIGN)()
        return method, path, ua or random.choice(g.BROWSER_UAS)
    cat = random.choice(list(g.ATTACKS))
    method, path, ua = random.choice(g.ATTACKS[cat])()
    return method, path, ua or random.choice(g.TOOL_UAS)


def main(n: int = 40, delay: float = 0.3):
    for _ in range(n):
        method, path, ua = pick()
        req = urllib.request.Request(TARGET + path, method=method, headers={"User-Agent": ua},
                                     data=b"" if method == "POST" else None)
        try:
            urllib.request.urlopen(req, timeout=3).read()
        except Exception as e:
            print("skip", path, e)
        time.sleep(delay)
    print(f"sent {n} requests")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 40)
