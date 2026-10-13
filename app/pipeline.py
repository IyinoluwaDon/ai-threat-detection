import asyncio
import json
import sys

from app.parser import parse_line
from app.rules import detect
from app.tailer import tail


async def run(path: str):
    async for line in tail(path):
        rec = parse_line(line)
        if not rec:
            continue
        hits = detect(rec)
        if hits:
            print(json.dumps({"ip": rec["ip"], "path": rec["path"], "rules": hits}), flush=True)


if __name__ == "__main__":
    asyncio.run(run(sys.argv[1] if len(sys.argv) > 1 else "logs/access.log"))
