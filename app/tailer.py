import asyncio
import os


async def tail(path: str, poll: float = 0.2):
    """Yield new lines appended to a file."""
    with open(path, "r", errors="replace") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if line:
                yield line.rstrip("\n")
            else:
                await asyncio.sleep(poll)
