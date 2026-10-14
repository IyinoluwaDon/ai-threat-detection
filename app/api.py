import asyncio
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse

from app.engine import Engine
from app.parser import parse_line
from app.store import Store
from app.tailer import tail

LOG_PATH = os.environ.get("LOG_PATH", "logs/access.log")
INDEX = os.path.join(os.path.dirname(__file__), "static", "index.html")
store = Store(os.environ.get("DB_PATH", "data/alerts.db"))
clients: set = set()


async def broadcast(alert: dict):
    for ws in list(clients):
        try:
            await ws.send_json(alert)
        except Exception:
            clients.discard(ws)


async def consume(engine: Engine):
    async for line in tail(LOG_PATH):
        rec = parse_line(line)
        if not rec:
            continue
        alert = engine.analyze(rec)
        if alert:
            await broadcast(store.add(alert))


@asynccontextmanager
async def lifespan(app: FastAPI):
    os.makedirs(os.path.dirname(LOG_PATH) or ".", exist_ok=True)
    open(LOG_PATH, "a").close()
    task = asyncio.create_task(consume(Engine()))
    yield
    task.cancel()


app = FastAPI(title="AI Threat Detection Engine", lifespan=lifespan)


@app.get("/")
def index():
    return FileResponse(INDEX)


@app.get("/api/alerts")
def alerts(limit: int = 50):
    return store.recent(min(limit, 500))


@app.get("/api/stats")
def stats():
    return store.stats()


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    clients.add(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        clients.discard(ws)
