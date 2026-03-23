import asyncio, logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from routers.api import alerts_router, stats_router, response_router
from routers.cases import router as cases_router
from routers.ws import ws_endpoint, broadcast_loop

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(broadcast_loop())
    yield
    task.cancel()

app = FastAPI(title="HQG AI-SOC Platform", version="2.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

app.include_router(alerts_router)
app.include_router(stats_router)
app.include_router(response_router)
app.include_router(cases_router)

@app.websocket("/ws")
async def ws_route(ws: WebSocket):
    await ws_endpoint(ws)

@app.get("/health")
async def health():
    return {"status": "ok"}

app.mount("/", StaticFiles(directory="../static", html=True), name="static")
