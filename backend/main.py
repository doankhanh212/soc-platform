import asyncio, logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from routers.api import alerts_router, stats_router, response_router, blocked_router
from routers.cases import router as cases_router
from routers.rules import router as rules_router
from routers.auth import router as auth_router
from routers.hunting import router as hunting_router
from routers.ai import router as ai_router
from routers.report import router as report_router
from routers.threatintel import router as threatintel_router
from routers.settings import router as settings_router
from routers.ws import ws_endpoint, broadcast_loop
from services.rule_engine import rule_engine_loop
from ai.runner import ai_engine_loop
from response.firewall import load_blocked_from_iptables

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

@asynccontextmanager
async def lifespan(app: FastAPI):
    load_blocked_from_iptables()
    task      = asyncio.create_task(broadcast_loop())
    rule_task = asyncio.create_task(rule_engine_loop())
    ai_task   = asyncio.create_task(ai_engine_loop())
    yield
    task.cancel()
    rule_task.cancel()
    ai_task.cancel()

app = FastAPI(title="AI-SOC Platform", version="2.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

app.include_router(alerts_router)
app.include_router(stats_router)
app.include_router(response_router)
app.include_router(blocked_router)
app.include_router(cases_router)
app.include_router(rules_router)
app.include_router(auth_router)
app.include_router(hunting_router)
app.include_router(ai_router)
app.include_router(report_router)
app.include_router(threatintel_router)
app.include_router(settings_router)

@app.websocket("/ws")
async def ws_route(ws: WebSocket):
    await ws_endpoint(ws)

@app.get("/health")
async def health():
    return {"status": "ok"}

app.mount("/", StaticFiles(directory="../static", html=True), name="static")
