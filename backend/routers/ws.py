import asyncio, json, logging
from fastapi import WebSocket, WebSocketDisconnect
from services import (
    get_dashboard_kpis, get_recent_alerts, get_suricata_alerts,
    get_ai_anomaly_alerts, get_top_attacking_ips,
    get_top_ips_with_geo, get_alerts_over_time,
    get_top_rules, get_suricata_signature_stats,
)
from services.cases import case_stats
from config import get_settings

log = logging.getLogger(__name__)
cfg = get_settings()


class ConnectionManager:
    def __init__(self):
        self._clients: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._clients.append(ws)

    def disconnect(self, ws: WebSocket):
        self._clients.remove(ws) if ws in self._clients else None

    async def broadcast(self, payload: dict):
        dead, data = [], json.dumps(payload)
        for ws in self._clients:
            try: await ws.send_text(data)
            except: dead.append(ws)
        for ws in dead: self.disconnect(ws)

    @property
    def count(self): return len(self._clients)


manager = ConnectionManager()


async def ws_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        await _push_snapshot()
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)


async def _push_snapshot():
    try:
        kpis, alerts, suri, ai, top_ips, geo_ips, tl, rules, sigs, cstats = await asyncio.gather(
            get_dashboard_kpis(),
            get_recent_alerts(size=50, min_level=3),
            get_suricata_alerts(size=50),
            get_ai_anomaly_alerts(size=20),
            get_top_attacking_ips(size=10),
            get_top_ips_with_geo(size=12),
            get_alerts_over_time(hours=24),
            get_top_rules(size=8),
            get_suricata_signature_stats(),
            asyncio.to_thread(case_stats),
            return_exceptions=True,
        )
        # Replace exceptions with empty defaults
        def safe(v, default): return default if isinstance(v, Exception) else v

        await manager.broadcast({
            "type":             "snapshot",
            "kpis":             safe(kpis,    {}),
            "recent_alerts":    safe(alerts,  []),
            "suricata_alerts":  safe(suri,    []),
            "ai_alerts":        safe(ai,      []),
            "top_ips":          safe(top_ips, []),
            "geo_ips":          safe(geo_ips, []),
            "timeline":         safe(tl,      []),
            "top_rules":        safe(rules,   []),
            "suricata_sigs":    safe(sigs,    []),
            "case_stats":       safe(cstats,  {}),
        })
    except Exception as e:
        log.error("WS snapshot error: %s", e)
        await manager.broadcast({"type": "error", "message": str(e)})


async def broadcast_loop():
    log.info("WS loop started (interval=%ds)", cfg.ws_broadcast_interval)
    while True:
        await asyncio.sleep(cfg.ws_broadcast_interval)
        if manager.count > 0:
            await _push_snapshot()
