from fastapi import APIRouter, Query, HTTPException, Body
import re, subprocess
from services import (
    get_recent_alerts, get_suricata_alerts, get_ai_anomaly_alerts,
    get_dashboard_kpis, get_top_attacking_ips, get_top_ips_with_geo,
    get_alerts_over_time, get_mitre_stats, get_alert_severity_breakdown,
    get_top_rules, get_suricata_signature_stats,
)
from config import get_settings

cfg = get_settings()

alerts_router = APIRouter(prefix="/api/alerts", tags=["alerts"])
stats_router  = APIRouter(prefix="/api/stats",  tags=["stats"])
response_router = APIRouter(prefix="/api/response", tags=["response"])

# ── Alerts ────────────────────────────────────────────────────────

@alerts_router.get("/wazuh")
async def wazuh_alerts(
    size:      int = Query(100, ge=1, le=500),
    min_level: int = Query(1,   ge=1, le=15),
):
    return await get_recent_alerts(size=size, min_level=min_level)

@alerts_router.get("/suricata")
async def suricata_alerts(size: int = Query(100, ge=1, le=500)):
    return await get_suricata_alerts(size=size)

@alerts_router.get("/ai")
async def ai_alerts(size: int = Query(50, ge=1, le=200)):
    return await get_ai_anomaly_alerts(size=size)

# ── Stats ─────────────────────────────────────────────────────────

@stats_router.get("/kpis")
async def kpis():
    return await get_dashboard_kpis()

@stats_router.get("/top-ips")
async def top_ips(size: int = Query(10, ge=1, le=50)):
    return await get_top_attacking_ips(size=size)

@stats_router.get("/top-ips-geo")
async def top_ips_geo(size: int = Query(12, ge=1, le=30)):
    """Top IPs with real lat/lon from GeoLocation field — used by map."""
    return await get_top_ips_with_geo(size=size)

@stats_router.get("/timeline")
async def timeline(hours: int = Query(24, ge=1, le=168)):
    return await get_alerts_over_time(hours=hours)

@stats_router.get("/mitre")
async def mitre():
    return await get_mitre_stats()

@stats_router.get("/severity")
async def severity():
    return await get_alert_severity_breakdown()

@stats_router.get("/top-rules")
async def top_rules(size: int = Query(8, ge=1, le=20)):
    return await get_top_rules(size=size)

@stats_router.get("/suricata-sigs")
async def suricata_sigs():
    return await get_suricata_signature_stats()

# ── Response ──────────────────────────────────────────────────────

@response_router.post("/block-ip")
async def block_ip(ip: str = Query(...)):
    return await _block_ip_core(ip)


@response_router.post("")
async def response_action(payload: dict = Body(...)):
    """
    Compatibility endpoint:
      POST /api/response { "action": "block_ip", "ip": "x.x.x.x" }
    """
    action = str(payload.get("action", "")).strip().lower()
    ip = str(payload.get("ip", "")).strip()
    if action != "block_ip":
        raise HTTPException(400, "action không hỗ trợ")
    return await _block_ip_core(ip)


async def _block_ip_core(ip: str):
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        raise HTTPException(400, "IP không hợp lệ")
    try:
        result = subprocess.run(
            ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            raise HTTPException(500, f"iptables lỗi: {result.stderr}")

        # Ghi log vào OpenSearch nếu có
        try:
            import datetime
            from services.opensearch import _client
            async with _client() as c:
                await c.post(f"/{cfg.index_ai_anomaly}/_doc", json={
                    "@timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                    "src_ip": ip,
                    "action": "manual_block",
                    "blocked_by": "analyst",
                    "risk_score": 1.0,
                    "should_block": True,
                    "triggered_models": ["manual"],
                })
        except Exception:
            pass  # Log thất bại không ảnh hưởng việc block

        return {"status": "blocked", "ip": ip, "message": f"Đã chặn {ip} thành công"}
    except FileNotFoundError:
        raise HTTPException(500, "iptables không tìm thấy trên server")

@response_router.post("/unblock-ip")
async def unblock_ip(ip: str = Query(...)):
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        raise HTTPException(400, "IP không hợp lệ")
    try:
        r = subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            raise HTTPException(500, f"iptables lỗi: {r.stderr}")
        return {"status": "unblocked", "ip": ip, "message": f"Đã bỏ chặn {ip}"}
    except FileNotFoundError:
        raise HTTPException(500, "iptables không tìm thấy trên server")
