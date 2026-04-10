from datetime import datetime
from pathlib import Path
import ipaddress

from fastapi import APIRouter, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from services import (
    get_recent_alerts,
    get_suricata_alerts,
    get_ai_anomaly_alerts,
    get_dashboard_kpis,
    get_top_attacking_ips,
    get_top_ips_with_geo,
    get_alerts_over_time,
    get_mitre_stats,
    get_alert_severity_breakdown,
    get_top_rules,
    get_suricata_signature_stats,
)
from response.firewall import (
    block_ip as fw_block, unblock_ip as fw_unblock,
    get_blocked_list, get_block_log,
)

alerts_router = APIRouter(prefix="/api/alerts", tags=["alerts"])
stats_router = APIRouter(prefix="/api/stats", tags=["stats"])
response_router = APIRouter(prefix="/api/response", tags=["response"])


# Alerts
@alerts_router.get("/wazuh")
async def wazuh_alerts(
    size: int = Query(100, ge=1, le=500),
    min_level: int = Query(1, ge=1, le=15),
):
    return await get_recent_alerts(size=size, min_level=min_level)


@alerts_router.get("/suricata")
async def suricata_alerts(size: int = Query(100, ge=1, le=500)):
    return await get_suricata_alerts(size=size)


@alerts_router.get("/ai")
async def ai_alerts(size: int = Query(5000, ge=1)):
    return await get_ai_anomaly_alerts(size=size)


# Stats
@stats_router.get("/kpis")
async def kpis():
    return await get_dashboard_kpis()


@stats_router.get("/top-ips")
async def top_ips(size: int = Query(10, ge=1, le=50)):
    return await get_top_attacking_ips(size=size)


@stats_router.get("/top-ips-geo")
async def top_ips_geo(size: int = Query(12, ge=1, le=30)):
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


def _is_valid_ipv4(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).version == 4
    except Exception:
        return False


async def _block_ip_core(ip: str, reason: str = "Manual block"):
    if not _is_valid_ipv4(ip):
        return JSONResponse({"success": False, "message": "IP không hợp lệ"}, status_code=400)

    result = await run_in_threadpool(fw_block, ip, reason)

    if result["status"] in ("blocked", "already_blocked"):
        return {
            "success": True,
            "status": result["status"],
            "ip": ip,
            "message": result.get("message", ""),
            "local": result.get("local"),
            "suricata_vps": result.get("suricata_vps"),
            "agent_vps": result.get("agent_vps"),
        }
    return JSONResponse({"success": False, "message": result.get("message", "Lỗi block IP")}, status_code=500)


# Response
@response_router.post("")
async def response_action(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"success": False, "message": "Body JSON không hợp lệ"}, status_code=400)

    action = str(body.get("action", "")).strip().lower()
    ip = str(body.get("ip", "")).strip()
    reason = str(body.get("reason", "Manual block")).strip() or "Manual block"

    if not ip:
        return JSONResponse({"success": False, "message": "Thiếu IP"}, status_code=400)

    if action == "block_ip":
        return await _block_ip_core(ip=ip, reason=reason)

    return JSONResponse({"success": False, "message": f"Action không hỗ trợ: {action or 'null'}"}, status_code=400)


@response_router.post("/block-ip")
async def block_ip(ip: str = Query(...), reason: str = Query("Manual block")):
    return await _block_ip_core(ip=ip, reason=reason)


@response_router.post("/unblock-ip")
async def unblock_ip_route(ip: str = Query(...)):
    if not _is_valid_ipv4(ip):
        return JSONResponse({"success": False, "message": "IP không hợp lệ"}, status_code=400)

    result = await run_in_threadpool(fw_unblock, ip)
    if result["status"] in ("unblocked", "already_unblocked"):
        return {
            "success": True,
            "status": result["status"],
            "ip": ip,
            "message": result.get("message", ""),
            "local": result.get("local"),
            "suricata_vps": result.get("suricata_vps"),
            "agent_vps": result.get("agent_vps"),
        }
    return JSONResponse({"success": False, "message": result.get("message", "Lỗi unblock")}, status_code=500)


# ══════════════════════════════════════════════════════════════════
# GET /api/stats/today — 3 counter cho Dashboard
# ══════════════════════════════════════════════════════════════════

@stats_router.get("/today")
async def stats_today():
    """Đã phân loại, Dừng mối đe dọa, Báo động nhầm."""
    from services.pipeline import get_analyzed_alerts

    alerts      = get_analyzed_alerts(limit=500)
    classified  = len([a for a in alerts if a.get("risk_level") in ("HIGH", "MEDIUM", "LOW")])
    threats     = len(get_blocked_list())
    false_pos   = len([a for a in alerts
                       if a.get("risk_level") == "LOW"
                       and float(a.get("anomaly_score", 0) or 0) < 0.2])
    return {
        "classified":      classified,
        "threats_stopped": threats,
        "false_positives": false_pos,
    }


# ══════════════════════════════════════════════════════════════════
# /api/blocked-ips/* — CRUD danh sách IP bị chặn
# ══════════════════════════════════════════════════════════════════

blocked_router = APIRouter(prefix="/api/blocked-ips", tags=["blocked"])


@blocked_router.get("/count")
async def blocked_count():
    return {"count": len(get_blocked_list())}


@blocked_router.get("")
async def blocked_list_endpoint():
    ips = get_blocked_list()
    log_entries = get_block_log(limit=500)

    # Ghép IP + thông tin từ log (thời gian, lý do)
    # Format thực tế: "[2025-01-01 12:00:00] BLOCK | IP: 1.2.3.4 | Lý do: reason"
    ip_info: dict[str, dict] = {}
    for entry in log_entries:
        line = str(entry)
        try:
            # Parse "[ts] ACTION | IP: x.x.x.x | Lý do: reason"
            ts_end = line.index("]")
            ts = line[1:ts_end]  # bỏ "[" và "]"
            rest = line[ts_end + 2:]  # bỏ "] "
            segments = [s.strip() for s in rest.split("|")]
            action = segments[0] if len(segments) > 0 else ""
            ip_part = segments[1] if len(segments) > 1 else ""
            reason_part = segments[2] if len(segments) > 2 else ""
            # "IP: 1.2.3.4" → "1.2.3.4"
            ip_val = ip_part.replace("IP:", "").strip()
            # "Lý do: xyz" → "xyz"
            reason_val = reason_part.replace("Lý do:", "").strip()
            if ip_val and ip_val not in ip_info:
                ip_info[ip_val] = {"blocked_at": ts, "reason": reason_val, "action": action}
        except (ValueError, IndexError):
            continue

    items = []
    for ip in ips:
        info = ip_info.get(ip, {})
        items.append({
            "ip": ip,
            "blocked_at": info.get("blocked_at", ""),
            "reason": info.get("reason", ""),
        })

    return {"ips": items, "count": len(ips)}


@blocked_router.post("")
async def block_ip_endpoint(
    ip:       str = Query(...),
    reason:   str = Query("Manual block"),
    alert_id: str = Query(None),
):
    return await run_in_threadpool(fw_block, ip, reason)


@blocked_router.delete("/{ip}")
async def unblock_ip_endpoint(ip: str):
    return await run_in_threadpool(fw_unblock, ip)
