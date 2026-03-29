from datetime import datetime
from pathlib import Path
import ipaddress
import subprocess

from fastapi import APIRouter, Query, Request
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
async def ai_alerts(size: int = Query(50, ge=1, le=200)):
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


def _append_block_log(ip: str, reason: str) -> None:
    try:
        with Path("/var/log/soc_blocks.log").open("a", encoding="utf-8") as f:
            f.write(f"{datetime.now().isoformat()} BLOCKED {ip} reason={reason}\n")
    except Exception:
        # Không để lỗi ghi log chặn luồng phản ứng.
        pass


async def _block_ip_core(ip: str, reason: str = "Manual block"):
    if not _is_valid_ipv4(ip):
        return JSONResponse({"success": False, "message": "IP không hợp lệ"}, status_code=400)

    try:
        base_cmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
        result = subprocess.run(
            base_cmd,
            capture_output=True,
            text=True,
            timeout=5,
        )
        stderr_text = (result.stderr or "").strip()
        if result.returncode != 0 and (
            "Permission denied" in stderr_text
            or "Operation not permitted" in stderr_text
        ):
            # Cho phép fallback dùng sudo khi service không chạy bằng root
            # và đã được cấp NOPASSWD trong sudoers.
            result = subprocess.run(
                ["sudo", *base_cmd],
                capture_output=True,
                text=True,
                timeout=5,
            )
            stderr_text = (result.stderr or "").strip()

        if result.returncode != 0:
            return JSONResponse(
                {"success": False, "message": f"iptables lỗi: {stderr_text or 'unknown error'}"},
                status_code=500,
            )

        _append_block_log(ip=ip, reason=reason)
        return {
            "success": True,
            "status": "blocked",
            "ip": ip,
            "message": f"Đã chặn IP {ip} qua iptables",
        }
    except subprocess.TimeoutExpired:
        return JSONResponse({"success": False, "message": "Timeout khi chạy iptables"}, status_code=500)
    except FileNotFoundError:
        return JSONResponse({"success": False, "message": "iptables không tìm thấy trên server"}, status_code=500)
    except Exception as e:
        return JSONResponse({"success": False, "message": str(e)}, status_code=500)


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
async def unblock_ip(ip: str = Query(...)):
    if not _is_valid_ipv4(ip):
        return JSONResponse({"success": False, "message": "IP không hợp lệ"}, status_code=400)
    try:
        base_cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        result = subprocess.run(
            base_cmd,
            capture_output=True,
            text=True,
            timeout=5,
        )
        stderr_text = (result.stderr or "").strip()
        if result.returncode != 0 and (
            "Permission denied" in stderr_text
            or "Operation not permitted" in stderr_text
        ):
            result = subprocess.run(
                ["sudo", *base_cmd],
                capture_output=True,
                text=True,
                timeout=5,
            )
            stderr_text = (result.stderr or "").strip()

        if result.returncode != 0:
            return JSONResponse(
                {"success": False, "message": f"iptables lỗi: {stderr_text or 'unknown error'}"},
                status_code=500,
            )
        return {"success": True, "status": "unblocked", "ip": ip, "message": f"Đã bỏ chặn {ip}"}
    except subprocess.TimeoutExpired:
        return JSONResponse({"success": False, "message": "Timeout khi chạy iptables"}, status_code=500)
    except FileNotFoundError:
        return JSONResponse({"success": False, "message": "iptables không tìm thấy trên server"}, status_code=500)
    except Exception as e:
        return JSONResponse({"success": False, "message": str(e)}, status_code=500)
