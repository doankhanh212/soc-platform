"""
AI Engine API — endpoints cho AI Detection System.

Endpoints:
  POST /api/ai/analyze   — phân tích một log event  → anomaly + risk + explanation
  GET  /api/ai/alerts    — danh sách alerts đã phân tích
  POST /api/ai/block     — chặn IP thủ công
  POST /api/ai/unblock   — bỏ chặn IP
  GET  /api/ai/stats     — thống kê AI engine
  GET  /api/ai/blocked   — danh sách IP đang bị chặn
  GET  /api/ai/block-log — lịch sử block/unblock
  POST /api/ai/test      — chạy sample data để kiểm tra pipeline
"""
from fastapi import APIRouter, Query, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel

from services.pipeline import (
    analyze_single_event,
    get_analyzed_alerts,
    get_ai_stats,
)
from response.firewall import (
    block_ip,
    unblock_ip,
    get_blocked_list,
    get_block_log,
)

router = APIRouter(prefix="/api/ai", tags=["ai-engine"])


# ── Schema ────────────────────────────────────────────────────────

class LogEvent(BaseModel):
    """Raw log event — accepts any Wazuh/Suricata field."""
    class Config:
        extra = "allow"


# ══════════════════════════════════════════════════════════════════
# POST /analyze — phân tích một log event
# ══════════════════════════════════════════════════════════════════

@router.post("/analyze")
async def analyze(event: LogEvent):
    """
    Phân tích một log event theo pipeline:
    raw log → features → AI detection → risk scoring → explanation

    Input:  raw Wazuh/Suricata log
    Output: anomaly_score, risk_score, risk_level, explanation
    """
    result = await run_in_threadpool(analyze_single_event, event.model_dump())
    return result


# ══════════════════════════════════════════════════════════════════
# GET /alerts — danh sách alerts đã phân tích
# ══════════════════════════════════════════════════════════════════

@router.get("/alerts")
async def alerts(limit: int = Query(50, ge=1, le=500)):
    """Trả về danh sách alerts đã được AI engine phân tích."""
    return get_analyzed_alerts(limit=limit)


# ══════════════════════════════════════════════════════════════════
# POST /block — chặn IP thủ công
# ══════════════════════════════════════════════════════════════════

@router.post("/block")
async def block(ip: str = Query(...)):
    """Chặn IP thủ công qua iptables."""
    result = await run_in_threadpool(block_ip, ip, "Analyst manual block via AI API")
    if result["status"] == "error":
        raise HTTPException(400, result["message"])
    return result


# ══════════════════════════════════════════════════════════════════
# POST /unblock — bỏ chặn IP
# ══════════════════════════════════════════════════════════════════

@router.post("/unblock")
async def unblock(ip: str = Query(...)):
    """Bỏ chặn IP."""
    result = await run_in_threadpool(unblock_ip, ip)
    if result["status"] == "error":
        raise HTTPException(400, result["message"])
    return result


# ══════════════════════════════════════════════════════════════════
# GET /stats — thống kê AI engine
# ══════════════════════════════════════════════════════════════════

@router.get("/stats")
async def stats():
    """
    Thống kê tổng hợp:
      • Tổng số event đã phân tích
      • Tổng số anomaly (score > 0.5)
      • Số IP nguy hiểm (HIGH)
      • Số IP đang bị chặn
      • Top 10 IP theo risk_score
    """
    return get_ai_stats()


# ══════════════════════════════════════════════════════════════════
# GET /blocked — danh sách IP đang bị chặn
# ══════════════════════════════════════════════════════════════════

@router.get("/blocked")
async def blocked_ips():
    """Trả về danh sách IP đang bị chặn trong iptables."""
    return {"blocked_ips": get_blocked_list()}


# ══════════════════════════════════════════════════════════════════
# GET /block-log — lịch sử block/unblock
# ══════════════════════════════════════════════════════════════════

@router.get("/block-log")
async def block_log_endpoint(limit: int = Query(50, ge=1, le=500)):
    """Đọc file log ghi lại lịch sử block/unblock IP."""
    return {"log": get_block_log(limit=limit)}


# ══════════════════════════════════════════════════════════════════
# POST /test — chạy sample data
# ══════════════════════════════════════════════════════════════════

@router.post("/test")
async def test_pipeline():
    """
    Chạy pipeline với 3 sample events để kiểm tra toàn bộ hệ thống.
    Không ảnh hưởng firewall (không auto-block trong test).
    """
    from ai.extractor import SAMPLE_EVENTS

    results = []
    for ev in SAMPLE_EVENTS:
        r = await run_in_threadpool(analyze_single_event, ev)
        results.append({
            "src_ip":        r["src_ip"],
            "anomaly_score": r["anomaly_score"],
            "risk_score":    r["risk_score"],
            "risk_level":    r["risk_level"],
            "summary":       r["explanation"]["summary"],
            "reasons":       r["explanation"]["reasons"],
        })
    return {"message": "Pipeline test completed", "results": results}
