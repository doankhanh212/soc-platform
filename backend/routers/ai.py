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
from datetime import datetime, timezone
from collections import defaultdict

from services.pipeline import (
    analyze_single_event,
    get_analyzed_alerts,
    get_ai_stats,
)
from services import get_recent_alerts, get_ai_anomaly_alerts
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


@router.get("/models/status")
async def models_status():
    """
    Trả trạng thái 4 lớp giám sát AI cho UI dashboard.
    """
    try:
        alerts = await get_ai_anomaly_alerts(size=500)
    except Exception:
        alerts = []

    threshold = 0.6
    model_defs = ["IsolationForest", "EWMA", "CUSUM", "Entropy"]
    scores: dict[str, list[float]] = defaultdict(list)
    detections: dict[str, int] = defaultdict(int)

    for item in alerts:
        model_scores = item.get("model_scores", {}) or {}
        for model in model_defs:
            raw = model_scores.get(model)
            if raw is None:
                continue
            val = float(raw or 0)
            scores[model].append(val)
            if val >= threshold:
                detections[model] += 1

    rows = []
    for model in model_defs:
        values = scores.get(model, [])
        avg_score = (sum(values) / len(values)) if values else 0.0
        rows.append({
            "model": model,
            "running": True,
            "score": round(avg_score, 3),
            "threshold": threshold,
            "detections_today": int(detections.get(model, 0)),
        })

    return {
        "threshold": threshold,
        "models": rows,
        "updated_at": datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z"),
    }


@router.get("/anomalies")
async def get_anomalies(
    limit: int = Query(500, ge=1, le=5000),
    sort: str = Query("risk_desc"),
):
    """
    Danh sách anomalies đã enrich cho Explainable panel.
    """
    try:
        fetch_size = max(int(limit or 0), 800)
        ai_alerts = await get_ai_anomaly_alerts(size=fetch_size)
    except Exception:
        ai_alerts = []

    try:
        wazuh_alerts = await get_recent_alerts(size=1500, min_level=1)
    except Exception:
        wazuh_alerts = []

    if not ai_alerts:
        return []

    def _risk_value(item: dict) -> float:
        raw = item.get("risk_score", 0.0)
        try:
            return float(raw or 0.0)
        except Exception:
            return 0.0

    risk_sorted = sorted(ai_alerts, key=_risk_value, reverse=True)
    max_rank = max(len(risk_sorted), 1)
    percentiles = {id(item): 100 - int((idx / max_rank) * 100) for idx, item in enumerate(risk_sorted)}

    grouped_wazuh: dict[str, list[dict]] = defaultdict(list)
    for row in wazuh_alerts:
        src_ip = str(row.get("data", {}).get("src_ip") or "").strip()
        if src_ip:
            grouped_wazuh[src_ip].append(row)

    out = []
    for item in risk_sorted:
        ip = str(item.get("src_ip") or "").strip()
        if not ip:
            continue

        related = grouped_wazuh.get(ip, [])
        last_hour_count = 0
        unique_ports = set()
        privilege_escalation = 0
        file_changed = 0
        now = datetime.now(tz=timezone.utc)
        latest_geo_country = "Unknown"

        for alert in related:
            data = alert.get("data", {}) or {}
            rule = alert.get("rule", {}) or {}
            ts = _to_datetime(alert.get("@timestamp"))
            if (now - ts).total_seconds() <= 3600:
                last_hour_count += 1
            dest_port = data.get("dest_port")
            if dest_port is not None:
                unique_ports.add(str(dest_port))

            desc = str(rule.get("description", "")).lower()
            groups = [str(g).lower() for g in (rule.get("groups") or [])]
            if "privilege" in desc or "escalat" in desc or "privilege_escalation" in groups:
                privilege_escalation += 1
            if "integrity" in desc or "file" in desc or "syscheck" in groups:
                file_changed += 1

            if latest_geo_country == "Unknown":
                latest_geo_country = str(alert.get("GeoLocation", {}).get("country_name") or "Unknown")

        model_scores = item.get("model_scores", {}) or {}
        if_score = float(model_scores.get("IsolationForest", 0.0) or 0.0)
        cusum_score = float(model_scores.get("CUSUM", 0.0) or 0.0) * 10
        total_count = len(related)
        risk = _risk_value(item)

        out.append({
            "ip": ip,
            "diem_rui_ro": round(risk, 3),
            "quoc_gia": latest_geo_country,
            "asn": "AS-Unknown",
            "mo_hinh_kich_hoat": item.get("triggered_models", []) or [],
            "da_chan": bool(item.get("da_chan", False)),
            "auto_block_reason": str(item.get("auto_block_reason", "") or ""),
            "ly_do": {
                "tong_canh_bao": total_count,
                "so_canh_bao_1h": max(last_hour_count, int(item.get("alerts_1h", 0) or 0)),
                "unique_dest_ports": len(unique_ports),
                "leo_thang_quyen": privilege_escalation,
                "file_bi_sua": file_changed,
                "if_percentile": percentiles.get(id(item), 50),
                "if_score": round(if_score, 3),
                "cusum_s": round(cusum_score, 2),
            },
        })

    if sort == "risk_desc":
        out.sort(key=lambda x: float(x.get("diem_rui_ro", 0)), reverse=True)

    return out[:limit]


# ══════════════════════════════════════════════════════════════════
# GET /blocked — danh sách IP đang bị chặn
# ══════════════════════════════════════════════════════════════════

@router.get("/blocked")
async def blocked_ips():
    """Trả về danh sách IP đang bị chặn trong iptables."""
    return {"blocked_ips": get_blocked_list()}


def _to_datetime(value: str | None) -> datetime:
    if not value:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return datetime.fromtimestamp(0, tz=timezone.utc)


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
