"""
AI Pipeline — luồng xử lý chính:

    raw log → feature extraction → anomaly detection → risk scoring
            → explainable AI → auto response

Hai chế độ:
  • Single event  — POST /api/ai/analyze (real-time)
  • Batch          — background loop gọi từ runner.py
"""
import logging
import time
import asyncio
from datetime import datetime
from pathlib import Path

from ai.extractor import extract_features, extract_features_batch
from ai.model import compute_anomaly_score
from ai.scoring import compute_risk_score
from ai.explain import explain_risk
from config import get_settings
from services.opensearch import index_ai_anomaly_alert

log = logging.getLogger("ai_pipeline")
cfg = get_settings()

# ── Lịch sử phân tích (in-memory ring buffer) ────────────────────
_history: list[dict] = []
_MAX_HISTORY = 5000
AUTO_BLOCK_BASE_THRESHOLD = 0.70
AUTO_BLOCK_COMBINED_RISK = 0.65
AUTO_BLOCK_COMBINED_ALERTS_1H = 1000
SOC_BLOCK_LOG = Path("/var/log/soc_blocks.log")


def _derive_triggered_models(model_scores: dict, threshold: float = 0.5) -> list[str]:
    return [
        name for name, score in model_scores.items()
        if float(score or 0) >= threshold
    ]


def _estimate_alert_count_1h(features: dict) -> int:
    """Chuan hoa tan suat canh bao ve moc 1 gio de dung cho dieu kien auto-block."""
    if not isinstance(features, dict):
        return 0

    candidates: list[int] = []

    raw_alerts_1h = features.get("alerts_1h")
    if raw_alerts_1h is not None:
        try:
            candidates.append(max(0, int(float(raw_alerts_1h))))
        except (TypeError, ValueError):
            pass

    # single-event extractor: alert_frequency trong 5 phut
    raw_alert_frequency = features.get("alert_frequency")
    try:
        alert_frequency = float(raw_alert_frequency or 0.0)
        if alert_frequency > 0:
            candidates.append(max(0, int(alert_frequency * 12)))
    except (TypeError, ValueError):
        pass

    # batch extractor: connection_count trong 15 phut
    raw_connection_count = features.get("connection_count")
    try:
        connection_count = float(raw_connection_count or 0.0)
        if connection_count > 0:
            candidates.append(max(0, int(connection_count * 4)))
    except (TypeError, ValueError):
        pass

    # request_rate la so canh bao/phut
    raw_request_rate = features.get("request_rate")
    try:
        request_rate = float(raw_request_rate or 0.0)
        if request_rate > 0:
            candidates.append(max(0, int(request_rate * 60)))
    except (TypeError, ValueError):
        pass

    return max(candidates, default=0)


def _should_auto_block(risk_score: float, features: dict) -> bool:
    """Dieu kien block:
    - risk >= 0.70, hoac
    - risk >= 0.65 va so canh bao 1h >= 1000
    """
    alerts_1h = _estimate_alert_count_1h(features)
    return (
        float(risk_score or 0.0) >= AUTO_BLOCK_BASE_THRESHOLD
        or (
            float(risk_score or 0.0) >= AUTO_BLOCK_COMBINED_RISK
            and alerts_1h >= AUTO_BLOCK_COMBINED_ALERTS_1H
        )
    )


def _append_soc_block_log(ip: str, risk_score: float, reason: str) -> None:
    """Best-effort log cho moi truong production Linux."""
    try:
        with SOC_BLOCK_LOG.open("a", encoding="utf-8") as f:
            f.write(f"{datetime.now().isoformat()} BLOCKED {ip} score={risk_score:.3f} reason={reason}\n")
    except Exception:
        # Khong chan luong chinh khi khong co quyen ghi /var/log
        pass


async def auto_block_ip(ip: str, risk_score: float, reason: str) -> bool:
    """Goi firewall block + log + broadcast websocket event."""
    from response.firewall import block_ip

    try:
        block_result = await asyncio.to_thread(block_ip, ip, reason)
    except Exception as e:
        log.error("Auto block failed for %s: %s", ip, e)
        return False

    status = str(block_result.get("status", "")).strip().lower()
    if status not in {"blocked", "already_blocked"}:
        log.error("Auto block failed for %s: %s", ip, block_result.get("message", "unknown error"))
        return False

    _append_soc_block_log(ip=ip, risk_score=risk_score, reason=reason)
    log.info("AUTO BLOCKED: %s score=%.3f reason=%s", ip, risk_score, reason)

    payload = {
        "type": "ip_blocked",
        "data": {
            "ip": ip,
            "risk_score": float(risk_score or 0.0),
            "reason": reason,
            "auto": True,
        },
    }
    try:
        from routers.ws import manager
        await manager.broadcast(payload)
    except Exception as e:
        log.warning("WS broadcast failed for auto block %s: %s", ip, e)

    return True


# ══════════════════════════════════════════════════════════════════
# SINGLE EVENT (real-time, dùng cho API)
# ══════════════════════════════════════════════════════════════════

def analyze_single_event(event: dict) -> dict:
    """
    Pipeline đầy đủ cho một log event.

    Input:  raw Wazuh / Suricata log (dict)
    Output: {
        src_ip, timestamp,
        anomaly_score, risk_score, risk_level,
        explanation, features, model_scores, risk_components
    }
    """
    # 1. Feature Extraction
    features = extract_features(event)

    if not features.get("src_ip"):
        explanation = {
            "summary": "Sự kiện thiếu địa chỉ IP nguồn nên chưa thể phân tích chính xác",
            "reasons": ["Thiếu trường src_ip trong log đầu vào"],
            "risk_level": "LOW",
            "risk_score": 0.0,
            "recommendation": "Chuẩn hóa nguồn log trước khi đưa vào AI Engine",
        }
        result = {
            "src_ip":          "",
            "timestamp":       features["timestamp"] or time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "anomaly_score":   0.0,
            "risk_score":      0.0,
            "risk_level":      "LOW",
            "explanation":     explanation,
            "features":        features,
            "model_scores":    {"isolation_forest": 0.0, "ewma": 0.0, "cusum": 0.0},
            "risk_components": {
                "anomaly_score": 0.0,
                "normalized_severity": 0.0,
                "alert_frequency_normalized": 0.0,
            },
        }
        _history.append(result)
        if len(_history) > _MAX_HISTORY:
            _history.pop(0)
        return result

    # 2. Anomaly Detection (Isolation Forest + EWMA + CUSUM)
    anomaly_result = compute_anomaly_score(features)

    # 3. Risk Scoring
    risk_result = compute_risk_score(anomaly_result["anomaly_score"], features)

    # 4. Explainable AI
    explanation = explain_risk(event, features, anomaly_result, risk_result)

    # 5. Tổng hợp kết quả
    result = {
        "src_ip":          features["src_ip"],
        "timestamp":       features["timestamp"] or time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "anomaly_score":   anomaly_result["anomaly_score"],
        "risk_score":      risk_result["risk_score"],
        "risk_level":      risk_result["risk_level"],
        "triggered_models": _derive_triggered_models(anomaly_result["model_scores"]),
        "should_block":    _should_auto_block(risk_result["risk_score"], features),
        "explanation":     explanation,
        "features":        features,
        "model_scores":    anomaly_result["model_scores"],
        "risk_components": risk_result["components"],
    }

    # Lưu lịch sử
    _history.append(result)
    if len(_history) > _MAX_HISTORY:
        _history.pop(0)

    log.info(
        "Pipeline: ip=%s risk=%.3f level=%s",
        features["src_ip"], risk_result["risk_score"], risk_result["risk_level"],
    )
    return result


# ══════════════════════════════════════════════════════════════════
# BATCH (background, dùng cho runner loop)
# ══════════════════════════════════════════════════════════════════

async def analyze_batch() -> list[dict]:
    """
    Lấy data từ OpenSearch → phân tích tất cả IPs trong 15 phút.
    Tự động block nếu risk_level = HIGH và config bật auto-block.
    """
    from response.firewall import is_blocked

    features_list = await extract_features_batch(window_minutes=15)
    if not features_list:
        return []

    results: list[dict] = []

    for features in features_list:
        ip = features["src_ip"]

        # Anomaly detection
        anomaly_result = compute_anomaly_score(features)

        # Risk scoring
        risk_result = compute_risk_score(anomaly_result["anomaly_score"], features)

        # Bỏ qua risk thấp
        if risk_result["risk_score"] < 0.3:
            continue

        # Explanation
        explanation = explain_risk({}, features, anomaly_result, risk_result)
        alerts_1h = _estimate_alert_count_1h(features)
        should_block = _should_auto_block(risk_result["risk_score"], features)

        result = {
            "src_ip":        ip,
            "timestamp":     time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "anomaly_score": anomaly_result["anomaly_score"],
            "risk_score":    risk_result["risk_score"],
            "risk_level":    risk_result["risk_level"],
            "triggered_models": _derive_triggered_models(anomaly_result["model_scores"]),
            "should_block":  should_block,
            "explanation":   explanation,
            "features":      features,
            "alerts_1h":     alerts_1h,
            "model_scores":  anomaly_result["model_scores"],
            "risk_components": risk_result["components"],
            "da_chan": False,
            "auto_block_reason": "",
        }

        # Auto-response nếu HIGH + config bật
        if cfg.ai_block_auto and should_block:
            if is_blocked(ip):
                result["da_chan"] = True
                result["auto_block_reason"] = "IP da nam trong danh sach chan"
            else:
                reason = (
                    f"AI auto-block: risk_score={risk_result['risk_score']:.3f}, "
                    f"alerts_1h={alerts_1h}, models={result['triggered_models']}"
                )
                blocked = await auto_block_ip(
                    ip=ip,
                    risk_score=float(risk_result["risk_score"] or 0.0),
                    reason=reason,
                )
                result["da_chan"] = bool(blocked)
                if blocked:
                    result["auto_block_reason"] = reason

        results.append(result)
        await index_ai_anomaly_alert(result)

        # Lưu lịch sử
        _history.append(result)

    # Trim
    while len(_history) > _MAX_HISTORY:
        _history.pop(0)

    return results


# ══════════════════════════════════════════════════════════════════
# QUERY — dùng cho GET endpoints
# ══════════════════════════════════════════════════════════════════

def get_analyzed_alerts(limit: int = 0) -> list[dict]:
    """Trả về danh sách alerts đã phân tích (mới nhất trước). limit=0 trả tất cả."""
    if limit <= 0:
        return list(reversed(_history))
    return list(reversed(_history[-limit:]))


def get_ai_stats() -> dict:
    """
    Thống kê AI engine:
      • Tổng số IP nguy hiểm (HIGH)
      • Tổng số anomaly (anomaly_score > 0.5)
      • Top IP theo risk_score
      • Số IP đang bị block
    """
    from response.firewall import get_blocked_list

    high_ips:       set[str]        = set()
    total_anomalies                 = 0
    ip_scores:      dict[str, float] = {}

    for a in _history:
        if a.get("risk_level") == "HIGH":
            high_ips.add(a["src_ip"])
        if a.get("anomaly_score", 0) > 0.5:
            total_anomalies += 1
        ip_scores[a["src_ip"]] = max(
            ip_scores.get(a["src_ip"], 0), a.get("risk_score", 0)
        )

    top_ips = sorted(
        [{"ip": ip, "risk_score": round(sc, 4)} for ip, sc in ip_scores.items()],
        key=lambda x: x["risk_score"],
        reverse=True,
    )[:10]

    return {
        "total_analyzed":  len(_history),
        "total_anomalies": total_anomalies,
        "high_risk_ips":   len(high_ips),
        "blocked_ips":     len(get_blocked_list()),
        "top_ips":         top_ips,
    }
