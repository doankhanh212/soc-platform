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

from ai.extractor import extract_features, extract_features_batch
from ai.model import compute_anomaly_score
from ai.scoring import compute_risk_score
from ai.explain import explain_risk
from config import get_settings

log = logging.getLogger("ai_pipeline")
cfg = get_settings()

# ── Lịch sử phân tích (in-memory ring buffer) ────────────────────
_history: list[dict] = []
_MAX_HISTORY = 500


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
    from response.firewall import block_ip, is_blocked

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

        result = {
            "src_ip":        ip,
            "timestamp":     time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "anomaly_score": anomaly_result["anomaly_score"],
            "risk_score":    risk_result["risk_score"],
            "risk_level":    risk_result["risk_level"],
            "explanation":   explanation,
            "features":      features,
            "model_scores":  anomaly_result["model_scores"],
            "risk_components": risk_result["components"],
        }
        results.append(result)

        # Auto-response nếu HIGH + config bật
        if (risk_result["risk_level"] == "HIGH"
                and cfg.ai_block_auto
                and not is_blocked(ip)):
            reason = (f"AI auto-block: risk_score={risk_result['risk_score']:.3f}, "
                      f"models={list(anomaly_result['model_scores'].keys())}")
            block_ip(ip, reason)

        # Lưu lịch sử
        _history.append(result)

    # Trim
    while len(_history) > _MAX_HISTORY:
        _history.pop(0)

    return results


# ══════════════════════════════════════════════════════════════════
# QUERY — dùng cho GET endpoints
# ══════════════════════════════════════════════════════════════════

def get_analyzed_alerts(limit: int = 100) -> list[dict]:
    """Trả về danh sách alerts đã phân tích (mới nhất trước)."""
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
