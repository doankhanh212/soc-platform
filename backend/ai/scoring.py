"""
Risk Scoring — tính điểm rủi ro tổng hợp.

Formula:
    risk_score = 0.4 × anomaly_score
               + 0.3 × normalized_severity
               + 0.3 × alert_frequency_normalized

Phân loại:
    0.0 → 0.3  →  LOW
    0.3 → 0.7  →  MEDIUM
    > 0.7       →  HIGH
"""


def _normalize(value: float, max_val: float) -> float:
    """Chuẩn hóa về [0, 1]."""
    if max_val <= 0:
        return 0.0
    return min(1.0, max(0.0, value / max_val))


def compute_risk_score(anomaly_score: float, features: dict) -> dict:
    """
    Tính risk_score và phân loại risk_level.

    Parameters
    ----------
    anomaly_score : float  – output từ model.compute_anomaly_score()
    features      : dict   – output từ extractor.extract_features()

    Returns
    -------
    {
        "risk_score":  float (0 → 1),
        "risk_level":  "LOW" | "MEDIUM" | "HIGH",
        "components": {
            "anomaly_score":                float,
            "normalized_severity":          float,
            "alert_frequency_normalized":   float,
        }
    }
    """
    # ── Chuẩn hóa severity ───────────────────────────────────────
    # Wazuh rule.level: 0-15  (15 = critical nhất)
    # Suricata alert.severity: 1 = critical, 2 = high, 3 = medium
    anomaly_score  = float(anomaly_score or 0)
    rule_level     = float(features.get("rule_level", 0) or 0)
    alert_severity = float(features.get("alert_severity", 0) or 0)

    # Chuyển Suricata severity ngược (1→12, 2→8, 3→4) để scale giống Wazuh
    suri_mapped = max(0, (4 - alert_severity) * 4) if alert_severity > 0 else 0
    severity_raw = max(rule_level, suri_mapped)
    normalized_severity = _normalize(severity_raw, 15)

    # ── Chuẩn hóa alert_frequency ────────────────────────────────
    # 50 alerts / 5 phút được xem là max
    alert_freq = float(features.get("alert_frequency", 0) or 0)
    alert_frequency_normalized = _normalize(alert_freq, 50)

    # ── Công thức risk_score ──────────────────────────────────────
    risk_score = (
        0.4 * anomaly_score
      + 0.3 * normalized_severity
      + 0.3 * alert_frequency_normalized
    )
    risk_score = round(min(1.0, max(0.0, risk_score)), 4)

    # ── Phân loại ─────────────────────────────────────────────────
    if risk_score > 0.7:
        risk_level = "HIGH"
    elif risk_score >= 0.3:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "components": {
            "anomaly_score":              round(anomaly_score, 4),
            "normalized_severity":        round(normalized_severity, 4),
            "alert_frequency_normalized": round(alert_frequency_normalized, 4),
        },
    }
