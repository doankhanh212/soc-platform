"""
Explainable AI — giải thích rủi ro bằng ngôn ngữ đơn giản.

Không dùng thuật ngữ AI phức tạp — viết cho analyst / quản lý hiểu.
"""


def explain_risk(
    event: dict,
    features: dict,
    anomaly_result: dict,
    risk_result: dict,
) -> dict:
    """
    Sinh lời giải thích rủi ro cho SOC analyst.

    Returns
    -------
    {
        "summary":        str,
        "reasons":        list[str],
        "risk_level":     str,
        "recommendation": str,
    }
    """
    risk_level = risk_result["risk_level"]
    risk_score = risk_result["risk_score"]
    src_ip     = features.get("src_ip", "N/A")

    # ── Summary ───────────────────────────────────────────────────
    summary_map = {
        "HIGH":   f"IP {src_ip} có hành vi rất bất thường, khả năng cao đang tấn công",
        "MEDIUM": f"IP {src_ip} có một số dấu hiệu đáng ngờ, cần theo dõi thêm",
        "LOW":    f"IP {src_ip} hoạt động trong ngưỡng bình thường, rủi ro thấp",
    }
    summary = summary_map.get(risk_level, summary_map["LOW"])

    # ── Reasons (thu thập từ features + model scores) ─────────────
    reasons: list[str] = []

    conn = features.get("connection_count", 0)
    if conn > 30:
        reasons.append(f"Tần suất kết nối cao bất thường ({conn} kết nối trong 5 phút)")

    port_var = features.get("port_variance", 0)
    if port_var > 10:
        reasons.append(f"Quét nhiều port khác nhau ({port_var} ports)")

    alert_freq = features.get("alert_frequency", 0)
    if alert_freq > 10:
        reasons.append(f"Có nhiều cảnh báo IDS ({alert_freq} cảnh báo)")

    req_rate = features.get("request_rate", 0)
    if req_rate > 5:
        reasons.append(f"Tốc độ request cao ({req_rate:.1f} events/phút)")

    rl = features.get("rule_level", 0)
    if rl >= 12:
        reasons.append(f"Cảnh báo mức Critical từ Wazuh (level {rl})")
    elif rl >= 7:
        reasons.append(f"Cảnh báo mức High từ Wazuh (level {rl})")

    # Giải thích từ model scores
    ms = anomaly_result.get("model_scores", {})
    if ms.get("ewma", 0) > 0.5:
        reasons.append("Lưu lượng tăng đột biến so với mức bình thường (spike)")
    if ms.get("cusum", 0) > 0.5:
        reasons.append("Hành vi thay đổi liên tục kéo dài — không phải tăng tạm thời")
    if ms.get("isolation_forest", 0) > 0.5:
        reasons.append("Mẫu hành vi khác biệt rõ rệt so với các IP khác")

    # Suricata signature
    sig = features.get("alert_signature", "")
    if sig:
        reasons.append(f"Suricata phát hiện: {sig}")

    if not reasons:
        reasons.append("Không phát hiện hành vi bất thường nào đáng kể")

    # ── Recommendation ────────────────────────────────────────────
    rec_map = {
        "HIGH":   "Chặn IP ngay lập tức và mở điều tra sự cố",
        "MEDIUM": "Theo dõi IP thêm, xem xét chặn nếu hành vi tiếp tục",
        "LOW":    "Không cần hành động, tiếp tục giám sát tự động",
    }
    recommendation = rec_map.get(risk_level, rec_map["LOW"])

    return {
        "summary":        summary,
        "reasons":        reasons[:5],       # giới hạn 5 lý do
        "risk_level":     risk_level,
        "risk_score":     risk_score,
        "recommendation": recommendation,
    }
