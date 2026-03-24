"""
HQG Autonomous AI-SOC — AI Detection Engine
Triển khai 4 phương pháp phát hiện bất thường theo luận văn:
1. EWMA — phát hiện spike traffic theo chuỗi thời gian
2. CUSUM — phát hiện drift kéo dài (sustained anomaly)
3. Entropy Analysis — phát hiện ransomware, DNS tunneling
4. Isolation Forest — phát hiện outlier đa chiều
Tổng hợp → risk_score → ghi ai-anomaly-alerts → auto block
"""

import asyncio
import logging
import math
import time
import json
from collections import defaultdict
from pathlib import Path
import httpx

log = logging.getLogger("ai_engine")

# ── Config ──────────────────────────────────────────────
OPENSEARCH_URL  = "https://localhost:9200"
OPENSEARCH_USER = "admin"
OPENSEARCH_PASS = "8mrFejtroEaBwVA.K*IJuLtBSRWNjsmp"
INDEX_WAZUH     = "wazuh-alerts-4.x-*"
INDEX_AI_OUT    = "ai-anomaly-alerts"
RUN_INTERVAL    = 60       # giây
RISK_AUTO_BLOCK = 0.75     # ngưỡng tự động block
RISK_ESCALATE   = 0.55     # ngưỡng tạo case
FASTAPI_URL     = "http://localhost:8000"

# ── MITRE ATT&CK mapping theo hành vi phát hiện ─────────
MITRE_MAP = {
    "ssh_bruteforce":       ("T1110",    "Credential Access"),
    "port_scan":            ("T1046",    "Discovery"),
    "dns_tunneling":        ("T1071.004","Command and Control"),
    "file_entropy_high":    ("T1486",    "Impact"),
    "login_anomaly":        ("T1078",    "Valid Accounts"),
    "spike_failed_login":   ("T1110.001","Brute Force"),
    "lateral_movement":     ("T1021",    "Lateral Movement"),
    "privilege_escalation": ("T1548",    "Privilege Escalation"),
    "default":              ("T1190",    "Initial Access"),
}

# ══════════════════════════════════════════════════════════
# PHẦN 1 — FEATURE EXTRACTION
# Thu thập feature từ OpenSearch theo 5 nhóm trong báo cáo:
# Auth / Process / File(FIM) / Network / Threat-Intel
# ══════════════════════════════════════════════════════════

async def _os_post(path: str, body: dict) -> dict:
    """Gọi OpenSearch API với SSL verify=False."""
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        r = await c.post(
            f"{OPENSEARCH_URL}{path}",
            json=body,
            auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
        )
        return r.json()


async def extract_features_per_ip(window_minutes: int = 15) -> dict[str, dict]:
    """
    Thu thập và tính feature cho từng IP nguồn trong window.
    Trả về dict: {ip → feature_dict}
    Feature groups theo báo cáo:
      - Auth: failed_login_count, success_after_failures
      - Network: unique_dest_ports, unique_dest_ips, connection_count
      - FIM: file_change_count
      - Suricata: suricata_alert_count, alert_severity_1_count
      - Behavior: rule_levels (max, mean)
    """
    since = f"now-{window_minutes}m"
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": since}}},
        "aggs": {
            # Group theo IP nguồn (cả 2 field)
            "by_srcip": {
                "terms": {"field": "data.srcip", "size": 50},
                "aggs": {
                    "failed_logins": {
                        "filter": {"terms": {
                            "rule.id": ["5503","5710","5712","5716","5720",
                                        "2501","2502","5301","5302"]
                        }}
                    },
                    "max_level":  {"max": {"field": "rule.level"}},
                    "mean_level": {"avg": {"field": "rule.level"}},
                    "fim_events": {
                        "filter": {"terms": {"rule.id": ["550","554","750"]}}
                    },
                    "priv_esc": {
                        "filter": {"terms": {
                            "rule.id": ["5400","5401","5402",
                                        "2900","2901","200300"]
                        }}
                    },
                }
            },
            "by_src_ip": {
                "terms": {"field": "data.src_ip", "size": 50},
                "aggs": {
                    "unique_dests": {
                        "cardinality": {"field": "data.dest_ip"}
                    },
                    "unique_ports": {
                        "cardinality": {"field": "data.dest_port"}
                    },
                    "suri_alerts": {
                        "filter": {"exists": {"field": "data.alert.signature"}}
                    },
                    "critical_suri": {
                        "filter": {"term": {"data.alert.severity": "1"}}
                    },
                    "max_level":  {"max": {"field": "rule.level"}},
                }
            }
        }
    }

    result = await _os_post(f"/{INDEX_WAZUH}/_search", body)
    aggs   = result.get("aggregations", {})
    features: dict[str, dict] = {}

    # Xử lý HIDS (data.srcip)
    for b in aggs.get("by_srcip", {}).get("buckets", []):
        ip = b["key"]
        if not ip or ip in ("", "127.0.0.1", "::1"):
            continue
        features.setdefault(ip, _empty_feature(ip))
        f = features[ip]
        f["failed_login_count"]    += b["failed_logins"]["doc_count"]
        f["fim_change_count"]      += b["fim_events"]["doc_count"]
        f["privilege_escalation"]  += b["priv_esc"]["doc_count"]
        f["total_alerts"]          += b["doc_count"]
        f["max_rule_level"]         = max(f["max_rule_level"],
                                          b.get("max_level", {}).get("value") or 0)
        ml = b.get("mean_level", {}).get("value") or 0
        if f["mean_rule_level"] == 0:
            f["mean_rule_level"] = ml
        else:
            f["mean_rule_level"] = (f["mean_rule_level"] + ml) / 2

    # Xử lý Network/Suricata (data.src_ip)
    for b in aggs.get("by_src_ip", {}).get("buckets", []):
        ip = b["key"]
        if not ip or ip in ("", "127.0.0.1", "::1"):
            continue
        features.setdefault(ip, _empty_feature(ip))
        f = features[ip]
        f["unique_dest_ips"]       += b["unique_dests"]["value"]
        f["unique_dest_ports"]     += b["unique_ports"]["value"]
        f["suricata_alert_count"]  += b["suri_alerts"]["doc_count"]
        f["critical_suri_count"]   += b["critical_suri"]["doc_count"]
        f["total_alerts"]          += b["doc_count"]
        f["max_rule_level"]         = max(f["max_rule_level"],
                                          b.get("max_level", {}).get("value") or 0)

    return features


def _empty_feature(ip: str) -> dict:
    return {
        "ip":                   ip,
        "failed_login_count":   0,
        "fim_change_count":     0,
        "privilege_escalation": 0,
        "suricata_alert_count": 0,
        "critical_suri_count":  0,
        "unique_dest_ips":      0,
        "unique_dest_ports":    0,
        "total_alerts":         0,
        "max_rule_level":       0,
        "mean_rule_level":      0.0,
        "dns_entropy":          0.0,
    }


async def compute_dns_entropy(ip: str, window_minutes: int = 15) -> float:
    """
    Tính entropy của DNS labels từ IP nguồn.
    Entropy cao → DNS tunneling hoặc DGA domain.
    """
    since = f"now-{window_minutes}m"
    body = {
        "size": 100,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": since}}},
                    {"exists": {"field": "data.dns.question.name"}},
                ],
                "should": [
                    {"term": {"data.src_ip": ip}},
                    {"term": {"data.srcip":  ip}},
                ],
                "minimum_should_match": 1,
            }
        },
        "_source": ["data.dns.question.name"],
    }
    try:
        r = await _os_post(f"/{INDEX_WAZUH}/_search", body)
        names = []
        for h in r.get("hits", {}).get("hits", []):
            n = h["_source"].get("data", {}).get("dns", {}) \
                            .get("question", {}).get("name", "")
            if n:
                names.append(n)
        if not names:
            return 0.0
        return _string_entropy(" ".join(names))
    except Exception:
        return 0.0


def _string_entropy(s: str) -> float:
    """Shannon entropy của chuỗi."""
    if not s:
        return 0.0
    freq: dict[str, int] = defaultdict(int)
    for c in s:
        freq[c] += 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


# ══════════════════════════════════════════════════════════
# PHẦN 2 — 4 PHƯƠNG PHÁP PHÁT HIỆN (theo báo cáo)
# ══════════════════════════════════════════════════════════

# State cho EWMA và CUSUM (lưu in-memory, reset khi restart)
_ewma_state:  dict[str, float] = {}   # ip → ewma_value
_cusum_state: dict[str, float] = {}   # ip → cusum_score
_baseline:    dict[str, dict]  = {}   # ip → historical mean

EWMA_ALPHA = 0.3   # smoothing factor (0.1=slow, 0.5=fast)
CUSUM_K    = 2.0   # allowable slack
CUSUM_H    = 5.0   # decision threshold


def detect_ewma(ip: str, current_value: float) -> tuple[float, str]:
    """
    EWMA — phát hiện spike đột biến theo chuỗi thời gian.
    Phù hợp với: failed_login_rate, connection_count spike.
    Trả về (score 0-1, description)
    """
    prev = _ewma_state.get(ip, current_value)
    ewma = EWMA_ALPHA * current_value + (1 - EWMA_ALPHA) * prev
    _ewma_state[ip] = ewma

    if ewma == 0:
        return 0.0, ""

    ratio = current_value / (ewma + 1e-9)
    # Ratio > 3 = spike đáng kể
    if ratio > 5:
        score = min(1.0, (ratio - 5) / 15 + 0.7)
        return score, f"EWMA spike: current={current_value:.0f}, ewma={ewma:.0f}, ratio={ratio:.1f}x"
    elif ratio > 3:
        score = min(0.7, (ratio - 3) / 8 + 0.4)
        return score, f"EWMA tăng đột biến: ratio={ratio:.1f}x"
    return 0.0, ""


def detect_cusum(ip: str, current_value: float,
                 mean_baseline: float = 5.0) -> tuple[float, str]:
    """
    CUSUM — phát hiện drift kéo dài (sustained anomaly).
    Phù hợp với: phát hiện tấn công chậm không bị EWMA bắt.
    """
    z = (current_value - mean_baseline) / (mean_baseline + 1)
    prev = _cusum_state.get(ip, 0.0)
    cusum = max(0.0, prev + z - CUSUM_K)
    _cusum_state[ip] = cusum

    if cusum > CUSUM_H * 2:
        score = min(1.0, (cusum - CUSUM_H) / (CUSUM_H * 3) + 0.6)
        return score, f"CUSUM drift cao: S={cusum:.1f} (ngưỡng={CUSUM_H})"
    elif cusum > CUSUM_H:
        score = min(0.6, (cusum - CUSUM_H) / CUSUM_H + 0.35)
        return score, f"CUSUM drift: S={cusum:.1f}"
    return 0.0, ""


def detect_entropy(f: dict) -> tuple[float, str, str]:
    """
    Entropy Analysis — phát hiện:
    1. DNS tunneling: entropy DNS labels cao
    2. Ransomware: file changes nhiều + entropy pattern
    Trả về (score, description, mitre_key)
    """
    dns_ent = f.get("dns_entropy", 0.0)
    fim     = f.get("fim_change_count", 0)

    # DNS tunneling: entropy > 3.5
    if dns_ent > 4.0:
        score = min(1.0, (dns_ent - 4.0) / 3.0 + 0.65)
        return score, f"DNS entropy={dns_ent:.2f} — khả năng DNS tunneling", "dns_tunneling"
    elif dns_ent > 3.5:
        return 0.45, f"DNS entropy={dns_ent:.2f} — đáng ngờ", "dns_tunneling"

    # Ransomware pattern: FIM thay đổi nhiều file nhanh
    if fim > 50:
        score = min(1.0, fim / 200 + 0.6)
        return score, f"FIM thay đổi {fim} file — khả năng ransomware/data staging", "file_entropy_high"
    elif fim > 20:
        return 0.45, f"FIM thay đổi {fim} file trong 15 phút", "file_entropy_high"

    return 0.0, "", "default"


def detect_isolation_forest(features: list[dict]) -> dict[str, float]:
    """
    Isolation Forest — phát hiện outlier đa chiều.
    Không cần nhãn (unsupervised).
    Triển khai lightweight không cần sklearn nếu thiếu.
    Trả về dict: {ip → anomaly_score 0-1}
    """
    if not features:
        return {}
    try:
        from sklearn.ensemble import IsolationForest
        import numpy as np

        keys = ["failed_login_count", "unique_dest_ports",
                "unique_dest_ips", "suricata_alert_count",
                "fim_change_count", "max_rule_level",
                "total_alerts", "privilege_escalation"]

        X = np.array([[f.get(k, 0) for k in keys] for f in features],
                     dtype=float)
        # Normalize
        maxv = X.max(axis=0) + 1e-9
        X = X / maxv

        clf = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42,
        )
        clf.fit(X)
        # score_samples: sâu hơn → ít bất thường hơn
        raw = clf.score_samples(X)
        # Chuyển về [0,1]: raw âm nhiều = outlier → score cao
        scores = 1 - (raw - raw.min()) / (raw.max() - raw.min() + 1e-9)

        return {f["ip"]: float(s) for f, s in zip(features, scores)}

    except ImportError:
        # Fallback: heuristic đơn giản nếu không có sklearn
        results = {}
        for f in features:
            score = 0.0
            if f["failed_login_count"]   > 20: score += 0.3
            if f["unique_dest_ports"]    > 50: score += 0.3
            if f["suricata_alert_count"] > 10: score += 0.2
            if f["max_rule_level"]       >= 12: score += 0.3
            if f["privilege_escalation"] > 0:  score += 0.4
            results[f["ip"]] = min(1.0, score)
        return results


# ══════════════════════════════════════════════════════════
# PHẦN 3 — SCORE AGGREGATOR
# Tổng hợp 4 model → risk_score + explainability
# ══════════════════════════════════════════════════════════

def aggregate_risk(
    ip: str,
    f: dict,
    ewma_score:    float,
    ewma_desc:     str,
    cusum_score:   float,
    cusum_desc:    str,
    entropy_score: float,
    entropy_desc:  str,
    if_score:      float,
) -> dict:
    """
    Tổng hợp scores theo trọng số (theo báo cáo):
    - Isolation Forest: 30% (outlier đa chiều)
    - EWMA spike:       25% (phát hiện nhanh)
    - CUSUM drift:      20% (phát hiện chậm)
    - Entropy:          15% (đặc thù)
    - Rule-based:       10% (max_rule_level từ Wazuh)
    """
    rule_score = min(1.0, f["max_rule_level"] / 15.0)

    # Trọng số theo báo cáo
    risk_score = (
        if_score      * 0.30 +
        ewma_score    * 0.25 +
        cusum_score   * 0.20 +
        entropy_score * 0.15 +
        rule_score    * 0.10
    )
    risk_score = min(1.0, risk_score)

    # Risk level theo ngưỡng báo cáo: low < 0.5, medium 0.5-0.8, high > 0.8
    if risk_score >= 0.80:
        risk_level = "high"
    elif risk_score >= 0.55:
        risk_level = "medium"
    elif risk_score >= 0.30:
        risk_level = "low"
    else:
        return {}   # Không đủ ngưỡng, bỏ qua

    # Explainability: top contributing features cho analyst
    top_features = []
    if f["failed_login_count"] > 10:
        top_features.append(
            f"failed_login_count={f['failed_login_count']} "
            f"(ngưỡng 10) — xác thực thất bại nhiều lần")
    if f["unique_dest_ports"] > 20:
        top_features.append(
            f"unique_dest_ports={f['unique_dest_ports']} "
            f"— khả năng quét cổng")
    if f["privilege_escalation"] > 0:
        top_features.append(
            f"privilege_escalation={f['privilege_escalation']} "
            f"— leo thang đặc quyền")
    if f["fim_change_count"] > 10:
        top_features.append(
            f"fim_change_count={f['fim_change_count']} "
            f"— file integrity bất thường")
    if f["critical_suri_count"] > 0:
        top_features.append(
            f"suricata_severity_1={f['critical_suri_count']} "
            f"— cảnh báo Suricata mức Critical")
    if ewma_desc:
        top_features.append(ewma_desc)
    if cusum_desc:
        top_features.append(cusum_desc)
    if entropy_desc:
        top_features.append(entropy_desc)

    # Giữ top 4 theo độ quan trọng
    top_features = top_features[:4]

    # MITRE ATT&CK mapping
    mitre_id, mitre_tactic = MITRE_MAP["default"]
    if f["privilege_escalation"] > 0:
        mitre_id, mitre_tactic = MITRE_MAP["privilege_escalation"]
    elif f["failed_login_count"] > 10:
        mitre_id, mitre_tactic = MITRE_MAP["ssh_bruteforce"]
    elif f["unique_dest_ports"] > 20:
        mitre_id, mitre_tactic = MITRE_MAP["port_scan"]
    elif entropy_score > 0.4:
        if "dns" in entropy_desc.lower():
            mitre_id, mitre_tactic = MITRE_MAP["dns_tunneling"]
        else:
            mitre_id, mitre_tactic = MITRE_MAP["file_entropy_high"]

    # Triggered models list
    triggered_models = []
    if if_score      > 0.3: triggered_models.append("IsolationForest")
    if ewma_score    > 0.3: triggered_models.append("EWMA")
    if cusum_score   > 0.3: triggered_models.append("CUSUM")
    if entropy_score > 0.3: triggered_models.append("Entropy")
    if rule_score    > 0.5: triggered_models.append("WazuhRule")

    return {
        "@timestamp":       _now_iso(),
        "src_ip":           ip,
        "risk_score":       round(risk_score, 4),
        "risk_level":       risk_level,
        "anomaly_score":    round(risk_score, 4),
        "top_features":     top_features,
        "triggered_models": triggered_models,
        "mitre_id":         mitre_id,
        "mitre_tactic":     mitre_tactic,
        "should_block":     risk_score >= RISK_AUTO_BLOCK,
        "features_raw": {
            "failed_login_count":   f["failed_login_count"],
            "unique_dest_ports":    f["unique_dest_ports"],
            "unique_dest_ips":      f["unique_dest_ips"],
            "suricata_alert_count": f["suricata_alert_count"],
            "fim_change_count":     f["fim_change_count"],
            "max_rule_level":       f["max_rule_level"],
            "privilege_escalation": f["privilege_escalation"],
            "dns_entropy":          round(f.get("dns_entropy", 0), 3),
        },
        "model_scores": {
            "isolation_forest": round(if_score,      4),
            "ewma":             round(ewma_score,    4),
            "cusum":            round(cusum_score,   4),
            "entropy":          round(entropy_score, 4),
            "rule_based":       round(rule_score,    4),
        },
        "engine_version": "1.0.0",
    }


# ══════════════════════════════════════════════════════════
# PHẦN 4 — WRITE TO OPENSEARCH + AUTO ACTION
# ══════════════════════════════════════════════════════════

async def write_anomaly(doc: dict) -> None:
    """Ghi kết quả vào ai-anomaly-alerts index."""
    await _os_post(f"/{INDEX_AI_OUT}/_doc", doc)
    log.info(
        "AI anomaly: ip=%s risk_score=%.3f risk_level=%s models=%s",
        doc["src_ip"], doc["risk_score"],
        doc["risk_level"], doc["triggered_models"],
    )


async def auto_block_if_needed(doc: dict) -> None:
    """
    Nếu risk_score >= RISK_AUTO_BLOCK → gọi FastAPI block-ip.
    Safety: chỉ block khi có ít nhất 2 model kích hoạt.
    """
    if not doc.get("should_block"):
        return
    if len(doc.get("triggered_models", [])) < 2:
        log.info("AI: skip block %s — chưa đủ 2 model xác nhận", doc["src_ip"])
        return

    ip = doc["src_ip"]
    log.warning(
        "AI AUTO-BLOCK: ip=%s risk_score=%.3f triggered=%s",
        ip, doc["risk_score"], doc["triggered_models"],
    )

    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(
                f"{FASTAPI_URL}/api/response/block-ip",
                params={"ip": ip},
            )
            if r.status_code == 200:
                log.info("AI: block %s thành công", ip)
            else:
                log.warning("AI: block %s lỗi %d: %s",
                            ip, r.status_code, r.text[:200])
    except Exception as e:
        log.error("AI: không thể gọi block-ip: %s", e)


async def ensure_index() -> None:
    """Tạo index ai-anomaly-alerts nếu chưa có."""
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as c:
            r = await c.head(
                f"{OPENSEARCH_URL}/{INDEX_AI_OUT}",
                auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
            )
            if r.status_code == 404:
                mapping = {
                    "mappings": {
                        "properties": {
                            "@timestamp":     {"type": "date"},
                            "src_ip":         {"type": "ip"},
                            "risk_score":     {"type": "float"},
                            "risk_level":     {"type": "keyword"},
                            "anomaly_score":  {"type": "float"},
                            "mitre_id":       {"type": "keyword"},
                            "mitre_tactic":   {"type": "keyword"},
                            "should_block":   {"type": "boolean"},
                            "engine_version": {"type": "keyword"},
                        }
                    }
                }
                await _os_post(f"/{INDEX_AI_OUT}", mapping)
                log.info("Đã tạo index %s", INDEX_AI_OUT)
    except Exception as e:
        log.warning("ensure_index: %s", e)


# ══════════════════════════════════════════════════════════
# PHẦN 5 — MAIN LOOP
# ══════════════════════════════════════════════════════════

def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


async def run_once() -> None:
    """
    Chạy 1 chu kỳ phát hiện:
    1. Thu thập features từ OpenSearch (15 phút gần nhất)
    2. Chạy 4 model phát hiện
    3. Tổng hợp risk_score
    4. Ghi kết quả + auto block nếu cần
    """
    features_map = await extract_features_per_ip(window_minutes=15)
    if not features_map:
        log.debug("AI: không có data trong 15 phút vừa qua")
        return

    # Tính DNS entropy song song để tiết kiệm thời gian
    dns_tasks = {ip: compute_dns_entropy(ip, 15) for ip in features_map}
    for ip, coro in dns_tasks.items():
        features_map[ip]["dns_entropy"] = await coro

    # Isolation Forest trên toàn bộ tập
    feature_list  = list(features_map.values())
    if_scores_map = detect_isolation_forest(feature_list)

    created = 0
    for ip, f in features_map.items():
        # Bỏ qua IP nội bộ/loopback
        if ip.startswith(("127.", "10.", "192.168.", "172.16.")):
            continue

        if_score = if_scores_map.get(ip, 0.0)

        # EWMA trên failed_login_count
        ewma_score, ewma_desc   = detect_ewma(ip, f["failed_login_count"])

        # CUSUM trên total_alerts
        cusum_score, cusum_desc = detect_cusum(ip, f["total_alerts"],
                                               mean_baseline=20.0)

        # Entropy (DNS + FIM)
        ent_score, ent_desc, _  = detect_entropy(f)

        # Tổng hợp
        doc = aggregate_risk(
            ip, f,
            ewma_score,  ewma_desc,
            cusum_score, cusum_desc,
            ent_score,   ent_desc,
            if_score,
        )

        if not doc:
            continue

        await write_anomaly(doc)
        await auto_block_if_needed(doc)
        created += 1

    if created:
        log.info("AI Engine: phát hiện %d anomaly IPs", created)


async def ai_engine_loop() -> None:
    """Background loop chạy mỗi RUN_INTERVAL giây."""
    log.info(
        "AI Engine khởi động (interval=%ds, auto_block>=%.2f)",
        RUN_INTERVAL, RISK_AUTO_BLOCK,
    )
    await ensure_index()
    await asyncio.sleep(15)  # Chờ FastAPI khởi động xong

    while True:
        try:
            await run_once()
        except Exception as e:
            log.error("AI Engine lỗi: %s", e, exc_info=True)
        await asyncio.sleep(RUN_INTERVAL)


# ── Entry point khi chạy độc lập ────────────────────────
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    asyncio.run(ai_engine_loop())
