"""
Feature Extraction — trích xuất đặc trưng từ log Wazuh + Suricata.

Input:  raw log event (dict) từ OpenSearch
Output: feature vector (dict) dùng cho AI models

Features cơ bản: src_ip, dest_ip, dest_port, protocol,
                 alert_signature, alert_severity, rule_level, timestamp
Features tính thêm: connection_count, alert_frequency,
                    port_variance, request_rate
"""
import time
from threading import Lock

import pandas as pd

from config import get_settings
from services.opensearch import _search

cfg = get_settings()

# ── In-memory sliding window (5 phút) cho real-time features ─────
_event_window: list[dict] = []
_WINDOW_SEC = 300        # 5 phút
_MAX_WINDOW = 10_000
_window_lock = Lock()


def _trim_window():
    """Loại bỏ events quá cũ."""
    global _event_window
    cutoff = time.time() - _WINDOW_SEC
    recent = [e for e in _event_window if e["_ts"] >= cutoff]
    if len(recent) > _MAX_WINDOW:
        recent = recent[-_MAX_WINDOW:]
    _event_window = recent


def _safe_int(v) -> int:
    try:
        return int(v)
    except (ValueError, TypeError):
        return 0


# ══════════════════════════════════════════════════════════════════
# SINGLE EVENT — dùng cho POST /api/ai/analyze
# ══════════════════════════════════════════════════════════════════

def extract_features(event: dict) -> dict:
    """
    Trích xuất features từ một log event đơn lẻ.

    Trả về dict chứa cả raw fields lẫn computed features.
    """
    data  = event.get("data", {})
    rule  = event.get("rule", {})
    alert = data.get("alert", {})
    agent = event.get("agent", {})

    src_ip          = data.get("src_ip") or data.get("srcip") or agent.get("ip", "")
    dest_ip         = data.get("dest_ip", "")
    dest_port       = _safe_int(data.get("dest_port", 0))
    protocol        = data.get("proto", "")
    alert_signature = alert.get("signature", "")
    alert_severity  = _safe_int(alert.get("severity", 0))
    rule_level      = _safe_int(rule.get("level", 0))
    timestamp       = event.get("@timestamp") or event.get("timestamp", "")

    # Ghi vào sliding window nếu có src_ip hợp lệ.
    now = time.time()
    recent = []
    with _window_lock:
        if src_ip:
            _event_window.append({
                "_ts":        now,
                "src_ip":     src_ip,
                "dest_port":  dest_port,
                "rule_level": rule_level,
            })
        _trim_window()

        if src_ip:
            cutoff = now - _WINDOW_SEC
            recent = [e for e in _event_window
                      if e["_ts"] >= cutoff and e["src_ip"] == src_ip]

    connection_count = len(recent)
    alert_frequency  = sum(1 for e in recent if e["rule_level"] > 0)
    ports            = {e["dest_port"] for e in recent if e["dest_port"] > 0}
    port_variance    = len(ports)
    if recent:
        first_seen = min(e["_ts"] for e in recent)
        minutes = max((now - first_seen) / 60, 1 / 60)
    else:
        minutes = 1.0
    request_rate     = round(connection_count / minutes, 2)

    return {
        # Raw fields
        "src_ip":          src_ip,
        "dest_ip":         dest_ip,
        "dest_port":       dest_port,
        "protocol":        protocol,
        "alert_signature": alert_signature,
        "alert_severity":  alert_severity,
        "rule_level":      rule_level,
        "timestamp":       timestamp,
        # Computed features
        "connection_count": connection_count,
        "alert_frequency":  alert_frequency,
        "port_variance":    port_variance,
        "request_rate":     request_rate,
    }


# ══════════════════════════════════════════════════════════════════
# BATCH — dùng cho background AI loop
# ══════════════════════════════════════════════════════════════════

async def extract_features_batch(window_minutes: int = 15) -> list[dict]:
    """
    Trích xuất features cho tất cả IPs trong cửa sổ thời gian.
    Dùng pandas để group-by và aggregate.
    """
    body = {
        "size": 1000,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"range": {"@timestamp": {"gte": f"now-{window_minutes}m"}}},
        "_source": [
            "@timestamp", "agent.ip", "agent.name",
            "data.src_ip", "data.srcip", "data.dest_ip",
            "data.dest_port", "data.proto",
            "data.alert.signature", "data.alert.severity",
            "rule.level", "rule.description", "rule.id",
        ],
    }

    try:
        result = await _search(cfg.index_wazuh_alerts, body)
        hits = [h["_source"] for h in result.get("hits", {}).get("hits", [])]
    except Exception:
        return []

    if not hits:
        return []

    # ── Pandas processing ────────────────────────────────────────
    df = pd.json_normalize(hits, sep="_")

    # Chuẩn hóa cột src_ip (Suricata: data.src_ip, Wazuh: data.srcip).
    src_ip_series = pd.Series(index=df.index, dtype="object")
    if "data_src_ip" in df.columns:
        src_ip_series = src_ip_series.combine_first(df["data_src_ip"])
    if "data_srcip" in df.columns:
        src_ip_series = src_ip_series.combine_first(df["data_srcip"])
    if "agent_ip" in df.columns:
        src_ip_series = src_ip_series.combine_first(df["agent_ip"])
    df["src_ip"] = src_ip_series.fillna("")

    df["dest_port"] = pd.to_numeric(
        df.get("data_dest_port", pd.Series(dtype="int")),
        errors="coerce",
    ).fillna(0).astype(int)

    df["rule_level"] = pd.to_numeric(
        df.get("rule_level", pd.Series(dtype="int")),
        errors="coerce",
    ).fillna(0).astype(int)

    df["alert_severity"] = pd.to_numeric(
        df.get("data_alert_severity", pd.Series(dtype="int")),
        errors="coerce",
    ).fillna(0).astype(int)

    # ── Group by IP, aggregate ───────────────────────────────────
    results: list[dict] = []

    for ip, grp in df.groupby("src_ip"):
        if not ip or ip in ("", "127.0.0.1", "::1", "0.0.0.0"):
            continue

        unique_ports = grp["dest_port"].nunique()

        results.append({
            "src_ip":           ip,
            "connection_count": len(grp),
            "alert_frequency":  int((grp["rule_level"] > 0).sum()),
            "port_variance":    int(unique_ports),
            "request_rate":     round(len(grp) / max(1, window_minutes), 2),
            "alert_severity":   int(grp["alert_severity"].max()),
            "rule_level":       int(grp["rule_level"].max()),
            "mean_rule_level":  round(float(grp["rule_level"].mean()), 2),
        })

    return results


# ══════════════════════════════════════════════════════════════════
# SAMPLE TEST DATA
# ══════════════════════════════════════════════════════════════════

SAMPLE_EVENTS = [
    {
        "@timestamp": "2026-03-24T10:00:00Z",
        "agent": {"ip": "192.168.1.100", "name": "wazuh-agent-01"},
        "data": {
            "src_ip": "45.33.32.156",
            "dest_ip": "192.168.1.100",
            "dest_port": "22",
            "proto": "TCP",
            "alert": {"signature": "ET SCAN SSH Brute Force", "severity": "1"},
        },
        "rule": {"level": "12", "description": "SSH brute-force attack detected"},
    },
    {
        "@timestamp": "2026-03-24T10:01:00Z",
        "agent": {"ip": "192.168.1.101", "name": "suricata-sensor"},
        "data": {
            "src_ip": "185.220.101.42",
            "dest_ip": "192.168.1.101",
            "dest_port": "443",
            "proto": "TCP",
            "alert": {"signature": "ET POLICY TLS possible TOR SSL", "severity": "2"},
        },
        "rule": {"level": "8", "description": "Suricata: possible TOR connection"},
    },
    {
        "@timestamp": "2026-03-24T10:02:00Z",
        "agent": {"ip": "192.168.1.102", "name": "wazuh-agent-02"},
        "data": {
            "src_ip": "10.0.0.55",
            "dest_ip": "192.168.1.102",
            "dest_port": "80",
            "proto": "TCP",
            "alert": {"signature": "", "severity": ""},
        },
        "rule": {"level": "3", "description": "Syslog informational message"},
    },
]
