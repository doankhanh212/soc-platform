"""
Rule Engine — tự động tạo case từ alert theo rules định nghĩa sẵn.
Chạy ngầm mỗi 60 giây, poll OpenSearch lấy alerts mới.
Chống trùng bằng alert_id lưu trong SQLite.
"""
import asyncio
import logging
import time
from services.opensearch import _search
from services.cases import create_case
from config import get_settings

log = logging.getLogger("rule_engine")
cfg = get_settings()

# ── Rules định nghĩa ─────────────────────────────────────────────
# Mỗi rule là dict với các điều kiện, nếu thoả → tự động tạo case
# match_fn nhận alert dict, trả về True/False

AUTO_RULES = [
    {
        "name": "Critical level alert",
        "severity": "Critical",
        "match": lambda a: int(a.get("rule", {}).get("level", 0)) >= 12,
    },
    {
        "name": "SSH Brute Force",
        "severity": "High",
        "match": lambda a: a.get("rule", {}).get("id") in ("5720", "5716", "5710"),
    },
    {
        "name": "File Integrity Violation",
        "severity": "High",
        "match": lambda a: a.get("rule", {}).get("id") in ("550", "554"),
    },
    {
        "name": "Privilege Escalation",
        "severity": "High",
        "match": lambda a: a.get("rule", {}).get("id") in ("2502", "5503"),
    },
    {
        "name": "Suricata Critical Signature",
        "severity": "Critical",
        "match": lambda a: str(a.get("data", {}).get("alert", {}).get("severity", "")) == "1",
    },
    {
        "name": "SQL Injection Attempt",
        "severity": "High",
        "match": lambda a: a.get("rule", {}).get("id") in ("31101", "31166"),
    },
]


async def _get_seen_ids() -> set:
    """Lấy danh sách alert_id đã xử lý từ SQLite."""
    import sqlite3
    from pathlib import Path
    db = Path(__file__).parent.parent / "data" / "soc_cases.db"
    if not db.exists():
        return set()
    conn = sqlite3.connect(db)
    try:
        rows = conn.execute(
            "SELECT alert_id FROM processed_alerts"
        ).fetchall()
        return {r[0] for r in rows}
    except Exception:
        return set()
    finally:
        conn.close()


async def _mark_seen(alert_ids: list[str]):
    """Đánh dấu alert đã xử lý."""
    import sqlite3
    from pathlib import Path
    db = Path(__file__).parent.parent / "data" / "soc_cases.db"
    conn = sqlite3.connect(db)
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS processed_alerts (
                alert_id TEXT PRIMARY KEY,
                processed_at REAL NOT NULL
            )
        """)
        now = time.time()
        conn.executemany(
            "INSERT OR IGNORE INTO processed_alerts VALUES (?,?)",
            [(aid, now) for aid in alert_ids]
        )
        conn.commit()
    finally:
        conn.close()


async def _fetch_recent_alerts() -> list[dict]:
    """Lấy alerts 5 phút gần nhất từ OpenSearch."""
    body = {
        "size": 200,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": "now-5m"}}},
                    {"range": {"rule.level": {"gte": 7}}},
                ]
            }
        },
        "_source": [
            "@timestamp", "id",
            "agent.name", "agent.ip",
            "rule.id", "rule.level", "rule.description",
            "rule.mitre.id", "rule.mitre.tactic",
            "data.src_ip", "data.alert.severity", "data.alert.signature",
        ],
    }
    try:
        result = await _search(cfg.index_wazuh_alerts, body)
        return [h["_source"] | {"_alert_id": h["_id"]}
                for h in result.get("hits", {}).get("hits", [])]
    except Exception as e:
        log.error("Fetch alerts error: %s", e)
        return []


async def run_once():
    """Chạy 1 lần: fetch → match rules → tạo cases."""
    alerts = await _fetch_recent_alerts()
    if not alerts:
        return

    seen = await _get_seen_ids()
    new_alerts = [a for a in alerts if a.get("_alert_id") not in seen]
    if not new_alerts:
        return

    created = 0
    new_ids = []

    for alert in new_alerts:
        alert_id = alert.get("_alert_id", "")
        new_ids.append(alert_id)

        # Kiểm tra từng rule
        for rule in AUTO_RULES:
            try:
                if rule["match"](alert):
                    level = int(alert.get("rule", {}).get("level", 0))
                    mitre = alert.get("rule", {}).get("mitre", {})
                    create_case(
                        title=alert.get("rule", {}).get("description", "Auto case"),
                        severity=rule["severity"],
                        src_ip=alert.get("data", {}).get("src_ip", ""),
                        agent=alert.get("agent", {}).get("name", ""),
                        rule_id=str(alert.get("rule", {}).get("id", "")),
                        rule_desc=alert.get("rule", {}).get("description", ""),
                        mitre_ids=mitre.get("id", []),
                    )
                    created += 1
                    break  # 1 alert chỉ tạo 1 case
            except Exception as e:
                log.error("Rule match error: %s", e)

    await _mark_seen(new_ids)
    if created:
        log.info("Rule engine: created %d cases from %d new alerts", created, len(new_alerts))


async def rule_engine_loop():
    """Background loop chạy mỗi 60 giây."""
    log.info("Rule engine started (interval=60s)")
    # Chờ 10s để service khởi động xong
    await asyncio.sleep(10)
    while True:
        try:
            await run_once()
        except Exception as e:
            log.error("Rule engine loop error: %s", e)
        await asyncio.sleep(60)
