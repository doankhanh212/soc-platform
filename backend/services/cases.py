"""
SQLite-based Case Management
Tables: cases, triage_log
"""
import sqlite3
import json
import time
from pathlib import Path
from typing import Optional

DB_PATH = Path(__file__).parent.parent / "data" / "soc_cases.db"

def _conn():
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with _conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS cases (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id     TEXT UNIQUE NOT NULL,
            title       TEXT NOT NULL,
            status      TEXT NOT NULL DEFAULT 'New',
            severity    TEXT NOT NULL DEFAULT 'Medium',
            src_ip      TEXT,
            agent       TEXT,
            rule_id     TEXT,
            rule_desc   TEXT,
            mitre_ids   TEXT,
            assignee    TEXT,
            created_at  REAL NOT NULL,
            updated_at  REAL NOT NULL,
            closed_at   REAL
        );
        CREATE TABLE IF NOT EXISTS triage_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id         TEXT NOT NULL,
            classification  TEXT NOT NULL,
            reasons         TEXT,
            mitre_mapping   TEXT,
            impact_level    TEXT,
            analysis        TEXT,
            recommendation  TEXT,
            analyst         TEXT,
            created_at      REAL NOT NULL,
            FOREIGN KEY (case_id) REFERENCES cases(case_id)
        );
        CREATE INDEX IF NOT EXISTS idx_cases_status   ON cases(status);
        CREATE INDEX IF NOT EXISTS idx_cases_severity ON cases(severity);
        CREATE INDEX IF NOT EXISTS idx_cases_created  ON cases(created_at);
        """)

def _row_to_dict(row) -> dict:
    d = dict(row)
    for f in ("mitre_ids", "reasons", "mitre_mapping"):
        if f in d and d[f]:
            try: d[f] = json.loads(d[f])
            except: pass
    return d

# ─── Cases CRUD ───────────────────────────────────────────────────

def create_case(title: str, severity: str = "Medium", src_ip: str = "",
                agent: str = "", rule_id: str = "", rule_desc: str = "",
                mitre_ids: list = None) -> dict:
    now = time.time()
    with _conn() as c:
        # Auto-increment case number
        row = c.execute("SELECT MAX(CAST(SUBSTR(case_id,2) AS INT)) FROM cases").fetchone()
        next_num = (row[0] or 1000) + 1
        case_id = f"#{next_num}"
        c.execute("""
            INSERT INTO cases (case_id,title,status,severity,src_ip,agent,
                               rule_id,rule_desc,mitre_ids,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (case_id, title, "New", severity, src_ip, agent,
              rule_id, rule_desc, json.dumps(mitre_ids or []), now, now))
    return get_case(case_id)

def get_case(case_id: str) -> Optional[dict]:
    with _conn() as c:
        row = c.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
        return _row_to_dict(row) if row else None

def list_cases(status: str = None, limit: int = 50) -> list[dict]:
    sql = "SELECT * FROM cases"
    params = []
    if status:
        sql += " WHERE status=?"
        params.append(status)
    sql += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    with _conn() as c:
        rows = c.execute(sql, params).fetchall()
        return [_row_to_dict(r) for r in rows]

def update_case_status(case_id: str, status: str, assignee: str = None) -> dict:
    now = time.time()
    closed = now if status in ("Resolved", "Closed") else None
    with _conn() as c:
        c.execute("""UPDATE cases SET status=?, assignee=COALESCE(?,assignee),
                     updated_at=?, closed_at=? WHERE case_id=?""",
                  (status, assignee, now, closed, case_id))
    return get_case(case_id)

def submit_triage(case_id: str, classification: str, reasons: list,
                  mitre_mapping: list, impact_level: str,
                  analysis: str, recommendation: str,
                  analyst: str = "analyst") -> dict:
    now = time.time()
    new_status = "Resolved" if classification in ("True Positive", "False Positive") else "In Progress"
    with _conn() as c:
        c.execute("""
            INSERT INTO triage_log (case_id,classification,reasons,mitre_mapping,
                                    impact_level,analysis,recommendation,analyst,created_at)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (case_id, classification, json.dumps(reasons), json.dumps(mitre_mapping),
              impact_level, analysis, recommendation, analyst, now))
        c.execute("UPDATE cases SET status=?, updated_at=? WHERE case_id=?",
                  (new_status, now, case_id))
    return get_case(case_id)

def get_triage_log(case_id: str) -> list[dict]:
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM triage_log WHERE case_id=? ORDER BY created_at DESC",
            (case_id,)).fetchall()
        return [_row_to_dict(r) for r in rows]

def case_stats() -> dict:
    with _conn() as c:
        total   = c.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
        by_status = dict(c.execute(
            "SELECT status, COUNT(*) FROM cases GROUP BY status").fetchall())
        today = time.time() - 86400
        triaged = c.execute(
            "SELECT COUNT(*) FROM triage_log WHERE created_at>?", (today,)).fetchone()[0]
        tp = c.execute(
            "SELECT COUNT(*) FROM triage_log WHERE classification='True Positive' AND created_at>?",
            (today,)).fetchone()[0]
        fp = c.execute(
            "SELECT COUNT(*) FROM triage_log WHERE classification='False Positive' AND created_at>?",
            (today,)).fetchone()[0]
    return {
        "total": total,
        "by_status": by_status,
        "triaged_today": triaged,
        "true_positives": tp,
        "false_positives": fp,
    }

# Init on import
init_db()
