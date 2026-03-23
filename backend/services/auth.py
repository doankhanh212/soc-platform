import sqlite3, hashlib, secrets, time
from pathlib import Path
from typing import Optional

DB_PATH = Path(__file__).parent.parent / "data" / "soc_cases.db"

ROLES = {
    "admin":    {"level": 3, "label": "Admin",       "color": "#ff9900"},
    "soc2":     {"level": 2, "label": "SOC Level 2", "color": "#8b5cf6"},
    "soc1":     {"level": 1, "label": "SOC Level 1", "color": "#3b82f6"},
    "viewer":   {"level": 0, "label": "Viewer",      "color": "#6b7280"},
}

PERMISSIONS = {
    "admin":  ["view","triage","create_case","close_case","block_ip",
               "delete_triage","manage_users","view_settings"],
    "soc2":   ["view","triage","create_case","close_case","block_ip",
               "delete_triage"],
    "soc1":   ["view","triage","create_case"],
    "viewer": ["view"],
}

def _conn():
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_auth_db():
    with _conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role        TEXT NOT NULL DEFAULT 'soc1',
            full_name   TEXT DEFAULT '',
            email       TEXT DEFAULT '',
            is_active   INTEGER DEFAULT 1,
            created_at  REAL NOT NULL,
            last_login  REAL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token       TEXT PRIMARY KEY,
            user_id     INTEGER NOT NULL,
            username    TEXT NOT NULL,
            role        TEXT NOT NULL,
            created_at  REAL NOT NULL,
            expires_at  REAL NOT NULL
        );
        """)
        # Tạo admin mặc định nếu chưa có
        exists = c.execute(
            "SELECT id FROM users WHERE username='admin'"
        ).fetchone()
        if not exists:
            c.execute("""
                INSERT INTO users
                  (username,password_hash,role,full_name,created_at)
                VALUES (?,?,?,?,?)
            """, ("admin", _hash("admin123"), "admin",
                  "Administrator", time.time()))

def _hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def login(username: str, password: str) -> Optional[dict]:
    with _conn() as c:
        user = c.execute(
            "SELECT * FROM users WHERE username=? AND is_active=1",
            (username,)
        ).fetchone()
        if not user:
            return None
        if user["password_hash"] != _hash(password):
            return None
        # Tạo session token
        token = secrets.token_hex(32)
        now = time.time()
        expires = now + 8 * 3600  # 8 giờ
        c.execute("""
            INSERT INTO sessions
              (token,user_id,username,role,created_at,expires_at)
            VALUES (?,?,?,?,?,?)
        """, (token, user["id"], user["username"],
              user["role"], now, expires))
        c.execute(
            "UPDATE users SET last_login=? WHERE id=?",
            (now, user["id"])
        )
        return {
            "token":    token,
            "username": user["username"],
            "role":     user["role"],
            "full_name":user["full_name"],
            "expires":  expires,
        }

def verify_token(token: str) -> Optional[dict]:
    if not token:
        return None
    with _conn() as c:
        session = c.execute(
            "SELECT * FROM sessions WHERE token=? AND expires_at>?",
            (token, time.time())
        ).fetchone()
        if not session:
            return None
        return {
            "username": session["username"],
            "role":     session["role"],
            "token":    token,
        }

def logout(token: str):
    with _conn() as c:
        c.execute("DELETE FROM sessions WHERE token=?", (token,))

def list_users() -> list[dict]:
    with _conn() as c:
        rows = c.execute(
            "SELECT id,username,role,full_name,email,is_active,created_at,last_login"
            " FROM users ORDER BY created_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]

def create_user(username: str, password: str, role: str,
                full_name: str = "", email: str = "") -> dict:
    with _conn() as c:
        c.execute("""
            INSERT INTO users
              (username,password_hash,role,full_name,email,created_at)
            VALUES (?,?,?,?,?,?)
        """, (username, _hash(password), role,
              full_name, email, time.time()))
    return {"status": "created", "username": username}

def update_user(user_id: int, role: str = None,
                full_name: str = None, is_active: int = None,
                password: str = None):
    updates, params = [], []
    if role is not None:
        updates.append("role=?"); params.append(role)
    if full_name is not None:
        updates.append("full_name=?"); params.append(full_name)
    if is_active is not None:
        updates.append("is_active=?"); params.append(is_active)
    if password is not None:
        updates.append("password_hash=?"); params.append(_hash(password))
    if not updates:
        return
    params.append(user_id)
    with _conn() as c:
        c.execute(
            f"UPDATE users SET {','.join(updates)} WHERE id=?",
            params
        )

def delete_user(user_id: int):
    with _conn() as c:
        c.execute("DELETE FROM users WHERE id=? AND username!='admin'",
                  (user_id,))

def has_permission(role: str, perm: str) -> bool:
    return perm in PERMISSIONS.get(role, [])

init_auth_db()
