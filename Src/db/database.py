# src/db/database.py
import sqlite3
import hashlib
import datetime
import os
from config import DB_PATH


def get_conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            username  TEXT UNIQUE NOT NULL,
            password  TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT NOT NULL,
            url         TEXT NOT NULL,
            verdict     TEXT NOT NULL,
            risk_score  INTEGER NOT NULL,
            ml_verdict  TEXT,
            ml_conf     REAL,
            vt_hits     INTEGER DEFAULT 0,
            reasons     TEXT,
            ai_summary  TEXT,
            scan_time   TEXT DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    # Seed a default user so judges can log in immediately
    _seed_default_user(conn)
    conn.close()


def _seed_default_user(conn):
    try:
        conn.execute(
            "INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
            ("admin", _hash("admin123"))
        )
        conn.commit()
    except Exception:
        pass


def _hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def authenticate(username: str, password: str) -> bool:
    conn = get_conn()
    row = conn.execute(
        "SELECT 1 FROM users WHERE username=? AND password=?",
        (username, _hash(password))
    ).fetchone()
    conn.close()
    return row is not None


def register(username: str, password: str) -> tuple[bool, str]:
    if len(username) < 3:
        return False, "Username must be at least 3 characters."
    if len(password) < 6:
        return False, "Password must be at least 6 characters."
    try:
        conn = get_conn()
        conn.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, _hash(password))
        )
        conn.commit()
        conn.close()
        return True, "Account created."
    except sqlite3.IntegrityError:
        return False, "Username already taken."


def save_scan(username, url, verdict, risk_score,
              ml_verdict="", ml_conf=0.0, vt_hits=0,
              reasons="", ai_summary=""):
    conn = get_conn()
    conn.execute(
        """INSERT INTO scans
           (username,url,verdict,risk_score,ml_verdict,ml_conf,
            vt_hits,reasons,ai_summary)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (username, url, verdict, risk_score,
         ml_verdict, ml_conf, vt_hits,
         str(reasons), ai_summary)
    )
    conn.commit()
    conn.close()


def get_history(username: str, limit: int = 50) -> list:
    conn = get_conn()
    rows = conn.execute(
        """SELECT url, verdict, risk_score, vt_hits, scan_time
           FROM scans WHERE username=?
           ORDER BY scan_time DESC LIMIT ?""",
        (username, limit)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_stats(username: str) -> dict:
    conn = get_conn()
    row = conn.execute(
        """SELECT
             COUNT(*) as total,
             SUM(CASE WHEN verdict='MALICIOUS' THEN 1 ELSE 0 END) as malicious,
             SUM(CASE WHEN verdict='SUSPICIOUS' THEN 1 ELSE 0 END) as suspicious,
             SUM(CASE WHEN verdict='SAFE' THEN 1 ELSE 0 END) as safe,
             AVG(risk_score) as avg_risk
           FROM scans WHERE username=?""",
        (username,)
    ).fetchone()
    conn.close()
    return dict(row) if row else {}