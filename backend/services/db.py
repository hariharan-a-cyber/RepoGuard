import os
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

DB_PATH = os.getenv("SQLITE_DB_PATH", "data/repoguard.db")
_lock = Lock()


def get_conn() -> sqlite3.Connection:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def _connect():
    conn = get_conn()
    try:
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    with _lock, _connect() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                plan TEXT NOT NULL DEFAULT 'free',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scan_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                scanned_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_unlocks (
                email TEXT NOT NULL,
                scan_id TEXT NOT NULL,
                PRIMARY KEY (email, scan_id)
            );
            CREATE TABLE IF NOT EXISTS revoked_tokens (
                token TEXT PRIMARY KEY,
                revoked_at TEXT NOT NULL,
                expires_at TEXT
            );
            CREATE TABLE IF NOT EXISTS scan_history (
                scan_id TEXT PRIMARY KEY,
                user_email TEXT NOT NULL,
                github_url TEXT NOT NULL,
                repo_name TEXT NOT NULL DEFAULT '',
                risk_score INTEGER NOT NULL DEFAULT 0,
                issue_count INTEGER NOT NULL DEFAULT 0,
                timestamp TEXT NOT NULL,
                result_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_scan_events_email_time
                ON scan_events (email, scanned_at);
            CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires
                ON revoked_tokens (expires_at);
            CREATE INDEX IF NOT EXISTS idx_scan_history_user_time
                ON scan_history (user_email, timestamp);
        """)
        # Migration: add expires_at to revoked_tokens for databases created
        # before token-pruning support. CREATE TABLE IF NOT EXISTS will not add
        # the column to a pre-existing table, so do it explicitly and safely.
        cols = {row[1] for row in conn.execute("PRAGMA table_info(revoked_tokens)").fetchall()}
        if "expires_at" not in cols:
            conn.execute("ALTER TABLE revoked_tokens ADD COLUMN expires_at TEXT")
        conn.commit()


def upsert_user(email: str, password_hash: str, salt: str, plan: str, created_at: str) -> None:
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT INTO users (email, password_hash, salt, plan, created_at) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(email) DO UPDATE SET password_hash=excluded.password_hash, salt=excluded.salt, plan=excluded.plan",
            (email, password_hash, salt, plan, created_at)
        )
        conn.commit()


def get_user(email: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    return dict(row) if row else None


def set_user_plan(email: str, plan: str) -> None:
    with _lock, _connect() as conn:
        conn.execute("UPDATE users SET plan = ? WHERE email = ?", (plan, email))
        conn.commit()


def add_scan_event(email: str, scanned_at: str) -> None:
    with _lock, _connect() as conn:
        conn.execute("INSERT INTO scan_events (email, scanned_at) VALUES (?, ?)", (email, scanned_at))
        conn.commit()


def delete_latest_scan_event(email: str) -> None:
    with _lock, _connect() as conn:
        conn.execute(
            "DELETE FROM scan_events WHERE id = ("
            "SELECT id FROM scan_events WHERE email = ? ORDER BY id DESC LIMIT 1)",
            (email,)
        )
        conn.commit()


def get_scan_events_after(email: str, after_iso: str) -> list[str]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT scanned_at FROM scan_events WHERE email = ? AND scanned_at >= ?",
            (email, after_iso)
        ).fetchall()
    return [r["scanned_at"] for r in rows]


def add_audit_unlock(email: str, scan_id: str) -> None:
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO audit_unlocks (email, scan_id) VALUES (?, ?)",
            (email, scan_id)
        )
        conn.commit()


def get_audit_unlocks(email: str) -> set[str]:
    with _connect() as conn:
        rows = conn.execute("SELECT scan_id FROM audit_unlocks WHERE email = ?", (email,)).fetchall()
    return {r["scan_id"] for r in rows}


def revoke_token(token: str, revoked_at: str, expires_at: str | None = None) -> None:
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO revoked_tokens (token, revoked_at, expires_at) VALUES (?, ?, ?)",
            (token, revoked_at, expires_at)
        )
        conn.commit()


def is_token_revoked(token: str) -> bool:
    with _connect() as conn:
        row = conn.execute("SELECT 1 FROM revoked_tokens WHERE token = ?", (token,)).fetchone()
    return row is not None


def prune_expired_revoked_tokens(now_iso: str | None = None) -> int:
    cutoff = now_iso or datetime.now(timezone.utc).isoformat()
    with _lock, _connect() as conn:
        cur = conn.execute(
            "DELETE FROM revoked_tokens WHERE expires_at IS NOT NULL AND expires_at <= ?",
            (cutoff,)
        )
        conn.commit()
        return int(cur.rowcount or 0)


def save_scan(user_email: str, scan_id: str, github_url: str, repo_name: str,
              risk_score: int, issue_count: int, timestamp: str, result_json: str) -> None:
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO scan_history "
            "(scan_id, user_email, github_url, repo_name, risk_score, issue_count, timestamp, result_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (scan_id, user_email, github_url, repo_name, risk_score, issue_count, timestamp, result_json),
        )
        conn.commit()


def list_scans_db(user_email: str, limit: int = 50) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT scan_id, github_url, repo_name, risk_score, issue_count, timestamp "
            "FROM scan_history WHERE user_email = ? ORDER BY timestamp DESC LIMIT ?",
            (user_email, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def get_scan_db(user_email: str, scan_id: str) -> str | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT result_json FROM scan_history WHERE scan_id = ? AND user_email = ?",
            (scan_id, user_email),
        ).fetchone()
    return row["result_json"] if row else None
