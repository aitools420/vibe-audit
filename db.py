import sqlite3
import os
import json
import uuid
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(__file__), "vibe_audit.db")


def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _conn() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS audits (
            id TEXT PRIMARY KEY,
            license_key TEXT,
            email TEXT,
            repo_url TEXT,
            repo_name TEXT,
            score INTEGER,
            grade TEXT,
            report_json TEXT,
            source_files TEXT,
            created_at TEXT
        )""")
        # Migrate: add source_files column if missing
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(audits)").fetchall()]
        if "source_files" not in cols:
            conn.execute("ALTER TABLE audits ADD COLUMN source_files TEXT")
            conn.commit()


def save_audit(license_key, email, repo_url, audit_result):
    audit_id = uuid.uuid4().hex[:12]
    with _conn() as conn:
        conn.execute(
            "INSERT INTO audits (id, license_key, email, repo_url, repo_name, score, grade, report_json, source_files, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                audit_id,
                license_key,
                email,
                repo_url,
                audit_result.repo_name,
                audit_result.score,
                audit_result.grade,
                json.dumps(audit_result.to_dict()),
                json.dumps(audit_result.key_file_contents),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
    return audit_id


def get_audit(audit_id):
    with _conn() as conn:
        row = conn.execute("SELECT * FROM audits WHERE id = ?", (audit_id,)).fetchone()
    return dict(row) if row else None


init_db()
