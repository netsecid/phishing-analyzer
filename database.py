import json
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "cases.db"


def _conn():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def _migrate_db():
    new_columns = [
        ("ai_verdict", "TEXT"),
        ("ai_confidence", "INTEGER"),
        ("ai_brand_impersonated", "TEXT"),
        ("ai_risk_indicators", "TEXT"),
        ("ai_summary", "TEXT"),
        ("ai_recommended_action", "TEXT"),
        ("takedown_data", "TEXT"),
    ]
    with _conn() as conn:
        for col, col_type in new_columns:
            try:
                conn.execute(f"ALTER TABLE cases ADD COLUMN {col} {col_type}")
            except Exception:
                pass


def init_db():
    with _conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                url             TEXT NOT NULL,
                timestamp       TEXT NOT NULL,
                title           TEXT,
                final_url       TEXT,
                status_code     INTEGER,
                screenshot_path TEXT,
                raw_headers     TEXT
            )
        """)
    _migrate_db()


def insert_case(*, url, timestamp, title, final_url, status_code, screenshot_path, raw_headers):
    with _conn() as conn:
        cur = conn.execute(
            """INSERT INTO cases
               (url, timestamp, title, final_url, status_code, screenshot_path, raw_headers)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (url, timestamp, title, final_url, status_code, screenshot_path, raw_headers),
        )
        return cur.lastrowid


def get_all_cases():
    with _conn() as conn:
        rows = conn.execute("SELECT * FROM cases ORDER BY id DESC").fetchall()
    return [_row_to_dict(r) for r in rows]


def get_case(case_id: int):
    with _conn() as conn:
        row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    return _row_to_dict(row) if row else None


def update_case_takedown(case_id: int, takedown: dict):
    with _conn() as conn:
        conn.execute(
            "UPDATE cases SET takedown_data = ? WHERE id = ?",
            (json.dumps(takedown), case_id),
        )


def update_case_ai_analysis(case_id: int, analysis: dict):
    with _conn() as conn:
        conn.execute(
            """UPDATE cases SET
               ai_verdict = ?, ai_confidence = ?, ai_brand_impersonated = ?,
               ai_risk_indicators = ?, ai_summary = ?, ai_recommended_action = ?
               WHERE id = ?""",
            (
                analysis.get("verdict"),
                analysis.get("confidence"),
                analysis.get("brand_impersonated"),
                json.dumps(analysis.get("risk_indicators") or []),
                analysis.get("summary"),
                analysis.get("recommended_action"),
                case_id,
            ),
        )


def _row_to_dict(row):
    d = dict(row)
    d["raw_headers"] = json.loads(d.get("raw_headers") or "{}")
    d["ai_risk_indicators"] = json.loads(d.get("ai_risk_indicators") or "[]")
    raw_td = d.get("takedown_data")
    d["takedown_data"] = json.loads(raw_td) if raw_td else None
    return d
