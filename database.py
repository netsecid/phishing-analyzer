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
        ("response_body", "TEXT"),
        ("intel_data", "TEXT"),
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


def insert_case(*, url, timestamp, title, final_url, status_code, screenshot_path, raw_headers, response_body=None):
    with _conn() as conn:
        cur = conn.execute(
            """INSERT INTO cases
               (url, timestamp, title, final_url, status_code, screenshot_path, raw_headers, response_body)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (url, timestamp, title, final_url, status_code, screenshot_path, raw_headers, response_body),
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


def search_cases(query: str):
    q = f"%{query}%"
    with _conn() as conn:
        rows = conn.execute(
            """SELECT * FROM cases
               WHERE url LIKE ? OR final_url LIKE ? OR title LIKE ? OR ai_brand_impersonated LIKE ?
               ORDER BY id DESC""",
            (q, q, q, q),
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def find_cases_by_domain(domain: str):
    q = f"%{domain}%"
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM cases WHERE url LIKE ? OR final_url LIKE ? ORDER BY id DESC",
            (q, q),
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_stats():
    with _conn() as conn:
        total = conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
        verdicts = conn.execute(
            "SELECT ai_verdict, COUNT(*) as cnt FROM cases GROUP BY ai_verdict"
        ).fetchall()
        recent = conn.execute(
            """SELECT DATE(timestamp) as day, COUNT(*) as cnt
               FROM cases
               WHERE timestamp >= DATE('now', '-30 days')
               GROUP BY day ORDER BY day ASC"""
        ).fetchall()
    counts = {row["ai_verdict"]: row["cnt"] for row in verdicts}
    return {
        "total": total,
        "phishing": counts.get("phishing", 0),
        "suspicious": counts.get("suspicious", 0),
        "legitimate": counts.get("legitimate", 0),
        "inconclusive": counts.get("inconclusive", 0),
        "recent_by_day": [{"day": r["day"], "count": r["cnt"]} for r in recent],
    }


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


def update_case_intel(case_id: int, intel: dict):
    with _conn() as conn:
        conn.execute(
            "UPDATE cases SET intel_data = ? WHERE id = ?",
            (json.dumps(intel), case_id),
        )


def _row_to_dict(row):
    d = dict(row)
    d["raw_headers"] = json.loads(d.get("raw_headers") or "{}")
    d["ai_risk_indicators"] = json.loads(d.get("ai_risk_indicators") or "[]")
    raw_td = d.get("takedown_data")
    d["takedown_data"] = json.loads(raw_td) if raw_td else None
    raw_intel = d.get("intel_data")
    d["intel_data"] = json.loads(raw_intel) if raw_intel else None
    return d
