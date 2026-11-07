"""
Unified findings store for the SOAR dashboard.
All agents (API mapper, nmap/CVE scanner, reporter, future agents) read and
write to this single SQLite file instead of passing data to each other
directly. This means any single agent can be run in isolation as long as
the data it needs is already in the DB.
"""
 
import sqlite3
import json
import os
from datetime import datetime
from contextlib import contextmanager
 
DB_PATH = os.environ.get(
    "SOAR_DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "soar.db"),
)
 
SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    target TEXT,
    agent TEXT NOT NULL,
    finding_type TEXT NOT NULL,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL
);
 
CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT
);
 
CREATE TABLE IF NOT EXISTS cve_cache (
    query TEXT PRIMARY KEY,
    response TEXT NOT NULL,
    cached_at TEXT NOT NULL
);
 
CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(finding_type);
"""
 
 
@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
 
 
def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)
 
 
def add_finding(session_id, agent, finding_type, data, target=None):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO findings (session_id, target, agent, finding_type, data, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (
                session_id,
                target,
                agent,
                finding_type,
                json.dumps(data),
                datetime.utcnow().isoformat(),
            ),
        )
 
 
def get_findings(session_id=None, finding_type=None, target=None):
    query = "SELECT * FROM findings WHERE 1=1"
    params = []
    if session_id:
        query += " AND session_id = ?"
        params.append(session_id)
    if finding_type:
        query += " AND finding_type = ?"
        params.append(finding_type)
    if target:
        query += " AND target = ?"
        params.append(target)
    query += " ORDER BY created_at ASC"
    with get_conn() as conn:
        rows = conn.execute(query, params).fetchall()
    return [{**dict(r), "data": json.loads(r["data"])} for r in rows]
 
 
def get_sessions():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT DISTINCT session_id FROM findings ORDER BY session_id"
        ).fetchall()
    return [r["session_id"] for r in rows]
 
 
def get_targets(session_id, finding_type=None):
    query = "SELECT DISTINCT target FROM findings WHERE session_id=? AND target IS NOT NULL"
    params = [session_id]
    if finding_type:
        query += " AND finding_type=?"
        params.append(finding_type)
    with get_conn() as conn:
        rows = conn.execute(query, params).fetchall()
    return sorted(r["target"] for r in rows)
 
 
def set_config(key, value):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO config (key, value) VALUES (?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
 
 
def get_config(key, default=None):
    with get_conn() as conn:
        row = conn.execute("SELECT value FROM config WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default
 
 
def cve_cache_get(query, max_age_days=7):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT response, cached_at FROM cve_cache WHERE query=?", (query,)
        ).fetchone()
    if not row:
        return None
    cached_at = datetime.fromisoformat(row["cached_at"])
    if (datetime.utcnow() - cached_at).days > max_age_days:
        return None
    return json.loads(row["response"])
 
 
def cve_cache_set(query, response):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO cve_cache (query, response, cached_at) VALUES (?,?,?) "
            "ON CONFLICT(query) DO UPDATE SET response=excluded.response, cached_at=excluded.cached_at",
            (query, json.dumps(response), datetime.utcnow().isoformat()),
        )
 
