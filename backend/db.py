"""SQLite persistence layer.

Plain sqlite3 (stdlib) on purpose: zero ORM magic, every query is readable,
and the whole register lives in one file that can be backed up or handed to an
auditor.
"""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

DATA_DIR = Path(os.environ.get("NGRR_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))
DB_PATH = Path(os.environ.get("NGRR_DB_PATH", DATA_DIR / "register.db"))
EVIDENCE_DIR = DATA_DIR / "evidence"

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    role TEXT NOT NULL,
    title TEXT
);

CREATE TABLE IF NOT EXISTS appetite (
    category TEXT PRIMARY KEY,
    max_residual_score INTEGER NOT NULL,
    max_ale REAL NOT NULL,
    statement TEXT
);

CREATE TABLE IF NOT EXISTS risks (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    business_impact TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL,
    asset TEXT NOT NULL DEFAULT '',
    threat_source TEXT NOT NULL DEFAULT '',
    vulnerability TEXT NOT NULL DEFAULT '',
    owner TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'Identified',
    inherent_likelihood INTEGER NOT NULL,
    inherent_impact INTEGER NOT NULL,
    residual_likelihood INTEGER,
    residual_impact INTEGER,
    residual_override INTEGER NOT NULL DEFAULT 0,
    lef_min REAL, lef_likely REAL, lef_max REAL,
    lm_min REAL, lm_likely REAL, lm_max REAL,
    cvss REAL,
    attack_techniques TEXT NOT NULL DEFAULT '[]',
    framework_refs TEXT NOT NULL DEFAULT '[]',
    tags TEXT NOT NULL DEFAULT '[]',
    scenario_key TEXT,
    review_frequency_days INTEGER NOT NULL DEFAULT 90,
    last_reviewed_at TEXT,
    created_by TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS controls (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    control_type TEXT NOT NULL DEFAULT 'Preventive',
    implementation_status TEXT NOT NULL DEFAULT 'Not Implemented',
    effectiveness INTEGER NOT NULL DEFAULT 50,
    evidence_tier INTEGER NOT NULL DEFAULT 1,
    evidence_source TEXT NOT NULL DEFAULT '',
    owner TEXT NOT NULL DEFAULT '',
    last_tested_at TEXT,
    framework_refs TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS risk_controls (
    risk_id TEXT NOT NULL REFERENCES risks(id) ON DELETE CASCADE,
    control_id TEXT NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
    PRIMARY KEY (risk_id, control_id)
);

CREATE TABLE IF NOT EXISTS treatments (
    id TEXT PRIMARY KEY,
    risk_id TEXT NOT NULL REFERENCES risks(id) ON DELETE CASCADE,
    strategy TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    owner TEXT NOT NULL DEFAULT '',
    due_date TEXT,
    status TEXT NOT NULL DEFAULT 'Planned',
    progress INTEGER NOT NULL DEFAULT 0,
    cost REAL,
    completed_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS kris (
    id TEXT PRIMARY KEY,
    risk_id TEXT NOT NULL REFERENCES risks(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    unit TEXT NOT NULL DEFAULT '',
    direction TEXT NOT NULL DEFAULT 'above_is_bad',
    warning REAL NOT NULL,
    critical REAL NOT NULL,
    current_value REAL,
    source TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS kri_readings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kri_id TEXT NOT NULL REFERENCES kris(id) ON DELETE CASCADE,
    ts TEXT NOT NULL,
    value REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS acceptances (
    id TEXT PRIMARY KEY,
    risk_id TEXT NOT NULL REFERENCES risks(id) ON DELETE CASCADE,
    accepted_by TEXT NOT NULL,
    role TEXT NOT NULL,
    rationale TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Active',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    stored_name TEXT NOT NULL,
    tier INTEGER NOT NULL DEFAULT 1,
    note TEXT NOT NULL DEFAULT '',
    uploaded_by TEXT NOT NULL,
    uploaded_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    role TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_log(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_treat_risk ON treatments(risk_id);
CREATE INDEX IF NOT EXISTS idx_kri_risk ON kris(risk_id);
"""


def connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    conn = connect()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


@contextmanager
def session() -> Iterator[sqlite3.Connection]:
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def row_to_dict(row: sqlite3.Row | None, json_fields: tuple[str, ...] = ()) -> dict[str, Any] | None:
    if row is None:
        return None
    d = dict(row)
    for f in json_fields:
        if f in d and isinstance(d[f], str):
            try:
                d[f] = json.loads(d[f])
            except json.JSONDecodeError:
                d[f] = []
    return d


def next_id(conn: sqlite3.Connection, table: str, prefix: str, width: int = 4) -> str:
    row = conn.execute(f"SELECT id FROM {table} WHERE id LIKE ? ORDER BY id DESC LIMIT 1", (f"{prefix}-%",)).fetchone()
    n = 0
    if row:
        try:
            n = int(row["id"].split("-")[-1])
        except ValueError:
            n = 0
    return f"{prefix}-{n + 1:0{width}d}"


def get_setting(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
