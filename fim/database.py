"""SQLite persistence layer.

All SQL uses bound parameters. Dynamic parts (sort columns, filters) are
selected from explicit allowlists, never interpolated from user input.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS monitored_directories (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    label            TEXT    NOT NULL DEFAULT '',
    path             TEXT    NOT NULL UNIQUE,
    category         TEXT    NOT NULL DEFAULT 'other',
    created_at       TEXT    NOT NULL,
    last_baseline_at TEXT,
    last_scan_at     TEXT
);

CREATE TABLE IF NOT EXISTS file_baselines (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    directory_id INTEGER NOT NULL REFERENCES monitored_directories(id) ON DELETE CASCADE,
    rel_path     TEXT    NOT NULL,
    sha256       TEXT    NOT NULL CHECK (length(sha256) = 64),
    size         INTEGER NOT NULL CHECK (size >= 0),
    mtime_ns     INTEGER,
    baseline_at  TEXT    NOT NULL,
    UNIQUE (directory_id, rel_path)
);
CREATE INDEX IF NOT EXISTS idx_baselines_dir ON file_baselines(directory_id);

CREATE TABLE IF NOT EXISTS scan_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    directory_id  INTEGER NOT NULL REFERENCES monitored_directories(id) ON DELETE CASCADE,
    started_at    TEXT    NOT NULL,
    finished_at   TEXT,
    status        TEXT    NOT NULL CHECK (status IN ('RUNNING','COMPLETED','PARTIAL','FAILED')),
    trigger_type  TEXT    NOT NULL DEFAULT 'MANUAL' CHECK (trigger_type IN ('MANUAL','PERIODIC')),
    total_files   INTEGER NOT NULL DEFAULT 0,
    unchanged     INTEGER NOT NULL DEFAULT 0,
    modified      INTEGER NOT NULL DEFAULT 0,
    new_files     INTEGER NOT NULL DEFAULT 0,
    deleted       INTEGER NOT NULL DEFAULT 0,
    errors        INTEGER NOT NULL DEFAULT 0,
    message       TEXT
);
CREATE INDEX IF NOT EXISTS idx_scan_dir ON scan_history(directory_id, id);

CREATE TABLE IF NOT EXISTS scan_results (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       INTEGER NOT NULL REFERENCES scan_history(id) ON DELETE CASCADE,
    directory_id  INTEGER NOT NULL REFERENCES monitored_directories(id) ON DELETE CASCADE,
    rel_path      TEXT    NOT NULL,
    status        TEXT    NOT NULL CHECK (status IN ('UNCHANGED','MODIFIED','NEW','DELETED','ERROR')),
    previous_hash TEXT,
    current_hash  TEXT,
    size          INTEGER,
    error         TEXT
);
CREATE INDEX IF NOT EXISTS idx_results_scan ON scan_results(scan_id);

CREATE TABLE IF NOT EXISTS security_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT    NOT NULL,
    directory_id  INTEGER REFERENCES monitored_directories(id) ON DELETE SET NULL,
    directory_path TEXT,
    rel_path      TEXT,
    category      TEXT    NOT NULL CHECK (category IN
                    ('FILE_CHANGE','INSPECTION_ERROR','SCAN_FAILURE','BASELINE_CHANGE','SERVICE_ERROR')),
    change_type   TEXT,
    previous_hash TEXT,
    current_hash  TEXT,
    scan_id       INTEGER REFERENCES scan_history(id) ON DELETE SET NULL,
    description   TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_time ON security_events(timestamp DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_events_cat ON security_events(category);

CREATE TABLE IF NOT EXISTS application_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

DEFAULT_SETTINGS = {
    "periodic_enabled": "0",
    "scan_interval_seconds": "300",
}


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


def connect(db_path: str | Path) -> sqlite3.Connection:
    """Open a connection with foreign keys enforced. Caller must close it."""
    conn = sqlite3.connect(str(db_path), timeout=15, isolation_level=None)  # explicit transactions
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db(db_path: str | Path) -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = connect(db_path)
    try:
        conn.executescript(SCHEMA)
        now = utcnow()
        for key, value in DEFAULT_SETTINGS.items():
            conn.execute(
                "INSERT OR IGNORE INTO application_settings (key, value, updated_at) VALUES (?, ?, ?)",
                (key, value, now),
            )
    finally:
        conn.close()


def get_db() -> sqlite3.Connection:
    """Per-request connection stored on flask.g."""
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE"])
    return g.db


def close_db(_exc=None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def get_setting(conn: sqlite3.Connection, key: str) -> str:
    row = conn.execute("SELECT value FROM application_settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else DEFAULT_SETTINGS.get(key, "")


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO application_settings (key, value, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        (key, value, utcnow()),
    )


def add_event(conn, *, category: str, description: str, directory_id=None, directory_path=None,
              rel_path=None, change_type=None, previous_hash=None, current_hash=None,
              scan_id=None) -> int:
    cur = conn.execute(
        "INSERT INTO security_events (timestamp, directory_id, directory_path, rel_path, category, "
        "change_type, previous_hash, current_hash, scan_id, description) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (utcnow(), directory_id, directory_path, rel_path, category, change_type,
         previous_hash, current_hash, scan_id, description),
    )
    return cur.lastrowid


def check_database(conn: sqlite3.Connection) -> str:
    try:
        row = conn.execute("PRAGMA integrity_check").fetchone()
        return "OK" if row and row[0] == "ok" else "PROBLEM DETECTED"
    except sqlite3.Error:
        return "UNAVAILABLE"
