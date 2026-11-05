"""Data layer of the example IT service desk: one SQLite database (real reads and writes).

The database path comes from HELPDESK_DB (default: ./helpdesk_data/helpdesk.db next to the
current working directory). It is created and seeded on first use.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

_LOCK = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY, full_name TEXT NOT NULL, email TEXT NOT NULL, department TEXT NOT NULL,
    locked INTEGER NOT NULL DEFAULT 0, password_hash TEXT NOT NULL, password_changed_at TEXT
);
CREATE TABLE IF NOT EXISTS assets (
    asset_id TEXT PRIMARY KEY, owner TEXT NOT NULL, kind TEXT NOT NULL, model TEXT NOT NULL, status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tickets (
    ticket_id TEXT PRIMARY KEY, username TEXT NOT NULL, summary TEXT NOT NULL, status TEXT NOT NULL,
    priority TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, resolution TEXT
);
CREATE TABLE IF NOT EXISTS kb_articles (
    article_id TEXT PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS outbox (
    message_id TEXT PRIMARY KEY, recipient TEXT NOT NULL, subject TEXT NOT NULL, body TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hardware_requests (
    request_id TEXT PRIMARY KEY, username TEXT NOT NULL, item TEXT NOT NULL, status TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""

SEED_USERS = [
    ("alice", "Alice Moreau", "alice@example.org", "finance", 0),
    ("bob", "Bob Tanaka", "bob@example.org", "engineering", 1),
    ("carol", "Carol Diaz", "carol@example.org", "sales", 0),
]
SEED_ASSETS = [
    ("LT-1001", "alice", "laptop", "ThinkPad T14", "in_service"),
    ("LT-1002", "bob", "laptop", "MacBook Pro 14", "in_service"),
    ("PR-2001", "carol", "printer", "LaserJet M404", "degraded"),
]
SEED_KB = [
    ("KB-1", "Reset a forgotten password", "Ask the service desk to reset it; a temporary password is issued."),
    ("KB-2", "VPN does not connect", "Check the client version, then restart the VPN service."),
    ("KB-3", "Printer shows offline", "Power-cycle the printer and check the network cable."),
]


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def db_path() -> Path:
    return Path(os.environ.get("HELPDESK_DB", Path.cwd() / "helpdesk_data" / "helpdesk.db"))


def connect() -> sqlite3.Connection:
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    with _LOCK:
        conn.executescript(SCHEMA)
        if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            conn.executemany(
                "INSERT INTO users (username, full_name, email, department, locked, password_hash) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                [(u, n, e, d, lk, hashlib.sha256(f"initial-{u}".encode()).hexdigest())
                 for u, n, e, d, lk in SEED_USERS])
            conn.executemany("INSERT INTO assets VALUES (?, ?, ?, ?, ?)", SEED_ASSETS)
            conn.executemany("INSERT INTO kb_articles VALUES (?, ?, ?)", SEED_KB)
            conn.commit()
    return conn


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"


def as_json(row: sqlite3.Row | None) -> dict | None:
    return None if row is None else {k: row[k] for k in row.keys()}


def dumps(value: object) -> str:
    return json.dumps(value, sort_keys=True)
