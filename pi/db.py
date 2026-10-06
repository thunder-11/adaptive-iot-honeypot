"""SQLite persistence shared by the proxy, dashboard, decoy, and analyzer."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = ROOT / "data" / "honeypot.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    time REAL NOT NULL,
    ip TEXT NOT NULL,
    action TEXT NOT NULL,
    score REAL NOT NULL,
    detail TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ip_time ON events(ip, time);
CREATE TABLE IF NOT EXISTS sessions (
    ip TEXT NOT NULL,
    backend TEXT NOT NULL,
    start REAL NOT NULL,
    end REAL
);
CREATE INDEX IF NOT EXISTS idx_sessions_ip_start ON sessions(ip, start);
CREATE TABLE IF NOT EXISTS decoy_messages (
    time REAL NOT NULL,
    ip TEXT NOT NULL,
    topic TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_decoy_ip_time ON decoy_messages(ip, time);
"""


def connect(path: Path = DEFAULT_DB) -> sqlite3.Connection:
    """Open a concurrency-friendly database connection and ensure the schema."""
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=5.0)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA busy_timeout=5000")
    connection.executescript(SCHEMA)
    connection.commit()
    return connection


def add_event(time_value: float, ip: str, action: str, score: float, detail: str,
              path: Path = DEFAULT_DB) -> None:
    with connect(path) as connection:
        connection.execute(
            "INSERT INTO events(time, ip, action, score, detail) VALUES (?, ?, ?, ?, ?)",
            (time_value, ip, action, score, detail),
        )


def start_session(ip: str, backend: str, time_value: float,
                  path: Path = DEFAULT_DB) -> int:
    with connect(path) as connection:
        cursor = connection.execute(
            "INSERT INTO sessions(ip, backend, start, end) VALUES (?, ?, ?, NULL)",
            (ip, backend, time_value),
        )
        return int(cursor.lastrowid)


def end_session(session_id: int, time_value: float, path: Path = DEFAULT_DB) -> None:
    with connect(path) as connection:
        connection.execute("UPDATE sessions SET end = ? WHERE rowid = ?", (time_value, session_id))


def add_decoy_message(time_value: float, ip: str, topic: str, payload: str,
                      path: Path = DEFAULT_DB) -> None:
    with connect(path) as connection:
        connection.execute(
            "INSERT INTO decoy_messages(time, ip, topic, payload) VALUES (?, ?, ?, ?)",
            (time_value, ip, topic, payload),
        )


def rows(query: str, parameters: Iterable[object] = (),
         path: Path = DEFAULT_DB) -> list[sqlite3.Row]:
    """Return rows as mappings for read-only callers."""
    connection = connect(path)
    connection.row_factory = sqlite3.Row
    try:
        return list(connection.execute(query, tuple(parameters)))
    finally:
        connection.close()

