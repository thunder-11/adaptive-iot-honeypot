"""SQLite persistence shared by the proxy, dashboard, decoy, and analyzer."""

from __future__ import annotations

import sqlite3
import json
from pathlib import Path
from typing import Iterable

from pi.security import behavior_fingerprint, split_categories

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = ROOT / "data" / "honeypot.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    time REAL NOT NULL,
    ip TEXT NOT NULL,
    action TEXT NOT NULL,
    score REAL NOT NULL,
    detail TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT '',
    signal TEXT NOT NULL DEFAULT '',
    points REAL NOT NULL DEFAULT 0,
    response_latency_ms REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_events_ip_time ON events(ip, time);
CREATE TABLE IF NOT EXISTS sessions (
    ip TEXT NOT NULL,
    backend TEXT NOT NULL,
    start REAL NOT NULL,
    end REAL,
    profile TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sessions_ip_start ON sessions(ip, start);
CREATE TABLE IF NOT EXISTS decoy_messages (
    time REAL NOT NULL,
    ip TEXT NOT NULL,
    topic TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_decoy_ip_time ON decoy_messages(ip, time);
CREATE TABLE IF NOT EXISTS attackers (
    ip TEXT PRIMARY KEY,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    attack_count INTEGER NOT NULL DEFAULT 0,
    highest_risk REAL NOT NULL DEFAULT 0,
    current_score REAL NOT NULL DEFAULT 0,
    current_action TEXT NOT NULL DEFAULT 'allow',
    attack_types TEXT NOT NULL DEFAULT '',
    fingerprint TEXT NOT NULL DEFAULT '',
    fingerprint_label TEXT NOT NULL DEFAULT 'low-information',
    historical_behavior TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS device_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    time REAL NOT NULL,
    ip TEXT NOT NULL,
    locked INTEGER NOT NULL,
    led_on INTEGER NOT NULL,
    source TEXT NOT NULL DEFAULT ''
);
"""

EVENT_COLUMNS = {
    "category": "TEXT NOT NULL DEFAULT ''",
    "signal": "TEXT NOT NULL DEFAULT ''",
    "points": "REAL NOT NULL DEFAULT 0",
    "response_latency_ms": "REAL NOT NULL DEFAULT 0",
}
SESSION_COLUMNS = {"profile": "TEXT NOT NULL DEFAULT ''"}


def connect(path: Path = DEFAULT_DB) -> sqlite3.Connection:
    """Open a concurrency-friendly database connection and ensure the schema."""
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=5.0)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA busy_timeout=5000")
    connection.executescript(SCHEMA)
    _ensure_columns(connection, "events", EVENT_COLUMNS)
    _ensure_columns(connection, "sessions", SESSION_COLUMNS)
    connection.commit()
    return connection


def _ensure_columns(connection: sqlite3.Connection, table: str,
                    columns: dict[str, str]) -> None:
    """Apply additive migrations so existing demo databases remain usable."""
    existing = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
    for name, definition in columns.items():
        if name not in existing:
            connection.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")


def add_event(time_value: float, ip: str, action: str, score: float, detail: str,
              path: Path = DEFAULT_DB, *, category: str = "", signal: str = "",
              points: float = 0.0, response_latency_ms: float = 0.0) -> None:
    with connect(path) as connection:
        connection.execute(
            """INSERT INTO events(time, ip, action, score, detail, category, signal,
                                   points, response_latency_ms)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (time_value, ip, action, score, detail, category, signal, points,
             response_latency_ms),
        )
        _update_attacker(connection, time_value, ip, action, score, detail, category, signal)


def _update_attacker(connection: sqlite3.Connection, time_value: float, ip: str,
                     action: str, score: float, detail: str, category: str,
                     signal: str) -> None:
    existing = connection.execute("SELECT * FROM attackers WHERE ip = ?", (ip,)).fetchone()
    if existing:
        columns = [item[1] for item in connection.execute("PRAGMA table_info(attackers)")]
        current = dict(zip(columns, existing))
        history = json.loads(current["historical_behavior"] or "[]")
        types = set(split_categories(current["attack_types"]))
        first_seen = current["first_seen"]
        attack_count = current["attack_count"] + (1 if category else 0)
        highest = max(float(current["highest_risk"]), score)
    else:
        history, types = [], set()
        first_seen, attack_count, highest = time_value, (1 if category else 0), score
    types.update(split_categories(category))
    history.append({
        "time": time_value, "action": action, "score": round(score, 3),
        "category": category, "signal": signal, "detail": detail[:300],
    })
    history = history[-200:]
    recent = connection.execute(
        "SELECT category, signal, detail FROM events WHERE ip = ? ORDER BY time DESC LIMIT 100",
        (ip,),
    ).fetchall()
    categories = [item for row in recent for item in split_categories(row[0] or "")]
    signals = [row[1] for row in recent if row[1]]
    details = [row[2] for row in recent]
    fingerprint, label = behavior_fingerprint(categories, signals, details)
    connection.execute(
        """INSERT INTO attackers(ip, first_seen, last_seen, attack_count, highest_risk,
                                 current_score, current_action, attack_types, fingerprint,
                                 fingerprint_label, historical_behavior)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(ip) DO UPDATE SET
             last_seen=excluded.last_seen, attack_count=excluded.attack_count,
             highest_risk=excluded.highest_risk, current_score=excluded.current_score,
             current_action=excluded.current_action, attack_types=excluded.attack_types,
             fingerprint=excluded.fingerprint, fingerprint_label=excluded.fingerprint_label,
             historical_behavior=excluded.historical_behavior""",
        (ip, first_seen, time_value, attack_count, highest, score, action,
         ", ".join(sorted(types)), fingerprint, label, json.dumps(history)),
    )


def start_session(ip: str, backend: str, time_value: float,
                  path: Path = DEFAULT_DB, profile: str = "") -> int:
    with connect(path) as connection:
        cursor = connection.execute(
            "INSERT INTO sessions(ip, backend, start, end, profile) VALUES (?, ?, ?, NULL, ?)",
            (ip, backend, time_value, profile),
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


def restore_scores(path: Path = DEFAULT_DB) -> list[sqlite3.Row]:
    return rows(
        "SELECT ip, current_score, last_seen FROM attackers WHERE current_score > 0",
        path=path,
    )


def checkpoint_scores(scores: Iterable[tuple[float, str, float, str]],
                      path: Path = DEFAULT_DB) -> None:
    """Persist live risk without adding synthetic evidence events."""
    with connect(path) as connection:
        connection.executemany(
            """UPDATE attackers
               SET last_seen = ?, current_score = ?, current_action = ?
               WHERE ip = ?""",
            ((seen, score, action, ip) for seen, ip, score, action in scores),
        )


def update_device_state(time_value: float, ip: str, locked: bool, led_on: bool,
                        source: str, path: Path = DEFAULT_DB) -> None:
    """Store the last state confirmed by the whitelisted real device."""
    with connect(path) as connection:
        connection.execute(
            """INSERT INTO device_state(id, time, ip, locked, led_on, source)
               VALUES (1, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET time=excluded.time, ip=excluded.ip,
                 locked=excluded.locked, led_on=excluded.led_on, source=excluded.source""",
            (time_value, ip, int(locked), int(led_on), source[:100]),
        )


def clear_evidence(path: Path = DEFAULT_DB) -> None:
    """Clear recorded security evidence without changing live device state."""
    with connect(path) as connection:
        for table in ("events", "sessions", "decoy_messages", "attackers"):
            connection.execute(f"DELETE FROM {table}")

