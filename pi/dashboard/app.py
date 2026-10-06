#!/usr/bin/env python3
"""Read-only Flask dashboard for scores, routing, and decoy activity."""

from __future__ import annotations

import sys
import time
from pathlib import Path

from flask import Flask, render_template

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from pi import db
from pi.config import addresses, integer, load_config, number

app = Flask(__name__)


@app.route("/")
def index() -> str:
    config = load_config()
    stored_scores = db.rows("""
        SELECT e.ip, e.score, e.action, e.time, e.detail
        FROM events e
        JOIN (SELECT ip, MAX(rowid) AS newest FROM events GROUP BY ip) latest
          ON latest.newest = e.rowid
        ORDER BY e.score DESC
    """)
    whitelist = addresses(config, "WHITELIST_IPS")
    forced = addresses(config, "DECOY_FORCE_IPS")
    now = time.time()
    scores = []
    for row in stored_scores:
        current = 0.0 if row["ip"] in whitelist else max(
            0.0, row["score"] - (now - row["time"]) * number(config, "DECAY_POINTS_PER_SEC")
        )
        if row["ip"] in forced or current >= number(config, "HIGH"):
            action = "decoy"
        elif current >= number(config, "MEDIUM"):
            action = "throttle"
        else:
            action = "allow"
        scores.append({**dict(row), "score": current, "action": action})
    events = db.rows("SELECT * FROM events ORDER BY time DESC LIMIT 100")
    sessions = db.rows("SELECT rowid, * FROM sessions ORDER BY start DESC LIMIT 50")
    messages = db.rows("SELECT * FROM decoy_messages ORDER BY time DESC LIMIT 100")
    return render_template("index.html", scores=scores, events=events,
                           sessions=sessions, messages=messages)


if __name__ == "__main__":
    cfg = load_config()
    app.run(host="0.0.0.0", port=integer(cfg, "DASH_PORT"), debug=False)
