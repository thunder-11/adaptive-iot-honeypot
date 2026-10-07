#!/usr/bin/env python3
"""SOC dashboard and JSON APIs backed by the existing SQLite evidence store."""

from __future__ import annotations

import json
import sys
import time
from collections import Counter
from pathlib import Path

from flask import Flask, abort, jsonify, render_template, request

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from pi import db
from pi.config import addresses, integer, load_config, number
from pi.security import action_for_score, risk_level, split_categories

app = Flask(__name__)


def database_path() -> Path:
    return Path(app.config.get("DB_PATH", db.DEFAULT_DB))


def query(sql: str, parameters: tuple[object, ...] = ()) -> list[dict[str, object]]:
    return [dict(row) for row in db.rows(sql, parameters, database_path())]


def bounded_limit(default: int = 100) -> int:
    try:
        return max(1, min(500, int(request.args.get("limit", default))))
    except ValueError:
        return default


def current_risk(row: dict[str, object], config: dict[str, str]) -> dict[str, object]:
    ip = str(row["ip"])
    score = float(row.get("current_score", row.get("score", 0.0)))
    seen = float(row.get("last_seen", row.get("time", time.time())))
    score = max(0.0, score - (time.time() - seen) * number(config, "DECAY_POINTS_PER_SEC"))
    if ip in addresses(config, "WHITELIST_IPS"):
        score = min(score, number(config, "WHITELIST_MAX_ANOMALY_SCORE"))
    action = "decoy" if ip in addresses(config, "DECOY_FORCE_IPS") else action_for_score(
        score, number(config, "MEDIUM"), number(config, "HIGH"), number(config, "CRITICAL")
    )
    return {**row, "current_score": round(score, 2), "current_action": action,
            "risk_level": risk_level(score, number(config, "MEDIUM"),
                                     number(config, "HIGH"), number(config, "CRITICAL"))}


def attacker_rows() -> list[dict[str, object]]:
    config = load_config()
    values = query("SELECT * FROM attackers WHERE attack_count > 0 ORDER BY highest_risk DESC")
    return [current_risk(row, config) for row in values]


def stats_payload() -> dict[str, object]:
    attackers = attacker_rows()
    risk_distribution = Counter(str(row["risk_level"]) for row in attackers)
    attack_distribution: Counter[str] = Counter()
    for row in attackers:
        attack_distribution.update(split_categories(str(row["attack_types"])))
    session_count = query("SELECT COUNT(*) AS count FROM sessions")[0]["count"]
    decoy_hits = query("SELECT COUNT(*) AS count FROM decoy_messages")[0]["count"]
    return {
        "total_attackers": len(attackers),
        "high_critical": sum(1 for row in attackers if row["risk_level"] in {"HIGH", "CRITICAL"}),
        "sessions": session_count,
        "decoy_hits": decoy_hits,
        "risk_distribution": {name: risk_distribution.get(name, 0)
                              for name in ("LOW", "MEDIUM", "HIGH", "CRITICAL")},
        "attack_distribution": dict(attack_distribution),
        "generated_at": time.time(),
    }


def attacker_payload(ip: str) -> dict[str, object]:
    rows = query("SELECT * FROM attackers WHERE ip = ?", (ip,))
    if not rows:
        abort(404)
    attacker = current_risk(rows[0], load_config())
    attacker["timeline"] = query("SELECT rowid, * FROM events WHERE ip = ? ORDER BY time", (ip,))
    attacker["sessions"] = query("SELECT rowid, * FROM sessions WHERE ip = ? ORDER BY start", (ip,))
    attacker["decoy_messages"] = query(
        "SELECT rowid, * FROM decoy_messages WHERE ip = ? ORDER BY time", (ip,)
    )
    attacker["historical_behavior"] = json.loads(str(attacker["historical_behavior"]) or "[]")
    attacker["similar_attackers"] = query(
        "SELECT ip, fingerprint_label, highest_risk FROM attackers "
        "WHERE fingerprint = ? AND ip != ? AND attack_count > 0",
        (attacker["fingerprint"], ip),
    )
    return attacker


@app.route("/")
def index() -> str:
    return render_template("index.html", stats=stats_payload())


@app.get("/attackers")
def attackers_page() -> str:
    return render_template("attackers.html", attackers=attacker_rows())


@app.get("/attacker/<path:ip>")
def attacker_page(ip: str) -> str:
    return render_template("attacker.html", attacker=attacker_payload(ip))


@app.get("/events")
def events_page() -> str:
    events = query("SELECT rowid, * FROM events ORDER BY time DESC LIMIT 100")
    return render_template("events.html", events=events)


@app.get("/sessions")
def sessions_page() -> str:
    sessions = query("SELECT rowid, * FROM sessions ORDER BY start DESC LIMIT 100")
    return render_template("sessions.html", sessions=sessions)


@app.get("/api/stats")
def api_stats():
    return jsonify(stats_payload())


@app.get("/api/attackers")
def api_attackers():
    return jsonify(attacker_rows())


@app.get("/api/events")
def api_events():
    return jsonify(query("SELECT rowid, * FROM events ORDER BY time DESC LIMIT ?", (bounded_limit(),)))


@app.get("/api/sessions")
def api_sessions():
    return jsonify(query("SELECT rowid, * FROM sessions ORDER BY start DESC LIMIT ?", (bounded_limit(),)))


@app.get("/api/attacker/<path:ip>")
def api_attacker(ip: str):
    return jsonify(attacker_payload(ip))


@app.get("/api/risk/<path:ip>")
def api_risk(ip: str):
    rows = query("SELECT * FROM attackers WHERE ip = ?", (ip,))
    if not rows:
        abort(404)
    current = current_risk(rows[0], load_config())
    return jsonify({key: current[key] for key in (
        "ip", "current_score", "highest_risk", "current_action", "risk_level",
        "attack_types", "fingerprint", "fingerprint_label", "first_seen", "last_seen"
    )})


@app.get("/api/fingerprint/<path:label>")
def api_fingerprint(label: str):
    return jsonify(query(
        "SELECT ip, fingerprint, fingerprint_label, first_seen, last_seen, "
        "current_score, current_action, highest_risk FROM attackers "
        "WHERE fingerprint_label = ? ORDER BY first_seen",
        (label,),
    ))

if __name__ == "__main__":
    cfg = load_config()
    app.run(host="0.0.0.0", port=integer(cfg, "DASH_PORT"), debug=False)
