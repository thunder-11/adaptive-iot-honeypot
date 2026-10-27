#!/usr/bin/env python3
"""SOC dashboard and JSON APIs backed by the existing SQLite evidence store."""

from __future__ import annotations

import csv
import io
import json
import math
import sqlite3
import sys
import time
import zipfile
from collections import Counter
from pathlib import Path

from flask import Flask, Response, abort, g, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from pi import db
from pi.analysis.evaluate import first_high_critical_latencies, percentile
from pi.config import addresses, integer, load_config, number
from pi.security import action_for_score, risk_level, split_categories
from pi.alerts import ACTION_ORDER
from pi.decoy.profiles import load_profiles

app = Flask(__name__)


@app.teardown_appcontext
def close_dashboard_connection(_error=None):
    connection = g.pop("dashboard_connection", None)
    if connection is not None:
        connection.close()


@app.after_request
def fresh_evidence(response):
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.errorhandler(HTTPException)
def request_error(error):
    if request.path.startswith("/api/"):
        return jsonify({"error": error.description}), error.code
    return render_template("error.html", code=error.code, message=error.description), error.code


@app.errorhandler(sqlite3.Error)
def evidence_error(error):
    app.logger.error("Evidence database unavailable: %s", error)
    if request.path.startswith("/api/"):
        return jsonify({"error": "Evidence database unavailable. Retry shortly."}), 503
    return render_template("error.html", code=503,
                           message="Evidence database unavailable. Retry shortly."), 503


@app.context_processor
def console_context():
    return {"console_profiles": load_profiles(), "console_page": {
        "index": "Overview", "attackers_page": "Attackers", "attacker_page": "Attacker detail",
        "events_page": "Events & Alerts", "alerts_page": "Security Alerts",
        "sessions_page": "Sessions", "honeypot_page": "Honeypot / Decoy",
        "policy_page": "Response Policy", "settings_page": "Settings",
    }.get(request.endpoint, "SOC Console")}


def database_path() -> Path:
    return Path(app.config.get("DB_PATH", db.DEFAULT_DB))


def query(sql: str, parameters: tuple[object, ...] = ()) -> list[dict[str, object]]:
    # One read transaction per request keeps counters coherent during concurrent
    # proxy writes/resets and avoids repeating schema checks for every SELECT.
    if "dashboard_connection" not in g:
        connection = db.connect(database_path())
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN")
        g.dashboard_connection = connection
    return [dict(row) for row in g.dashboard_connection.execute(sql, parameters)]


def evidence_generation():
    rows = query("SELECT value FROM system_state WHERE key = 'score_reset'")
    return str(rows[0]["value"]) if rows else ""


def bounded_limit(default: int = 100) -> int:
    try:
        return max(1, min(500, int(request.args.get("limit", default))))
    except ValueError:
        return default


def bounded_nonnegative(name: str, default: int = 0) -> int:
    try:
        return max(0, int(request.args.get(name, default)))
    except ValueError:
        return default


def current_risk(row: dict[str, object], config: dict[str, str]) -> dict[str, object]:
    ip = str(row["ip"])
    score = float(row.get("current_score", row.get("score", 0.0)))
    seen = float(row.get("last_seen", row.get("time", time.time())))
    score = max(0.0, score - max(0.0, time.time() - seen) * number(config, "DECAY_POINTS_PER_SEC"))
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
    values = query("SELECT *, (SELECT MAX(time) FROM events WHERE events.ip = attackers.ip) "
                   "AS last_observed FROM attackers WHERE attack_count > 0 ORDER BY highest_risk DESC")
    return [current_risk(row, config) for row in values]


def alert_actions() -> list[str]:
    minimum = load_config().get("ALERT_MIN_ACTION", "restrict")
    return [name for name, rank in ACTION_ORDER.items()
            if rank >= ACTION_ORDER.get(minimum, ACTION_ORDER["restrict"])]


def alert_rows(limit: int = 100) -> list[dict[str, object]]:
    actions = alert_actions()
    placeholders = ",".join("?" for _ in actions)
    return query(
        f"SELECT rowid, * FROM events WHERE action IN ({placeholders}) "
        "ORDER BY rowid DESC LIMIT ?",
        (*actions, limit),
    )


def stats_payload() -> dict[str, object]:
    config = load_config()
    attackers = attacker_rows()
    risk_distribution = Counter(str(row["risk_level"]) for row in attackers)
    attack_distribution: Counter[str] = Counter()
    for row in attackers:
        attack_distribution.update(split_categories(str(row["attack_types"])))
    attack_event_distribution = {
        row["category"]: row["count"] for row in query(
            "SELECT category, COUNT(*) AS count FROM events "
            "WHERE category != '' GROUP BY category ORDER BY category"
        )
    }
    session_count = query("SELECT COUNT(*) AS count FROM sessions")[0]["count"]
    decoy_hits = query("SELECT COUNT(*) AS count FROM decoy_messages")[0]["count"]
    response_events = query(
        "SELECT time, ip, action FROM events "
        "WHERE action IN ('restrict', 'decoy') ORDER BY time"
    )
    first_seen = {str(row["ip"]): float(row["first_seen"]) for row in attackers}
    response_latencies = first_high_critical_latencies(response_events, first_seen)
    device_rows = query("SELECT * FROM device_state WHERE id = 1")
    device_age = max(0.0, time.time() - device_rows[0]["time"]) if device_rows else None
    cloud_rows = query("SELECT * FROM cloud_status WHERE id = 1")
    return {
        "total_attackers": len(attackers),
        "high_critical": sum(1 for row in attackers if row["risk_level"] in {"HIGH", "CRITICAL"}),
        "sessions": session_count,
        "decoy_hits": decoy_hits,
        "decoy_sessions": query("SELECT COUNT(*) AS count FROM sessions WHERE backend = 'decoy'")[0]["count"],
        "risk_distribution": {name: risk_distribution.get(name, 0)
                              for name in ("LOW", "MEDIUM", "HIGH", "CRITICAL")},
        "attack_distribution": dict(attack_distribution),
        "classified_events": sum(attack_event_distribution.values()),
        "attack_event_distribution": attack_event_distribution,
        "first_high_critical_latency_ms": {
            "p50": percentile(response_latencies, 0.50),
            "p95": percentile(response_latencies, 0.95),
            "samples": len(response_latencies),
        },
        "device_state": device_rows[0] if device_rows else None,
        "device_age_seconds": round(device_age, 1) if device_age is not None else None,
        "device_online": device_age is not None and device_age <= 30,
        "thingspeak_status": cloud_rows[0] if cloud_rows else None,
        "thingspeak_enabled": config.get("THINGSPEAK_ENABLED", "false").lower()
        in {"1", "true", "yes", "on"} and bool(config.get("THINGSPEAK_WRITE_API_KEY", "").strip()),
        "generated_at": time.time(),
    }


def attacker_payload(ip: str, record_limit: int | None = None) -> dict[str, object]:
    rows = query("SELECT *, (SELECT MAX(time) FROM events WHERE events.ip = attackers.ip) "
                 "AS last_observed FROM attackers WHERE ip = ?", (ip,))
    if not rows:
        abort(404)
    attacker = current_risk(rows[0], load_config())
    if record_limit is None and "limit" in request.args:
        record_limit = bounded_limit()
    for key, table, time_column in (("timeline", "events", "time"),
                                    ("sessions", "sessions", "start"),
                                    ("decoy_messages", "decoy_messages", "time")):
        if record_limit is not None:
            values = query(f"SELECT rowid, * FROM {table} WHERE ip = ? "
                           f"ORDER BY {time_column} DESC, rowid DESC LIMIT ?", (ip, record_limit))
            attacker[key] = list(reversed(values))
        else:
            attacker[key] = query(f"SELECT rowid, * FROM {table} WHERE ip = ? "
                                  f"ORDER BY {time_column}, rowid", (ip,))
    attacker["historical_behavior"] = json.loads(str(attacker["historical_behavior"]) or "[]")
    attacker["similar_attackers"] = query(
        "SELECT ip, fingerprint_label, highest_risk FROM attackers "
        "WHERE fingerprint = ? AND ip != ? AND attack_count > 0",
        (attacker["fingerprint"], ip),
    )
    return attacker


def event_filters():
    clauses, parameters = [], []
    for key, column in (("ip", "ip"), ("category", "category"), ("action", "action")):
        value = request.args.get(key, "").strip()
        if value:
            clauses.append(f"{column} = ?")
            parameters.append(value)
    risk = request.args.get("risk", "")
    if risk:
        risk_action = {"LOW": "allow", "MEDIUM": "throttle", "HIGH": "restrict", "CRITICAL": "decoy"}
        if risk not in risk_action:
            abort(400, description="Unknown risk level")
        clauses.append("action = ?")
        parameters.append(risk_action[risk])
    since = request.args.get("since")
    if since:
        try:
            value = float(since)
            if not math.isfinite(value) or value < 0:
                raise ValueError
        except ValueError:
            abort(400, description="since must be a finite, nonnegative Unix timestamp")
        clauses.append("time >= ?")
        parameters.append(value)
    return clauses, parameters


@app.get("/api/event-feed")
def api_event_feed():
    clauses, parameters = event_filters()
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    total = query("SELECT COUNT(*) AS count FROM events" + where, tuple(parameters))[0]["count"]
    before = bounded_nonnegative("before")
    if before:
        clauses.append("rowid < ?")
        parameters.append(before)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    limit = bounded_limit()
    rows = query("SELECT rowid, * FROM events" + where + " ORDER BY rowid DESC LIMIT ?",
                 (*parameters, limit + 1))
    has_more = len(rows) > limit
    rows = rows[:limit]
    return jsonify({"events": rows, "total": total, "has_more": has_more,
                    "next_before": rows[-1]["rowid"] if has_more else None,
                    "generation": evidence_generation()})


@app.get("/api/health")
def api_health():
    query("SELECT 1")
    latest = query("SELECT MAX(time) AS time FROM events")[0]["time"]
    return jsonify({"status": "ok", "database": "connected", "latest_event": latest,
                    "generated_at": time.time(), "alert_min_action": load_config().get("ALERT_MIN_ACTION", "throttle"),
                    "note": "API and evidence database status; does not assert MQTT services are running."})


@app.route("/")
def index() -> str:
    return render_template("index.html", stats=stats_payload())


@app.get("/attackers")
def attackers_page() -> str:
    return render_template("attackers.html", attackers=attacker_rows())


@app.get("/attacker/<path:ip>")
def attacker_page(ip: str) -> str:
    # Keep initial page loads bounded too; full evidence remains exportable.
    return render_template("attacker.html", attacker=attacker_payload(ip, record_limit=100))


@app.get("/events")
def events_page() -> str:
    events = query("SELECT rowid, * FROM events ORDER BY time DESC LIMIT 100")
    return render_template("events.html", events=events)


@app.get("/alerts")
def alerts_page() -> str:
    return render_template("alerts.html", alerts=alert_rows())


@app.get("/sessions")
def sessions_page() -> str:
    sessions = query("SELECT rowid, * FROM sessions ORDER BY start DESC LIMIT 100")
    return render_template("sessions.html", sessions=sessions)


@app.get("/honeypot")
def honeypot_page():
    return render_template("honeypot.html", data=honeypot_payload())


def honeypot_payload():
    return {"profiles": load_profiles(),
            "sessions": query("SELECT rowid, * FROM sessions WHERE backend = 'decoy' ORDER BY start DESC LIMIT 100"),
            "messages": query("SELECT rowid, * FROM decoy_messages ORDER BY time DESC LIMIT 100"),
            "routing": {row["backend"]: row["count"] for row in query(
                "SELECT backend, COUNT(*) AS count FROM sessions GROUP BY backend")}}


@app.get("/api/honeypot")
def api_honeypot():
    return jsonify(honeypot_payload())


def policy_payload():
    config = load_config()
    signals = [
        ("failed_auth", "WEIGHT_FAILED_AUTH", "Rejected authentication; capped by FAILED_AUTH_CAP."),
        ("connection_rate", "WEIGHT_CONNECTION_RATE", "Connections exceed the rolling window limit."),
        ("publish_rate", "WEIGHT_PUBLISH_RATE", "Publishes exceed the rolling window limit."),
        ("wildcard_subscription", "WEIGHT_WILDCARD_SUBSCRIBE", "Broad wildcard topic subscription."),
        ("topic_enumeration", "WEIGHT_TOPIC_ENUMERATION", "Distinct topic filters exceed the configured limit."),
        ("suspicious_publish", "WEIGHT_COMMAND_PUBLISH", "Publish to the protected home/door/lock command topic."),
        ("malformed_packet", "WEIGHT_MALFORMED_PACKET", "Invalid MQTT framing or suspicious payload."),
        ("short_session", "WEIGHT_SHORT_SESSION", "Repeated short sessions; points are capped."),
        ("command_sequence", "WEIGHT_COMMAND_SEQUENCE", "Wildcard reconnaissance followed by a command."),
        ("blacklist", "WEIGHT_BLACKLIST", "Source IP is explicitly blacklisted."),
        ("decoy_engagement", "WEIGHT_DECOY_ENGAGEMENT", "First interaction with the decoy."),
    ]
    keys = {key for _, key, _ in signals} | {
        "MEDIUM", "HIGH", "CRITICAL", "THROTTLE_DELAY_SEC", "THROTTLE_PACKET_DELAY_SEC",
        "DECAY_POINTS_PER_SEC", "CONNECTION_LIMIT", "CONNECTION_WINDOW_SEC", "PUBLISH_LIMIT",
        "PUBLISH_WINDOW_SEC", "FAILED_AUTH_CAP", "SHORT_SESSION_CAP", "WHITELIST_MAX_ANOMALY_SCORE",
        "ALERT_MIN_ACTION", "TOPIC_ENUMERATION_LIMIT", "DECOY_PROFILE",
    }
    return {"config": {key: config[key] for key in keys}, "signals": signals}


@app.get("/policy")
def policy_page():
    payload = policy_payload()
    return render_template("policy.html", policy=payload["config"], signals=payload["signals"])


@app.get("/api/policy")
def api_policy():
    return jsonify(policy_payload())


@app.get("/settings")
def settings_page():
    return render_template("settings.html")


@app.get("/api/stats")
def api_stats():
    return jsonify(stats_payload())


@app.get("/api/attackers")
def api_attackers():
    return jsonify(attacker_rows())


@app.get("/api/events")
def api_events():
    return jsonify(query("SELECT rowid, * FROM events ORDER BY time DESC LIMIT ?", (bounded_limit(),)))


@app.get("/api/alerts")
def api_alerts():
    """Return newly recorded high-severity events for dashboard notifications."""
    after = bounded_nonnegative("after")
    actions = alert_actions()
    placeholders = ",".join("?" for _ in actions)
    cursor_rows = query("SELECT COALESCE(MAX(rowid), 0) AS cursor FROM events")
    cursor = int(cursor_rows[0]["cursor"])
    generation = evidence_generation()
    if "after" not in request.args:
        return jsonify({"cursor": cursor, "events": [], "generation": generation})
    # SQLite may reuse rowids after the Clear logs action empties the table.
    if cursor < after or ("generation" in request.args and request.args["generation"] != generation):
        after = 0
    events = query(
        f"SELECT rowid, * FROM events WHERE rowid > ? AND action IN ({placeholders}) "
        "ORDER BY rowid LIMIT 20",
        (after, *actions),
    )
    return jsonify({"cursor": max([after, *[int(row["rowid"]) for row in events]]),
                    "events": events, "generation": generation})


@app.get("/api/alerts/history")
def api_alert_history():
    return jsonify(alert_rows(bounded_limit()))


def spreadsheet_safe(value: object) -> object:
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def csv_bytes(columns: tuple[str, ...], records: list[dict[str, object]]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(columns)
    for row in records:
        writer.writerow([spreadsheet_safe(row.get(column, "")) for column in columns])
    return output.getvalue().encode("utf-8-sig")


@app.get("/api/events/export.csv")
def export_events_csv():
    columns = ("time", "ip", "risk", "category", "signal", "points", "score",
               "action", "detail", "response_latency_ms")
    action_risks = {"allow": "LOW", "throttle": "MEDIUM", "restrict": "HIGH", "decoy": "CRITICAL"}
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(columns)
    clauses, parameters = event_filters()
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    for row in query("SELECT * FROM events" + where + " ORDER BY time", tuple(parameters)):
        values = {**row, "risk": action_risks.get(str(row["action"]), "")}
        writer.writerow([spreadsheet_safe(values.get(column, "")) for column in columns])
    return Response(
        output.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=honeypot-attack-events.csv"},
    )


@app.get("/api/evidence/export.zip")
def export_evidence_zip():
    """Export a complete, portable evidence bundle for the project demonstration."""
    action_risks = {"allow": "LOW", "throttle": "MEDIUM", "restrict": "HIGH", "decoy": "CRITICAL"}
    event_rows = query("SELECT rowid, * FROM events ORDER BY time")
    for row in event_rows:
        row["risk"] = action_risks.get(str(row["action"]), "")
    datasets = {
        "events.csv": (
            ("rowid", "time", "ip", "risk", "category", "signal", "points", "score",
             "action", "detail", "response_latency_ms"), event_rows,
        ),
        "attackers.csv": (
            ("ip", "first_seen", "last_seen", "attack_count", "highest_risk",
             "current_score", "current_action", "attack_types", "fingerprint",
             "fingerprint_label"),
            query("SELECT * FROM attackers ORDER BY first_seen"),
        ),
        "sessions.csv": (
            ("rowid", "ip", "backend", "start", "end", "profile"),
            query("SELECT rowid, * FROM sessions ORDER BY start"),
        ),
        "decoy_messages.csv": (
            ("rowid", "time", "ip", "topic", "payload"),
            query("SELECT rowid, * FROM decoy_messages ORDER BY time"),
        ),
        "device_state.csv": (
            ("time", "ip", "locked", "led_on", "source"),
            query("SELECT time, ip, locked, led_on, source FROM device_state"),
        ),
        "thingspeak_status.csv": (
            ("last_attempt", "last_success", "entry_id", "error"),
            query("SELECT last_attempt, last_success, entry_id, error FROM cloud_status"),
        ),
    }
    archive_buffer = io.BytesIO()
    with zipfile.ZipFile(archive_buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for filename, (columns, records) in datasets.items():
            archive.writestr(filename, csv_bytes(columns, records))
        alert_path = ROOT / load_config().get("ALERT_LOG_FILE", "logs/alerts.log")
        if alert_path.is_file():
            archive.writestr("alerts.jsonl", alert_path.read_bytes())
    return Response(
        archive_buffer.getvalue(), mimetype="application/zip",
        headers={"Content-Disposition": "attachment; filename=honeypot-evidence.zip"},
    )


@app.post("/api/logs/clear")
def clear_logs():
    payload = request.get_json(silent=True) or {}
    if payload.get("confirm") != "clear":
        return jsonify({"error": "confirmation required"}), 400
    db.clear_evidence(database_path())
    config = load_config()
    alert_path = ROOT / config.get("ALERT_LOG_FILE", "logs/alerts.log")
    try:
        alert_path.parent.mkdir(parents=True, exist_ok=True)
        alert_path.write_text("", encoding="utf-8")
    except OSError:
        app.logger.exception("could not clear alert log")
    return jsonify({"cleared": True})


@app.get("/api/sessions")
def api_sessions():
    clauses, parameters = [], []
    for key in ("ip", "backend"):
        value = request.args.get(key)
        if value:
            clauses.append(f"{key} = ?")
            parameters.append(value)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    return jsonify(query("SELECT rowid, * FROM sessions" + where + " ORDER BY start DESC LIMIT ?",
                         (*parameters, bounded_limit())))


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
