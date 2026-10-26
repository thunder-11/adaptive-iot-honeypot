from pathlib import Path
import io
import time
import zipfile

from pi import db
from pi.dashboard.app import app


def test_dashboard_pages_and_json_apis():
    path = Path("work/test-dashboard.db")
    path.parent.mkdir(exist_ok=True)
    for candidate in (path, Path(str(path) + "-wal"), Path(str(path) + "-shm")):
        candidate.unlink(missing_ok=True)
    now = time.time()
    db.add_event(now, "10.0.0.9", "allow", 0, "connection opened", path)
    db.add_event(now + 1, "10.0.0.9", "decoy", 60, "wildcard subscribe: #", path,
                 category="Reconnaissance", signal="wildcard_subscription", points=25)
    db.start_session("10.0.0.9", "decoy", now, path, profile="smart_lock")
    db.add_decoy_message(now + 1, "10.0.0.9", "home/door/lock", "unlock", path)
    db.update_device_state(now + 2, "127.0.0.1", True, True, "test-esp32", path)
    db.update_cloud_status(True, "12345", now + 2, path)
    app.config.update(TESTING=True, DB_PATH=str(path))
    client = app.test_client()
    pages = ("/", "/attackers", "/events", "/alerts", "/sessions", "/attacker/10.0.0.9",
             "/honeypot", "/policy", "/settings")
    for route in pages:
        page = client.get(route)
        assert page.status_code == 200
        assert b'id="theme-toggle"' in page.data
        assert b"localStorage" in page.data
    assert b"SOC Console" in client.get("/").data
    assert b"Security Alerts" in client.get("/alerts").data
    assert client.get("/attacker/192.0.2.99").status_code == 404
    assert client.get("/api/attacker/192.0.2.99").status_code == 404
    stats = client.get("/api/stats").get_json()
    assert stats["total_attackers"] == 1
    assert stats["sessions"] == 1
    assert stats["decoy_hits"] == 1
    assert stats["decoy_sessions"] == 1
    assert stats["classified_events"] == 1
    assert stats["attack_event_distribution"] == {"Reconnaissance": 1}
    assert stats["high_critical"] == 1
    assert stats["first_high_critical_latency_ms"] == {
        "p50": 1000.0, "p95": 1000.0, "samples": 1,
    }
    assert stats["device_state"]["locked"] == 1
    assert stats["thingspeak_status"]["entry_id"] == "12345"
    assert b"First response p95" in client.get("/").data
    assert client.get("/api/events").status_code == 200
    alert_start = client.get("/api/alerts").get_json()
    assert alert_start["events"] == []
    alerts = client.get("/api/alerts?after=0").get_json()
    assert alerts["events"][0]["action"] == "decoy"
    assert client.get("/api/alerts/history").get_json()[0]["action"] == "decoy"
    exported = client.get("/api/events/export.csv")
    assert exported.status_code == 200
    assert "honeypot-attack-events.csv" in exported.headers["Content-Disposition"]
    assert b"wildcard_subscription" in exported.data
    evidence = client.get("/api/evidence/export.zip")
    assert evidence.status_code == 200
    assert "honeypot-evidence.zip" in evidence.headers["Content-Disposition"]
    with zipfile.ZipFile(io.BytesIO(evidence.data)) as archive:
        assert set(archive.namelist()) >= {
            "events.csv", "attackers.csv", "sessions.csv", "decoy_messages.csv",
            "device_state.csv", "thingspeak_status.csv",
        }
        assert b"wildcard_subscription" in archive.read("events.csv")
    assert client.get("/api/sessions").status_code == 200
    decoy = client.get("/api/honeypot").get_json()
    assert decoy["routing"] == {"decoy": 1}
    assert decoy["profiles"]["smart_lock"]["device_name"] == "SecureDoor SL-200"
    assert decoy["messages"][0]["payload"] == "unlock"
    assert decoy["sessions"][0]["profile"] == "smart_lock"
    policy = client.get("/policy").data
    assert b"wildcard_subscription" in policy
    assert b"Scores are not globally capped at 100" in policy
    assert b"REAL_PASS" not in policy
    for asset in ("console.css", "console.js"):
        assert client.get(f"/static/{asset}").status_code == 200
    attacker = client.get("/api/attacker/10.0.0.9").get_json()
    assert attacker["timeline"][1]["signal"] == "wildcard_subscription"
    assert attacker["decoy_messages"][0]["payload"] == "unlock"
    assert client.get("/api/risk/10.0.0.9").get_json()["highest_risk"] == 60
    matches = client.get(f"/api/fingerprint/{attacker['fingerprint_label']}").get_json()
    assert [row["ip"] for row in matches] == ["10.0.0.9"]
    assert client.post("/api/logs/clear", json={}).status_code == 400
    assert client.post("/api/logs/clear", json={"confirm": "clear"}).status_code == 200
    assert client.get("/api/events").get_json() == []
    assert db.system_state("score_reset", path)
    assert client.get("/api/stats").get_json()["device_state"]["source"] == "test-esp32"
    db.add_event(now + 3, "10.0.0.10", "restrict", 45, "new alert", path,
                 category="Authentication Attack", signal="failed_auth", points=8)
    after_clear = client.get(f"/api/alerts?after={alert_start['cursor']}").get_json()
    assert [event["detail"] for event in after_clear["events"]] == ["new alert"]
