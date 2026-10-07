from pathlib import Path
import time

from pi import db
from pi.dashboard.app import app


def test_dashboard_pages_and_json_apis():
    path = Path("work/test-dashboard.db")
    path.parent.mkdir(exist_ok=True)
    for candidate in (path, Path(str(path) + "-wal"), Path(str(path) + "-shm")):
        candidate.unlink(missing_ok=True)
    now = time.time()
    db.add_event(now, "10.0.0.9", "decoy", 60, "wildcard subscribe: #", path,
                 category="Reconnaissance", signal="wildcard_subscription", points=25)
    db.start_session("10.0.0.9", "decoy", now, path, profile="smart_lock")
    db.add_decoy_message(now + 1, "10.0.0.9", "home/door/lock", "unlock", path)
    app.config.update(TESTING=True, DB_PATH=str(path))
    client = app.test_client()
    pages = ("/", "/attackers", "/events", "/sessions", "/attacker/10.0.0.9")
    for route in pages:
        page = client.get(route)
        assert page.status_code == 200
        assert b'id="theme-toggle"' in page.data
        assert b"localStorage" in page.data
    assert b"SOC Console" in client.get("/").data
    assert client.get("/attacker/192.0.2.99").status_code == 404
    assert client.get("/api/attacker/192.0.2.99").status_code == 404
    stats = client.get("/api/stats").get_json()
    assert stats["total_attackers"] == 1
    assert stats["sessions"] == 1
    assert stats["decoy_hits"] == 1
    assert stats["high_critical"] == 1
    assert client.get("/api/events").status_code == 200
    assert client.get("/api/sessions").status_code == 200
    attacker = client.get("/api/attacker/10.0.0.9").get_json()
    assert attacker["timeline"][0]["signal"] == "wildcard_subscription"
    assert attacker["decoy_messages"][0]["payload"] == "unlock"
    assert client.get("/api/risk/10.0.0.9").get_json()["highest_risk"] == 60
    matches = client.get(f"/api/fingerprint/{attacker['fingerprint_label']}").get_json()
    assert [row["ip"] for row in matches] == ["10.0.0.9"]
