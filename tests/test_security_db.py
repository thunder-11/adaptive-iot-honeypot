import json
from pathlib import Path

from pi import db
from pi.security import behavior_fingerprint, category_for_signal, risk_level


def test_classification_risk_and_fingerprint_are_explainable():
    assert category_for_signal("failed_auth") == "Brute Force"
    assert category_for_signal("topic_enumeration") == "MQTT Enumeration"
    assert risk_level(41, 21, 41, 51) == "HIGH"
    first = behavior_fingerprint(["Brute Force"], ["failed_auth"] * 3, ["username=admin"])
    second = behavior_fingerprint(["Brute Force"], ["failed_auth"] * 3, ["username=root"])
    assert first == second
    assert first[1] == "credential-bruteforcer"


def test_database_migration_and_persistent_attacker_history():
    path = Path("work/test-security.db")
    path.parent.mkdir(exist_ok=True)
    for candidate in (path, Path(str(path) + "-wal"), Path(str(path) + "-shm")):
        candidate.unlink(missing_ok=True)
    db.add_event(10, "10.0.0.2", "throttle", 24, "failed auth", path,
                 category="Brute Force", signal="failed_auth", points=8,
                 response_latency_ms=2.5)
    db.add_event(11, "10.0.0.2", "restrict", 45, "topic enumeration", path,
                 category="MQTT Enumeration", signal="topic_enumeration", points=12)
    attacker = db.rows("SELECT * FROM attackers", path=path)[0]
    assert attacker["first_seen"] == 10
    assert attacker["last_seen"] == 11
    assert attacker["attack_count"] == 2
    assert attacker["highest_risk"] == 45
    assert set(attacker["attack_types"].split(", ")) == {"Brute Force", "MQTT Enumeration"}
    assert len(json.loads(attacker["historical_behavior"])) == 2
    session = db.start_session("10.0.0.2", "decoy", 12, path, profile="smart_lock")
    db.end_session(session, 13, path)
    assert db.rows("SELECT profile FROM sessions", path=path)[0]["profile"] == "smart_lock"
