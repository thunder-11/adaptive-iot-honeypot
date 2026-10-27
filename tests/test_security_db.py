import json
import sqlite3
from pathlib import Path

import pytest

from pi import db
from pi.security import behavior_fingerprint, category_for_signal, risk_level


def test_database_context_closes_connection_after_commit_and_rollback(tmp_path):
    path = tmp_path / "handles.db"
    with db.connect(path) as connection:
        connection.execute("INSERT INTO system_state VALUES ('committed', 'yes')")
    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute("SELECT 1")
    with pytest.raises(RuntimeError):
        with db.connect(path) as failed:
            failed.execute("INSERT INTO system_state VALUES ('rolled-back', 'no')")
            raise RuntimeError("abort")
    assert db.system_state("committed", path) == "yes"
    assert db.system_state("rolled-back", path) == ""


def test_classification_risk_and_fingerprint_are_explainable():
    assert category_for_signal("failed_auth") == "Brute Force"
    assert category_for_signal("topic_enumeration") == "MQTT Enumeration"
    assert risk_level(41, 21, 41, 51) == "HIGH"
    first = behavior_fingerprint(["Brute Force"], ["failed_auth"] * 3, ["username=admin"])
    second = behavior_fingerprint(["Brute Force"], ["failed_auth"] * 3, ["username=root"])
    assert first == second
    assert first[1] == "credential-bruteforcer"
    rotating_a = behavior_fingerprint(
        ["Reconnaissance"], ["wildcard_subscription"],
        ["route=real client=sensor-001 connect_flags=0x02 keepalive=60 clean_session=1 will=0"],
    )
    rotating_b = behavior_fingerprint(
        ["Reconnaissance"], ["wildcard_subscription", "wildcard_subscription"],
        ["route=real client=sensor-947 connect_flags=0x02 keepalive=60 clean_session=1 will=0"],
    )
    assert rotating_a == rotating_b


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
