import json
from pathlib import Path

from pi.alerts import AlertManager
from pi.decoy.profiles import select_profile


def test_decoy_profile_auto_selection():
    name, profile = select_profile("auto", "office-thermostat-1")
    assert name == "thermostat"
    assert profile["firmware"]
    assert "home/thermostat/temperature" in profile["topics"]
    assert select_profile("smart_lock", "anything")[0] == "smart_lock"


def test_alert_log_and_cooldown():
    root = Path("work/alert-test")
    root.mkdir(parents=True, exist_ok=True)
    log = root / "alerts.log"
    log.unlink(missing_ok=True)
    manager = AlertManager({
        "ALERT_ENABLED": "true", "ALERT_MIN_ACTION": "restrict",
        "ALERT_WEBHOOK_URL": "", "ALERT_LOG_FILE": "alerts.log",
        "ALERT_COOLDOWN_SEC": "30",
    }, root)
    assert manager.emit({"ip": "10.0.0.2", "action": "restrict", "score": 45})
    assert not manager.emit({"ip": "10.0.0.2", "action": "restrict", "score": 46})
    assert not manager.emit({"ip": "10.0.0.3", "action": "throttle", "score": 25})
    payload = json.loads(log.read_text(encoding="utf-8"))
    assert payload["ip"] == "10.0.0.2"
