import json
from unittest.mock import Mock

import pytest

from pi import db
from pi.proxy.proxy import Proxy
from sim.sim_esp32 import DoorSimulator


@pytest.mark.parametrize("locked", [True, False])
def test_simulator_status_and_proxy_fallback_match_unlock_led(locked, tmp_path, monkeypatch):
    simulator = DoorSimulator.__new__(DoorSimulator)
    simulator.locked = locked
    simulator.client = Mock()
    simulator.publish_status()
    args, kwargs = simulator.client.publish.call_args
    status = json.loads(args[1])
    assert args[0] == "home/door/status"
    assert kwargs["retain"] is True
    assert status["locked"] is locked
    assert status["led_on"] is (not locked)

    database = tmp_path / "device.db"
    update_state = db.update_device_state
    monkeypatch.setattr(db, "update_device_state", lambda *args: update_state(*args, database))
    proxy = Proxy.__new__(Proxy)
    proxy.thingspeak = Mock()
    # Publishers omitting led_on follow the same convention.
    del status["led_on"]
    proxy.record_device_telemetry("127.0.0.1", "home/door/status", json.dumps(status))
    row = db.rows("SELECT * FROM device_state", path=database)[0]
    assert row["locked"] == int(locked)
    assert row["led_on"] == int(not locked)


@pytest.mark.parametrize("payload", ['{"locked":2}', '{"locked":true,"led_on":-1}',
                                     '{"locked":"false"}', '[]', 'null'])
def test_invalid_device_booleans_cannot_overwrite_status(payload, monkeypatch):
    update = Mock()
    monkeypatch.setattr(db, "update_device_state", update)
    proxy = Proxy.__new__(Proxy)
    proxy.thingspeak = Mock()
    proxy.record_device_telemetry("127.0.0.1", "home/door/status", payload)
    update.assert_not_called()
