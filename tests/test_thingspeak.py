from pi.thingspeak import ThingSpeakClient


def test_thingspeak_requires_enable_and_write_key():
    assert not ThingSpeakClient({"THINGSPEAK_ENABLED": "false"}).enabled
    assert not ThingSpeakClient({"THINGSPEAK_ENABLED": "true"}).enabled


def test_thingspeak_accepts_configured_channel():
    results = []
    client = ThingSpeakClient({
        "THINGSPEAK_ENABLED": "true",
        "THINGSPEAK_WRITE_API_KEY": "test-key",
        "THINGSPEAK_INTERVAL_SEC": "1",
    }, on_result=lambda success, message: results.append((success, message)))
    assert client.enabled
    # Do not enqueue a value: this validates configuration without network I/O.
    assert client.interval == 15.0
    client._report(True, "42")
    assert results == [(True, "42")]
