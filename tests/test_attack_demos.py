"""Exercise demo traffic through the real proxy, broker, database and HTTP API."""

import asyncio
import json
import shutil
import socket
import subprocess
import sys
import threading
import time

import pytest
from werkzeug.serving import make_server

from attacker import demo
from pi import db
from pi.config import load_config
from pi.dashboard.app import app
from pi.proxy.proxy import Proxy


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_individual_demos_produce_verified_evidence(tmp_path, monkeypatch):
    broker = shutil.which("mosquitto")
    passwd = shutil.which("mosquitto_passwd")
    if not broker or not passwd:
        pytest.skip("Native Mosquitto tools are required for the live demo integration test")
    backend_port = free_port()
    password_file = tmp_path / "passwords"
    subprocess.run([passwd, "-b", "-c", str(password_file), "lab", "lab-secret"], check=True)
    conf = tmp_path / "broker.conf"
    conf.write_text(f"listener {backend_port} 127.0.0.1\nallow_anonymous false\n"
                    f"password_file {password_file.as_posix()}\npersistence false\n", encoding="utf-8")
    config = load_config() | {
        "PI_IP": "127.0.0.1", "PROXY_PORT": "0", "REAL_PORT": str(backend_port),
        "REAL_USER": "lab", "REAL_PASS": "lab-secret", "REAL_HOST": "127.0.0.1",
        "WHITELIST_IPS": "127.0.0.1", "BLACKLIST_IPS": "", "DECOY_FORCE_IPS": "",
        "TLS_CERT_PATH": "", "TLS_KEY_PATH": "", "ALERT_ENABLED": "false",
        "THINGSPEAK_ENABLED": "false", "SHORT_SESSION_SEC": "0.1",
        "THROTTLE_DELAY_SEC": "0.01", "THROTTLE_PACKET_DELAY_SEC": "0.001",
    }
    database = tmp_path / "evidence.db"
    original_connect = db.connect
    monkeypatch.setattr(db, "connect", lambda path=db.DEFAULT_DB: original_connect(
        database if path == db.DEFAULT_DB else path))
    monkeypatch.setitem(app.config, "DB_PATH", str(database))
    monkeypatch.setattr(demo, "load_config", lambda: config)
    http = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()

    async def exercise():
        proxy = Proxy(config)
        server = await asyncio.start_server(proxy.handle_client, "127.0.0.1", 0)
        config["PROXY_PORT"] = str(server.sockets[0].getsockname()[1])
        try:
            for name, (signal, ip) in demo.SCENARIOS.items():
                output = tmp_path / f"{name}.json"
                monkeypatch.setattr(sys, "argv", [name, "--dashboard-url",
                    f"http://127.0.0.1:{http.server_port}", "--output", str(output)])
                result = await asyncio.to_thread(demo.main, name)
                report = json.loads(output.read_text(encoding="utf-8"))
                assert result == 0, report
                assert report["verified"]
                assert report["source_ip"] == ip
                if signal:
                    assert report["observed_signals"][signal] > 0
                    assert report["attack_count_delta"] > 0
                else:
                    assert report["attack_count_delta"] == 0
            stats = app.test_client().get("/api/stats").get_json()
            assert stats["total_attackers"] == 8
            assert len(stats["attack_event_distribution"]) == 6
            assert stats["classified_events"] == sum(stats["attack_event_distribution"].values())
            before = stats["classified_events"]
            # Same IP: new events, stable unique-attacker count.
            await asyncio.to_thread(demo.run_traffic, "command_spoofing", config, "127.0.0.5")
            await asyncio.sleep(0.2)
            after = app.test_client().get("/api/stats").get_json()
            assert after["total_attackers"] == 8
            assert after["classified_events"] > before
        finally:
            server.close()
            await server.wait_closed()
            await asyncio.sleep(0.2)

    with (tmp_path / "broker.log").open("w") as log:
        process = subprocess.Popen([broker, "-c", str(conf), "-v"], stdout=log, stderr=log)
        try:
            for _ in range(150):
                try:
                    with socket.create_connection(("127.0.0.1", backend_port), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                pytest.fail(f"Test broker did not start (exit={process.poll()}): "
                            f"{(tmp_path / 'broker.log').read_text()}")
            asyncio.run(exercise())
        finally:
            process.terminate()
            process.wait(timeout=5)
            http.shutdown()
            thread.join(timeout=5)
            http.server_close()


@pytest.mark.parametrize("scenario", ["brute_force", "benign"])
def test_demo_does_not_claim_success_without_expected_evidence(tmp_path, monkeypatch, scenario):
    config = load_config() | {"PI_IP": "127.0.0.1"}
    monkeypatch.setattr(demo, "load_config", lambda: config)
    monkeypatch.setattr(demo, "run_traffic", lambda *args: None)
    # Benign control must also fail if a classified event is observed.
    baseline = {"attack_count": 0, "timeline": []}
    after = {"attack_count": 1, "current_score": 3, "timeline": [
        {"rowid": 1, "signal": "short_session", "category": "Reconnaissance"}]}
    calls = iter([baseline, after])
    monkeypatch.setattr(demo, "snapshot", lambda *args: next(calls))
    monkeypatch.setattr(demo.time, "monotonic", iter([0, 9]).__next__)
    output = tmp_path / "failed.json"
    monkeypatch.setattr(sys, "argv", [scenario, "--output", str(output)])
    assert demo.main(scenario) == 1
    assert json.loads(output.read_text())["verified"] is False
