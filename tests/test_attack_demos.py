"""Exercise demo traffic through the real proxy, broker, database and HTTP API."""

import asyncio
import json
import shutil
import socket
import subprocess
import sys
import threading
import time
from unittest.mock import Mock

import pytest
from werkzeug.serving import make_server

from attacker import attack, demo
from pi import db
from pi.config import load_config
from pi.dashboard.app import app
from pi.proxy.proxy import Proxy


def test_combined_demo_accepts_fragmented_connack(monkeypatch):
    sock = Mock()
    sock.recv.side_effect = [b"\x20", b"\x02\x00", b"\x05"]
    monkeypatch.setattr(attack, "open_socket", lambda *args: sock)
    assert attack.reconnect("127.0.0.1", 1883, "127.0.0.20", b"connect", attempts=1) is sock
    sock.close.assert_not_called()


def test_combined_demo_closes_failed_socket_before_retry(monkeypatch):
    sock = Mock()
    sock.recv.side_effect = TimeoutError("slow broker")
    monkeypatch.setattr(attack, "open_socket", lambda *args: sock)
    monkeypatch.setattr(attack.time, "sleep", lambda *args: None)
    with pytest.raises(RuntimeError):
        attack.reconnect("127.0.0.1", 1883, "127.0.0.20", b"connect", attempts=1)
    sock.close.assert_called_once()


def test_local_trial_skips_used_and_reserved_sources(monkeypatch):
    config = load_config() | {"WHITELIST_IPS": "127.0.1.2", "BLACKLIST_IPS": "127.0.2.2",
                              "DECOY_FORCE_IPS": "127.0.3.2"}
    clean = {"timeline": [], "attack_count": 0, "current_score": 0}
    seen = []

    def evidence(_url, ip):
        seen.append(ip)
        return {**clean, "attack_count": 13, "current_score": 110} if ip == "127.0.0.2" else clean

    monkeypatch.setattr(demo, "snapshot", evidence)
    source, before = demo.fresh_loopback_source("http://lab", "127.0.0.2", config)
    assert source == "127.0.4.2"
    assert before == clean
    assert seen == ["127.0.0.2", "127.0.4.2"]


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
    decoy_port = free_port()
    password_file = tmp_path / "passwords"
    subprocess.run([passwd, "-b", "-c", str(password_file), "lab", "lab-secret"], check=True)
    conf = tmp_path / "broker.conf"
    conf.write_text(f"listener {backend_port} 127.0.0.1\nallow_anonymous false\n"
                    f"password_file {password_file.as_posix()}\npersistence false\n", encoding="utf-8")
    decoy_conf = tmp_path / "decoy.conf"
    decoy_conf.write_text(f"listener {decoy_port} 127.0.0.1\nallow_anonymous true\npersistence false\n")
    config = load_config() | {
        "PI_IP": "127.0.0.1", "PROXY_PORT": "0", "REAL_PORT": str(backend_port),
        "DECOY_PORT": str(decoy_port), "DECOY_HOST": "127.0.0.1",
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
    monkeypatch.setattr(attack, "load_config", lambda: config)
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
            # A repeated automatic brute-force trial must use fresh risk/auth state.
            output = tmp_path / "brute-force-repeat.json"
            monkeypatch.setattr(sys, "argv", ["brute_force", "--dashboard-url",
                f"http://127.0.0.1:{http.server_port}", "--output", str(output)])
            assert await asyncio.to_thread(demo.main, "brute_force") == 0
            repeated = json.loads(output.read_text())
            assert repeated["source_ip"] == "127.0.1.2"
            assert repeated["observed_signals"]["failed_auth"] == 3
            final = app.test_client().get("/api/stats").get_json()
            assert final["total_attackers"] == 9
            assert final["attack_event_distribution"]["Brute Force"] == 6
            # A full combined attack stays in the decoy; the trusted subscriber
            # never receives its unlock, and legitimate control still works.
            device_reader, device_writer = await asyncio.open_connection(
                "127.0.0.1", int(config["PROXY_PORT"]))
            try:
                device_writer.write(attack.connect_packet("trusted-door", "lab", "lab-secret"))
                await device_writer.drain()
                assert await device_reader.readexactly(4) == b"\x20\x02\x00\x00"
                device_writer.write(attack.subscribe_packet("home/door/lock"))
                await device_writer.drain()
                assert (await device_reader.readexactly(5))[:2] == b"\x90\x03"
                monkeypatch.setattr(sys, "argv", ["attack", "--source-ip", "127.0.0.20"])
                await asyncio.to_thread(attack.main)
                evidence = app.test_client().get("/api/attacker/127.0.0.20").get_json()
                assert any(s["backend"] == "decoy" for s in evidence["sessions"])
                assert any(m["payload"] == "unlock" for m in evidence["decoy_messages"])
                with pytest.raises(asyncio.TimeoutError):
                    await asyncio.wait_for(device_reader.read(1), 0.2)
                device_writer.write(attack.publish_packet("home/door/lock", "lock"))
                await device_writer.drain()
                assert await asyncio.wait_for(device_reader.readexactly(22), 2) == attack.publish_packet("home/door/lock", "lock")
                trusted = app.test_client().get("/api/attacker/127.0.0.1").get_json()
                assert trusted["attack_count"] == 0
            finally:
                device_writer.close()
                await device_writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()
            await asyncio.sleep(0.2)

    with (tmp_path / "broker.log").open("w") as log:
        process = subprocess.Popen([broker, "-c", str(conf), "-v"], stdout=log, stderr=log)
        decoy_process = subprocess.Popen([broker, "-c", str(decoy_conf), "-v"], stdout=log, stderr=log)
        try:
            for _ in range(150):
                try:
                    with socket.create_connection(("127.0.0.1", backend_port), timeout=0.1), \
                         socket.create_connection(("127.0.0.1", decoy_port), timeout=0.1):
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
            decoy_process.terminate()
            decoy_process.wait(timeout=5)
            http.shutdown()
            thread.join(timeout=5)
            http.server_close()


@pytest.mark.parametrize("scenario", ["brute_force", "benign"])
def test_demo_does_not_claim_success_without_expected_evidence(tmp_path, monkeypatch, scenario):
    config = load_config() | {"PI_IP": "127.0.0.1"}
    monkeypatch.setattr(demo, "load_config", lambda: config)
    monkeypatch.setattr(demo, "run_traffic", lambda *args: None)
    # Benign control must also fail if a classified event is observed.
    baseline = {"attack_count": 0, "timeline": [], "current_score": 0}
    after = {"attack_count": 1, "current_score": 3, "timeline": [
        {"rowid": 1, "signal": "short_session", "category": "Reconnaissance"}]}
    calls = iter([baseline, after])
    monkeypatch.setattr(demo, "snapshot", lambda *args: next(calls))
    monkeypatch.setattr(demo.time, "monotonic", iter([0, 9]).__next__)
    output = tmp_path / "failed.json"
    monkeypatch.setattr(sys, "argv", [scenario, "--output", str(output)])
    assert demo.main(scenario) == 1
    assert json.loads(output.read_text())["verified"] is False
