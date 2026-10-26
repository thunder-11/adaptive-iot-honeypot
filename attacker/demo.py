"""Small, bounded MQTT lab scenarios with verification against real evidence."""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import socket
import ssl
import sys
import time
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from attacker.attack import connect_packet, publish_packet, subscribe_packet
from pi.config import addresses, integer, load_config, number

# Separate loopback identities keep local experiments independent.
SCENARIOS = {
    "brute_force": ("failed_auth", "127.0.0.2"),
    "reconnaissance": ("wildcard_subscription", "127.0.0.3"),
    "topic_enumeration": ("topic_enumeration", "127.0.0.4"),
    "command_spoofing": ("suspicious_publish", "127.0.0.5"),
    "protocol_abuse": ("malformed_packet", "127.0.0.6"),
    "connection_flood": ("connection_rate", "127.0.0.7"),
    "publish_flood": ("publish_rate", "127.0.0.8"),
    "command_sequence": ("command_sequence", "127.0.0.9"),
    "benign": (None, "127.0.0.10"),
}


def snapshot(url: str, ip: str) -> dict:
    try:
        with urlopen(f"{url.rstrip('/')}/api/attacker/{quote(ip, safe='')}", timeout=5) as response:
            return json.load(response)
    except HTTPError as exc:
        if exc.code == 404:
            return {"timeline": [], "attack_count": 0, "current_score": 0}
        raise


def run_traffic(name: str, config: dict, source: str) -> None:
    host, port = config["PI_IP"], integer(config, "PROXY_PORT")

    def open_client():
        sock = socket.create_connection((host, port), timeout=8, source_address=(source, 0))
        if config.get("TLS_CERT_PATH"):
            cert = Path(config["TLS_CERT_PATH"])
            if not cert.is_absolute():
                cert = ROOT / cert
            try:
                sock = ssl.create_default_context(cafile=str(cert)).wrap_socket(sock, server_hostname=host)
            except Exception:
                sock.close()
                raise
        return sock

    def login(sock, index=0, wrong=False):
        password = config["REAL_PASS"] + "-demo-invalid" if wrong else config["REAL_PASS"]
        sock.sendall(connect_packet(f"lab-{name}-{index}", config["REAL_USER"], password))
        reply = bytearray()
        while len(reply) < 4:
            chunk = sock.recv(4 - len(reply))
            if not chunk:
                raise RuntimeError("Proxy disconnected before CONNACK; use a fresh source IP or clear demo scores.")
            reply.extend(chunk)
        expected = {4, 5} if wrong else {0}
        if reply[:2] != b"\x20\x02" or reply[3] not in expected:
            raise RuntimeError(f"Unexpected CONNACK {reply.hex()}; check credentials and existing decoy routing.")

    # Keep a benign session above the short-session heuristic.
    hold = number(config, "SHORT_SESSION_SEC") + 0.3
    if name == "connection_flood":
        count = integer(config, "CONNECTION_LIMIT") + 1
        if not 1 <= count <= 32:
            raise ValueError("Lab connection burst is capped at 32; use the default rate limit.")
        # Sequential pre-CONNECT closes avoid exhausting the Pi's concurrent-client cap.
        for _ in range(count):
            with open_client():
                pass
            time.sleep(0.02)
        return
    if name == "brute_force":
        for index in range(3):
            with open_client() as sock:
                login(sock, index, wrong=True)
            time.sleep(0.2)
        return
    if name == "protocol_abuse":
        with open_client() as sock:
            sock.sendall(b"\x10\x02\x00\x00")  # Complete CONNECT with truncated variable header.
            time.sleep(0.4)
        return
    with open_client() as sock:
        login(sock)
        if name in {"reconnaissance", "command_sequence"}:
            sock.sendall(subscribe_packet("#"))
        if name == "topic_enumeration":
            count = integer(config, "TOPIC_ENUMERATION_LIMIT") + 1
            if not 1 <= count <= 100:
                raise ValueError("Lab enumeration is capped at 100 topics.")
            for index in range(count):
                sock.sendall(subscribe_packet(f"lab/demo/topic/{index}"))
                # Consume SUBACK so packet IDs are not reused while outstanding.
                reply = bytearray()
                while len(reply) < 5:
                    chunk = sock.recv(5 - len(reply))
                    if not chunk:
                        raise RuntimeError("Disconnected during enumeration; use a fresh source IP.")
                    reply.extend(chunk)
                if reply[:2] != b"\x90\x03":
                    raise RuntimeError("Expected MQTT SUBACK during enumeration.")
        if name in {"command_spoofing", "command_sequence"}:
            # A lock command exercises command detection without an unlock demo.
            sock.sendall(publish_packet("home/door/lock", "lock"))
        if name == "publish_flood":
            count = integer(config, "PUBLISH_LIMIT") + 1
            if not 1 <= count <= 100:
                raise ValueError("Lab publish burst is capped at 100 messages.")
            for index in range(count):
                sock.sendall(publish_packet("lab/demo/telemetry", str(index)))
        if name == "benign":
            sock.sendall(publish_packet("lab/demo/telemetry", "normal"))
        time.sleep(hold)
        try:
            sock.sendall(b"\xe0\x00")
        except OSError:
            if name != "command_sequence":
                raise


def main(name: str) -> int:
    parser = argparse.ArgumentParser(description=f"Bounded authorized MQTT lab demo: {name}")
    parser.add_argument("--source-ip", help="Local lab address to bind; omit on a separate laptop")
    parser.add_argument("--dashboard-url", help="Dashboard URL; defaults to http://PI_IP:DASH_PORT")
    parser.add_argument("--output", type=Path, help="JSON evidence report destination")
    args = parser.parse_args()
    config = load_config()
    signal, loopback = SCENARIOS[name]
    host = config["PI_IP"]
    # UDP route lookup obtains the actual local address without sending MQTT traffic.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
        route.connect((host, integer(config, "PROXY_PORT")))
        source = args.source_ip or (loopback if route.getsockname()[0].startswith("127.") else route.getsockname()[0])
    if source in addresses(config, "WHITELIST_IPS"):
        parser.error("Use a non-whitelisted source, including for the benign control experiment.")
    url = args.dashboard_url or f"http://{host}:{config['DASH_PORT']}"
    output = args.output or ROOT / "data" / "demo-results" / f"{name}-{time.time_ns()}.json"
    print(f"Authorized lab demo: {name}; source={source}; proxy={host}:{config['PROXY_PORT']}")
    report = {"scenario": name, "source_ip": source, "expected_signal": signal,
              "started_at": time.time(), "verified": False}
    try:
        before = snapshot(url, source)
        watermark = max((event["rowid"] for event in before["timeline"]), default=0)
        report["attack_count_before"] = before["attack_count"]
        run_traffic(name, config, source)
        deadline = time.monotonic() + 8
        while True:
            after = snapshot(url, source)
            events = [event for event in after["timeline"] if event["rowid"] > watermark]
            observed = Counter(event["signal"] for event in events if event["category"])
            if (signal and observed[signal]) or (signal is None and events) or time.monotonic() >= deadline:
                break
            time.sleep(0.25)
        report.update(attack_count_after=after["attack_count"],
                      attack_count_delta=after["attack_count"] - before["attack_count"],
                      observed_signals=dict(observed), current_score=after["current_score"],
                      events=events,
                      verified=bool(observed[signal]) if signal else bool(events) and not observed)
    except (OSError, ValueError, RuntimeError) as exc:
        report["error"] = str(exc)
    report["finished_at"] = time.time()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"{'PASS' if report['verified'] else 'FAIL'}: {json.dumps({k: v for k, v in report.items() if k != 'events'})}")
    print(f"Evidence: {output}")
    return 0 if report["verified"] else 1
