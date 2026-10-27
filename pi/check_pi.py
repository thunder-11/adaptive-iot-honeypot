#!/usr/bin/env python3
"""Native Pi preflight and non-destructive stack readiness checks."""

from __future__ import annotations

import argparse
import importlib
import ipaddress
import math
import platform
import shutil
import socket
import sys
import time
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from pi.config import addresses, load_config

PORT_KEYS = ("REAL_PORT", "DECOY_PORT", "PROXY_PORT", "DASH_PORT")


def validate(config: dict[str, str], *, hardware: bool = False) -> list[str]:
    errors = []
    ports = []
    for key in PORT_KEYS:
        try:
            port = int(config[key])
            if not 1024 <= port <= 65535:
                raise ValueError
            ports.append(port)
        except (KeyError, ValueError):
            errors.append(f"{key} must be an unprivileged port (1024..65535)")
    if len(set(ports)) != len(ports):
        errors.append("Broker, proxy and dashboard ports must all be different")
    for key, default in (("MAX_CONNECTIONS", "32"), ("CONNECT_TIMEOUT_SEC", "15"),
                         ("STARTUP_TIMEOUT_SEC", "60")):
        try:
            raw = config.get(key, default)
            value = int(raw) if key == "MAX_CONNECTIONS" else float(raw)
            if not 0 < value < float("inf"):
                raise ValueError
        except ValueError:
            errors.append(f"{key} must be positive (MAX_CONNECTIONS must be an integer)")
    if bool(config.get("TLS_CERT_PATH")) != bool(config.get("TLS_KEY_PATH")):
        errors.append("Set both TLS_CERT_PATH and TLS_KEY_PATH, or leave both empty")
    if not config.get("REAL_USER") or not config.get("REAL_PASS"):
        errors.append("REAL_USER and REAL_PASS must not be empty")
    try:
        tiers = [float(config[key]) for key in ("MEDIUM", "HIGH", "CRITICAL")]
        if not all(math.isfinite(value) for value in tiers) or not 0 < tiers[0] < tiers[1] < tiers[2]:
            raise ValueError
    except (KeyError, ValueError):
        errors.append("Risk thresholds must be finite and ordered: 0 < MEDIUM < HIGH < CRITICAL")
    for key in config:
        if key.startswith("WEIGHT_") or key in {
            "FAILED_AUTH_CAP", "SHORT_SESSION_CAP", "DECAY_POINTS_PER_SEC",
            "THROTTLE_DELAY_SEC", "THROTTLE_PACKET_DELAY_SEC", "SHORT_SESSION_SEC",
            "WHITELIST_MAX_ANOMALY_SCORE", "ALERT_COOLDOWN_SEC",
        }:
            try:
                value = float(config[key])
                if not math.isfinite(value) or value < 0:
                    raise ValueError
            except ValueError:
                errors.append(f"{key} must be finite and nonnegative")
    for key in ("CONNECTION_LIMIT", "PUBLISH_LIMIT", "TOPIC_ENUMERATION_LIMIT"):
        try:
            if int(config[key]) < 1:
                raise ValueError
        except (KeyError, ValueError):
            errors.append(f"{key} must be a positive integer")
    for key in ("CONNECTION_WINDOW_SEC", "PUBLISH_WINDOW_SEC", "SCORE_CHECKPOINT_SEC"):
        try:
            value = float(config[key])
            if not math.isfinite(value) or value <= 0:
                raise ValueError
        except (KeyError, ValueError):
            errors.append(f"{key} must be finite and positive")
    if hardware:
        for key in ("PI_IP", "ESP32_IP"):
            try:
                address = ipaddress.IPv4Address(config.get(key, ""))
                if address.is_loopback or address.is_unspecified or address.is_multicast:
                    raise ValueError
            except ValueError:
                errors.append(f"{key} must be the actual LAN IPv4 address for the hardware demo")
        if config.get("PI_IP") == config.get("ESP32_IP"):
            errors.append("PI_IP and ESP32_IP must be different")
        trusted = addresses(config, "WHITELIST_IPS")
        if config.get("ESP32_IP") not in trusted or "127.0.0.1" not in trusted:
            errors.append("WHITELIST_IPS must include 127.0.0.1 and ESP32_IP")
        if trusted & (addresses(config, "BLACKLIST_IPS") | addresses(config, "DECOY_FORCE_IPS")):
            errors.append("Trusted sources must not also be blacklisted or forced into the decoy")
        if config.get("TLS_CERT_PATH"):
            errors.append("The bundled ESP32 sketch uses plaintext MQTT; leave both TLS paths empty")
    return errors


def wait_port(port: int, timeout: float, host: str = "127.0.0.1") -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--running", action="store_true", help="check listeners and dashboard HTTP")
    parser.add_argument("--wait-port", type=int, help="wait for a startup listener")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--hardware", action="store_true", help="validate Pi/ESP32 LAN configuration")
    parser.add_argument("--device", action="store_true", help="also require fresh status from ESP32_IP")
    args = parser.parse_args()
    args.running = args.running or args.device
    config = load_config()
    errors = validate(config, hardware=args.hardware)
    if errors:
        print("\n".join(f"FAIL: {error}" for error in errors))
        return 1
    timeout = float(config.get("STARTUP_TIMEOUT_SEC", "60"))
    if args.wait_port is not None:
        if wait_port(args.wait_port, timeout, args.host):
            return 0
        print(f"FAIL: {args.host}:{args.wait_port} not ready after {timeout:g}s; inspect logs/")
        return 1
    print(f"Python {platform.python_version()} / {platform.machine()}")
    model = Path("/proc/device-tree/model")
    if model.exists():
        print(model.read_text().strip("\x00\n"))
    if sys.version_info < (3, 11):
        errors.append("Python 3.11+ required; install Raspberry Pi OS Bookworm or newer")
    for module in ("paho.mqtt.client", "flask", "sqlite3"):
        try:
            importlib.import_module(module)
        except ImportError:
            errors.append(f"Missing {module}; rerun bash pi/setup_pi.sh")
    for executable in ("mosquitto", "mosquitto_passwd", "mosquitto_pub", "mosquitto_sub"):
        if not shutil.which(executable):
            errors.append(f"Missing {executable}; rerun bash pi/setup_pi.sh")
    if args.running:
        for key in PORT_KEYS:
            host = config.get("DECOY_BIND_IP", "127.0.0.1") if key == "DECOY_PORT" else "127.0.0.1"
            if host == "0.0.0.0":
                host = "127.0.0.1"
            if not wait_port(int(config[key]), 2, host):
                errors.append(f"{key} is not listening; inspect logs/")
        try:
            with urlopen(f"http://127.0.0.1:{config['DASH_PORT']}/", timeout=10) as response:
                if response.status != 200:
                    errors.append("Dashboard did not return HTTP 200")
        except Exception as exc:
            errors.append(f"Dashboard HTTP check failed: {exc}")
        if args.device:
            try:
                import json
                with urlopen(f"http://127.0.0.1:{config['DASH_PORT']}/api/stats", timeout=10) as response:
                    stats = json.load(response)
                device = stats.get("device_state") or {}
                if not stats.get("device_online") or device.get("ip") != config["ESP32_IP"]:
                    errors.append("No fresh status from ESP32_IP; check Serial Monitor, Wi-Fi, credentials and whitelist")
            except Exception as exc:
                errors.append(f"ESP32 telemetry check failed: {exc}")
    else:
        for key in PORT_KEYS:
            try:
                with socket.socket() as listener:
                    if sys.platform != "win32":
                        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    listener.bind(("0.0.0.0", int(config[key])))
            except OSError:
                errors.append(f"{key}={config[key]} is busy; stop the other service or change the port")
    if shutil.disk_usage(ROOT).free < 512 * 1024 * 1024:
        print("WARN: Less than 512 MiB free; free SD card space before collecting evidence")
    if config.get("PI_IP") == "127.0.0.1":
        print("NOTE: PI_IP is loopback; set it to the Pi LAN IP for the ESP32/laptop")
    if config.get("REAL_PASS") == "change-this-before-demo":
        print("NOTE: Replace the demo password before connecting hardware")
    for error in errors:
        print(f"FAIL: {error}")
    if not errors:
        print("PASS: " + ("listeners and dashboard respond" if args.running else "native prerequisites and ports"))
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
