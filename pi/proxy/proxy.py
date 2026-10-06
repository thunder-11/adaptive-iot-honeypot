#!/usr/bin/env python3
"""Async MQTT 3.1.1 inspection proxy with score-based backend selection."""

from __future__ import annotations

import asyncio
import logging
import signal
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pi import db
from pi.config import addresses, integer, load_config, number
from pi.proxy.mqtt_parse import (
    MQTTParseError,
    extract_packets,
    has_dangerous_wildcard,
    packet_type,
    parse_connack,
    parse_connect,
    parse_publish,
    parse_subscribe,
)
from pi.proxy.scoring import RiskScorer, ScoreConfig

LOGGER = logging.getLogger("mqtt-proxy")
MAX_BUFFER = 1024 * 1024
COMMAND_TOPICS = {"home/door/lock"}


def build_scorer(config: dict[str, str]) -> RiskScorer:
    return RiskScorer(ScoreConfig(
        medium=number(config, "MEDIUM"), high=number(config, "HIGH"),
        connection_weight=number(config, "WEIGHT_CONNECTION_RATE"),
        failed_auth_weight=number(config, "WEIGHT_FAILED_AUTH"),
        failed_auth_cap=number(config, "FAILED_AUTH_CAP"),
        wildcard_weight=number(config, "WEIGHT_WILDCARD_SUBSCRIBE"),
        command_weight=number(config, "WEIGHT_COMMAND_PUBLISH"),
        blacklist_weight=number(config, "WEIGHT_BLACKLIST"),
        connection_limit=integer(config, "CONNECTION_LIMIT"),
        connection_window=number(config, "CONNECTION_WINDOW_SEC"),
        decay_per_second=number(config, "DECAY_POINTS_PER_SEC"),
        whitelist=frozenset(addresses(config, "WHITELIST_IPS")),
        blacklist=frozenset(addresses(config, "BLACKLIST_IPS")),
        force_decoy=frozenset(addresses(config, "DECOY_FORCE_IPS")),
    ))


class Proxy:
    def __init__(self, config: dict[str, str]):
        self.config = config
        self.scorer = build_scorer(config)
        self.connections: dict[str, set[asyncio.StreamWriter]] = defaultdict(set)
        self.server: asyncio.Server | None = None

    def log_event(self, ip: str, detail: str) -> float:
        score = self.scorer.score(ip)
        action = self.scorer.action(ip)
        db.add_event(time.time(), ip, action, score, detail)
        LOGGER.info("ip=%s score=%.1f action=%s detail=%s", ip, score, action, detail)
        return score

    async def disconnect_ip_if_high(self, ip: str) -> None:
        if self.scorer.action(ip) != "decoy" or ip in self.scorer.config.force_decoy:
            return
        writers = list(self.connections.get(ip, set()))
        if writers:
            LOGGER.info("risk threshold crossed; closing %d connection(s) for %s", len(writers), ip)
        for writer in writers:
            writer.close()

    async def start(self) -> None:
        port = integer(self.config, "PROXY_PORT")
        self.server = await asyncio.start_server(self.handle_client, "0.0.0.0", port)
        LOGGER.info("proxy listening on 0.0.0.0:%d", port)
        async with self.server:
            await self.server.serve_forever()

    async def handle_client(self, reader: asyncio.StreamReader,
                            writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        ip = str(peer[0]) if peer else "unknown"
        self.connections[ip].add(writer)
        score, rate_awarded = self.scorer.record_connection(ip)
        black_score, black_applied = self.scorer.apply_blacklist(ip)
        detail = "connect"
        if rate_awarded:
            detail += "; connection-rate"
        if black_applied:
            detail += "; blacklist-first-sight"
        self.log_event(ip, detail)
        backend_writer: asyncio.StreamWriter | None = None
        session_id: int | None = None
        try:
            initial, info, following_packets, partial_tail = await self.read_connect(reader)
            inspect = info.protocol_name == "MQTT" and info.protocol_level == 4
            if not inspect:
                LOGGER.warning("ip=%s protocol=%s/%s forwarded without inspection", ip,
                               info.protocol_name, info.protocol_level)
                self.log_event(ip, f"non-MQTT-3.1.1 protocol level {info.protocol_level}")
            action = self.scorer.action(ip)
            backend = "decoy" if action == "decoy" else "real"
            if action == "throttle":
                await asyncio.sleep(number(self.config, "THROTTLE_DELAY_SEC"))
            port_key = "DECOY_PORT" if backend == "decoy" else "REAL_PORT"
            backend_reader, backend_writer = await asyncio.open_connection("127.0.0.1", integer(self.config, port_key))
            session_id = db.start_session(ip, backend, time.time())
            self.log_event(ip, f"route={backend} client={info.client_id} username={info.username or '-'}")
            backend_writer.write(initial)
            await backend_writer.drain()
            if inspect:
                for packet in following_packets:
                    await self.inspect_client_packet(packet, ip, backend)
            await asyncio.gather(
                self.pipe_client(reader, backend_writer, ip, backend, inspect, partial_tail),
                self.pipe_backend(backend_reader, writer, ip, backend),
            )
        except (asyncio.IncompleteReadError, ConnectionError):
            LOGGER.debug("connection ended for %s", ip)
        except (MQTTParseError, ValueError) as exc:
            LOGGER.warning("closing malformed connection from %s: %s", ip, exc)
            self.log_event(ip, f"malformed: {exc}")
        except Exception:
            LOGGER.exception("connection handler failed for %s", ip)
            self.log_event(ip, "internal connection error")
        finally:
            self.connections[ip].discard(writer)
            if session_id is not None:
                db.end_session(session_id, time.time())
            for stream in (backend_writer, writer):
                if stream is not None:
                    stream.close()
                    try:
                        await stream.wait_closed()
                    except (ConnectionError, asyncio.CancelledError):
                        pass

    async def read_connect(self, reader: asyncio.StreamReader) -> tuple[bytes, object, list[bytes], bytearray]:
        buffer = bytearray()
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                raise ConnectionError("client closed before CONNECT")
            buffer.extend(chunk)
            if len(buffer) > MAX_BUFFER:
                raise MQTTParseError("CONNECT buffer limit exceeded")
            working = bytearray(buffer)
            packets = extract_packets(working, MAX_BUFFER)
            if not packets:
                continue
            if packet_type(packets[0]) != 1:
                raise MQTTParseError("first packet must be CONNECT")
            return bytes(buffer), parse_connect(packets[0]), packets[1:], working

    async def pipe_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                          ip: str, backend: str, inspect: bool,
                          initial_buffer: bytearray | None = None) -> None:
        buffer = initial_buffer or bytearray()
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                return
            writer.write(chunk)
            await writer.drain()
            if not inspect:
                continue
            buffer.extend(chunk)
            if len(buffer) > MAX_BUFFER:
                raise MQTTParseError("client buffer limit exceeded")
            for packet in extract_packets(buffer, MAX_BUFFER):
                await self.inspect_client_packet(packet, ip, backend)

    async def inspect_client_packet(self, packet: bytes, ip: str, backend: str) -> None:
        kind = packet_type(packet)
        if kind == 8:
            topics = parse_subscribe(packet)
            if has_dangerous_wildcard(topics):
                self.scorer.record_wildcard(ip)
                self.log_event(ip, f"wildcard subscribe: {','.join(topics)}")
                await self.disconnect_ip_if_high(ip)
        elif kind == 3:
            published = parse_publish(packet)
            payload = published.payload.decode("utf-8", errors="replace")
            if backend == "decoy":
                db.add_decoy_message(time.time(), ip, published.topic, payload)
                self.log_event(ip, f"decoy publish topic={published.topic} payload={payload[:200]}")
            if published.topic in COMMAND_TOPICS:
                if ip not in self.scorer.config.whitelist:
                    self.scorer.record_command_publish(ip)
                self.log_event(ip, f"command publish topic={published.topic} payload={payload[:200]}")
                await self.disconnect_ip_if_high(ip)

    async def pipe_backend(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                           ip: str, backend: str) -> None:
        buffer = bytearray()
        connack_seen = False
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                return
            writer.write(chunk)
            await writer.drain()
            if connack_seen:
                continue
            buffer.extend(chunk)
            if len(buffer) > MAX_BUFFER:
                raise MQTTParseError("backend buffer limit exceeded")
            packets = extract_packets(buffer, MAX_BUFFER)
            if not packets:
                continue
            connack_seen = True
            if packet_type(packets[0]) == 2:
                code = parse_connack(packets[0])
                if backend == "real" and code in (4, 5):
                    _, points = self.scorer.record_failed_auth(ip)
                    self.log_event(ip, f"failed auth CONNACK={code} points={points:g}")
                    await self.disconnect_ip_if_high(ip)


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    proxy = Proxy(load_config())
    loop = asyncio.get_running_loop()
    task = asyncio.create_task(proxy.start())
    stop = asyncio.Event()
    for name in ("SIGINT", "SIGTERM"):
        if hasattr(signal, name):
            try:
                loop.add_signal_handler(getattr(signal, name), stop.set)
            except NotImplementedError:  # Windows event loops do not support this API.
                pass
    try:
        await task
    except asyncio.CancelledError:
        pass


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
