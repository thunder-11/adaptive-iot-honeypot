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
from pi.alerts import AlertManager
from pi.config import addresses, integer, load_config, number
from pi.decoy.profiles import select_profile
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
from pi.security import category_for_signal

LOGGER = logging.getLogger("mqtt-proxy")
MAX_BUFFER = 1024 * 1024
COMMAND_TOPICS = {"home/door/lock"}


def build_scorer(config: dict[str, str]) -> RiskScorer:
    return RiskScorer(ScoreConfig(
        medium=number(config, "MEDIUM"), high=number(config, "HIGH"),
        critical=number(config, "CRITICAL"),
        connection_weight=number(config, "WEIGHT_CONNECTION_RATE"),
        failed_auth_weight=number(config, "WEIGHT_FAILED_AUTH"),
        failed_auth_cap=number(config, "FAILED_AUTH_CAP"),
        wildcard_weight=number(config, "WEIGHT_WILDCARD_SUBSCRIBE"),
        command_weight=number(config, "WEIGHT_COMMAND_PUBLISH"),
        blacklist_weight=number(config, "WEIGHT_BLACKLIST"),
        topic_enumeration_weight=number(config, "WEIGHT_TOPIC_ENUMERATION"),
        publish_rate_weight=number(config, "WEIGHT_PUBLISH_RATE"),
        malformed_weight=number(config, "WEIGHT_MALFORMED_PACKET"),
        short_session_weight=number(config, "WEIGHT_SHORT_SESSION"),
        short_session_cap=number(config, "SHORT_SESSION_CAP"),
        command_sequence_weight=number(config, "WEIGHT_COMMAND_SEQUENCE"),
        decoy_engagement_weight=number(config, "WEIGHT_DECOY_ENGAGEMENT"),
        connection_limit=integer(config, "CONNECTION_LIMIT"),
        connection_window=number(config, "CONNECTION_WINDOW_SEC"),
        topic_enumeration_limit=integer(config, "TOPIC_ENUMERATION_LIMIT"),
        publish_limit=integer(config, "PUBLISH_LIMIT"),
        publish_window=number(config, "PUBLISH_WINDOW_SEC"),
        decay_per_second=number(config, "DECAY_POINTS_PER_SEC"),
        whitelist=frozenset(addresses(config, "WHITELIST_IPS")),
        blacklist=frozenset(addresses(config, "BLACKLIST_IPS")),
        force_decoy=frozenset(addresses(config, "DECOY_FORCE_IPS")),
    ))


class Proxy:
    def __init__(self, config: dict[str, str]):
        self.config = config
        self.scorer = build_scorer(config)
        self.alerts = AlertManager(config, ROOT)
        self.connections: dict[str, set[asyncio.StreamWriter]] = defaultdict(set)
        self.server: asyncio.Server | None = None
        self._restore_scores()

    def _restore_scores(self) -> None:
        now = time.time()
        for row in db.restore_scores():
            decayed = max(0.0, row["current_score"] -
                          (now - row["last_seen"]) * self.scorer.config.decay_per_second)
            self.scorer.seed(row["ip"], decayed)

    def log_event(self, ip: str, detail: str, *, signal: str = "", points: float = 0.0,
                  started_at: float | None = None) -> float:
        score = self.scorer.score(ip)
        action = self.scorer.action(ip)
        category = category_for_signal(signal)
        latency = (time.monotonic() - started_at) * 1000 if started_at is not None else 0.0
        db.add_event(time.time(), ip, action, score, detail, category=category,
                     signal=signal, points=points, response_latency_ms=latency)
        LOGGER.info("ip=%s score=%.1f action=%s signal=%s detail=%s",
                    ip, score, action, signal or "-", detail)
        self.alerts.emit({"ip": ip, "score": round(score, 2), "action": action,
                          "category": category, "signal": signal, "detail": detail})
        return score

    async def disconnect_ip_if_critical(self, ip: str) -> None:
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
        connection_started = time.monotonic()
        self.connections[ip].add(writer)
        _, rate_awarded = self.scorer.record_connection(ip)
        _, black_applied = self.scorer.apply_blacklist(ip)
        self.log_event(ip, "connection opened")
        if rate_awarded:
            self.log_event(ip, "connection frequency exceeded rolling limit",
                           signal="connection_rate", points=self.scorer.config.connection_weight,
                           started_at=connection_started)
        if black_applied:
            self.log_event(ip, "blacklist first sight", signal="blacklist",
                           points=self.scorer.config.blacklist_weight,
                           started_at=connection_started)
        backend_writer: asyncio.StreamWriter | None = None
        session_id: int | None = None
        try:
            connect_packet, info, following_packets, partial_tail = await self.read_connect(reader)
            inspect = info.protocol_name == "MQTT" and info.protocol_level == 4
            if not inspect:
                LOGGER.warning("ip=%s protocol=%s/%s forwarded without inspection", ip,
                               info.protocol_name, info.protocol_level)
                self.log_event(ip, f"non-MQTT-3.1.1 protocol level {info.protocol_level}",
                               signal="protocol_abuse")
            action = self.scorer.action(ip)
            backend = "decoy" if action == "decoy" else "real"
            if action == "throttle":
                await asyncio.sleep(number(self.config, "THROTTLE_DELAY_SEC"))
            port_key = "DECOY_PORT" if backend == "decoy" else "REAL_PORT"
            host_key = "DECOY_HOST" if backend == "decoy" else "REAL_HOST"
            backend_reader, backend_writer = await asyncio.open_connection(
                self.config.get(host_key, "127.0.0.1"), integer(self.config, port_key)
            )
            profile_name, profile = select_profile(self.config.get("DECOY_PROFILE", "auto"), info.client_id)
            session_id = db.start_session(ip, backend, time.time(), profile=profile_name if backend == "decoy" else "")
            self.log_event(
                ip, f"route={backend} client={info.client_id} username={info.username or '-'} "
                    f"profile={profile_name if backend == 'decoy' else '-'}",
                started_at=connection_started,
            )
            backend_writer.write(connect_packet)
            await backend_writer.drain()
            if inspect:
                for packet in following_packets:
                    if await self.inspect_client_packet(packet, ip, backend):
                        backend_writer.write(packet)
                        await backend_writer.drain()
            await asyncio.gather(
                self.pipe_client(reader, backend_writer, ip, backend, inspect, partial_tail),
                self.pipe_backend(backend_reader, writer, ip, backend),
            )
        except (asyncio.IncompleteReadError, ConnectionError):
            LOGGER.debug("connection ended for %s", ip)
        except (MQTTParseError, ValueError) as exc:
            LOGGER.warning("closing malformed connection from %s: %s", ip, exc)
            self.scorer.record_malformed(ip)
            self.log_event(ip, f"malformed or suspicious packet: {exc}",
                           signal="malformed_packet", points=self.scorer.config.malformed_weight,
                           started_at=connection_started)
            await self.disconnect_ip_if_critical(ip)
        except Exception:
            LOGGER.exception("connection handler failed for %s", ip)
            self.log_event(ip, "internal connection error")
        finally:
            self.connections[ip].discard(writer)
            if session_id is not None:
                db.end_session(session_id, time.time())
            duration = time.monotonic() - connection_started
            if duration < number(self.config, "SHORT_SESSION_SEC"):
                _, points = self.scorer.record_short_session(ip)
                if points:
                    self.log_event(ip, f"short session duration={duration:.3f}s",
                                   signal="short_session", points=points)
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
            return packets[0], parse_connect(packets[0]), packets[1:], working

    async def pipe_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                          ip: str, backend: str, inspect: bool,
                          initial_buffer: bytearray | None = None) -> None:
        buffer = initial_buffer or bytearray()
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                return
            if not inspect:
                writer.write(chunk)
                await writer.drain()
                continue
            buffer.extend(chunk)
            if len(buffer) > MAX_BUFFER:
                raise MQTTParseError("client buffer limit exceeded")
            for packet in extract_packets(buffer, MAX_BUFFER):
                if await self.inspect_client_packet(packet, ip, backend):
                    if self.scorer.action(ip) == "throttle":
                        await asyncio.sleep(number(self.config, "THROTTLE_PACKET_DELAY_SEC"))
                    writer.write(packet)
                    await writer.drain()

    async def inspect_client_packet(self, packet: bytes, ip: str, backend: str) -> bool:
        kind = packet_type(packet)
        if kind == 8:
            topics = parse_subscribe(packet)
            for topic in topics:
                _, enumerating = self.scorer.record_topic(ip, topic)
                if enumerating:
                    self.log_event(ip, f"topic enumeration unique_topics={len(self.scorer.states[ip].topics)}",
                                   signal="topic_enumeration",
                                   points=self.scorer.config.topic_enumeration_weight)
            if has_dangerous_wildcard(topics):
                self.scorer.record_wildcard(ip)
                self.log_event(ip, f"wildcard subscribe: {','.join(topics)}",
                               signal="wildcard_subscription", points=self.scorer.config.wildcard_weight)
                await self.disconnect_ip_if_critical(ip)
                if backend == "real" and self.scorer.action(ip) in {"restrict", "decoy"}:
                    self.log_event(ip, "withheld wildcard subscription from real broker",
                                   signal="protocol_abuse")
                    return False
            if backend == "real" and self.scorer.action(ip) == "decoy":
                await self.disconnect_ip_if_critical(ip)
                self.log_event(ip, "withheld critical-risk subscription from real broker")
                return False
        elif kind == 3:
            published = parse_publish(packet)
            payload = published.payload.decode("utf-8", errors="replace")
            _, rate_awarded = self.scorer.record_publish(ip)
            if rate_awarded:
                self.log_event(ip, "publish frequency exceeded rolling limit",
                               signal="publish_rate", points=self.scorer.config.publish_rate_weight)
            if backend == "decoy":
                db.add_decoy_message(time.time(), ip, published.topic, payload)
                _, engaged = self.scorer.record_decoy_engagement(ip)
                if engaged:
                    self.log_event(ip, "attacker interacted with decoy",
                                   signal="decoy_engagement",
                                   points=self.scorer.config.decoy_engagement_weight)
                self.log_event(ip, f"decoy publish topic={published.topic} payload={payload[:200]}")
            if published.topic in COMMAND_TOPICS:
                if ip not in self.scorer.config.whitelist:
                    self.scorer.record_command_publish(ip)
                self.log_event(ip, f"command publish topic={published.topic} payload={payload[:200]}",
                               signal="suspicious_publish", points=self.scorer.config.command_weight)
                _, sequence = self.scorer.record_command_sequence(ip)
                if sequence:
                    self.log_event(ip, "wildcard-to-command sequence detected",
                                   signal="command_sequence",
                                   points=self.scorer.config.command_sequence_weight)
                await self.disconnect_ip_if_critical(ip)
                if backend == "real" and self.scorer.action(ip) in {"restrict", "decoy"}:
                    self.log_event(ip, f"withheld command publish topic={published.topic}",
                                   signal="protocol_abuse")
                    return False
            elif len(published.payload) > 4096 or "\x00" in payload:
                self.scorer.record_malformed(ip)
                self.log_event(ip, f"suspicious payload topic={published.topic} bytes={len(published.payload)}",
                               signal="malformed_packet", points=self.scorer.config.malformed_weight)
                if backend == "real" and self.scorer.action(ip) in {"restrict", "decoy"}:
                    await self.disconnect_ip_if_critical(ip)
                    return False
            if backend == "real" and self.scorer.action(ip) == "decoy":
                await self.disconnect_ip_if_critical(ip)
                self.log_event(ip, "withheld critical-risk publish from real broker")
                return False
        return True

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
                    self.log_event(ip, f"failed auth CONNACK={code} points={points:g}",
                                   signal="failed_auth", points=points)
                    await self.disconnect_ip_if_critical(ip)


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
