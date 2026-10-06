"""Bounds-checked MQTT 3.1.1 packet framing and field parsing."""

from __future__ import annotations

from dataclasses import dataclass


class MQTTParseError(ValueError):
    """Raised for malformed complete MQTT data."""


@dataclass(frozen=True)
class ConnectInfo:
    protocol_name: str
    protocol_level: int
    client_id: str
    username: str | None


@dataclass(frozen=True)
class PublishInfo:
    topic: str
    payload: bytes


def decode_remaining_length(data: bytes | bytearray, offset: int = 1) -> tuple[int, int] | None:
    """Return (length, bytes_used), None when incomplete, or raise if invalid."""
    multiplier = 1
    value = 0
    for index in range(4):
        position = offset + index
        if position >= len(data):
            return None
        encoded = data[position]
        value += (encoded & 0x7F) * multiplier
        if not encoded & 0x80:
            return value, index + 1
        multiplier *= 128
    raise MQTTParseError("remaining length exceeds four bytes")


def extract_packets(buffer: bytearray, max_packet_size: int) -> list[bytes]:
    """Remove and return every complete packet while retaining a partial tail."""
    packets: list[bytes] = []
    while buffer:
        decoded = decode_remaining_length(buffer)
        if decoded is None:
            break
        remaining, used = decoded
        total = 1 + used + remaining
        if total > max_packet_size:
            raise MQTTParseError(f"packet exceeds {max_packet_size} byte limit")
        if len(buffer) < total:
            break
        packets.append(bytes(buffer[:total]))
        del buffer[:total]
    return packets


def packet_type(packet: bytes) -> int:
    if not packet:
        raise MQTTParseError("empty packet")
    return packet[0] >> 4


def _body(packet: bytes) -> bytes:
    decoded = decode_remaining_length(packet)
    if decoded is None:
        raise MQTTParseError("truncated fixed header")
    remaining, used = decoded
    start = 1 + used
    if len(packet) != start + remaining:
        raise MQTTParseError("packet length mismatch")
    return packet[start:]


def _u16(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 2 > len(data):
        raise MQTTParseError("truncated two-byte integer")
    return int.from_bytes(data[offset:offset + 2], "big"), offset + 2


def _field(data: bytes, offset: int) -> tuple[str, int]:
    size, offset = _u16(data, offset)
    end = offset + size
    if end > len(data):
        raise MQTTParseError("truncated UTF-8 field")
    try:
        return data[offset:end].decode("utf-8"), end
    except UnicodeDecodeError as exc:
        raise MQTTParseError("invalid UTF-8 field") from exc


def parse_connect(packet: bytes) -> ConnectInfo:
    if packet_type(packet) != 1:
        raise MQTTParseError("not a CONNECT packet")
    body = _body(packet)
    protocol_name, offset = _field(body, 0)
    if offset + 4 > len(body):
        raise MQTTParseError("truncated CONNECT variable header")
    level = body[offset]
    flags = body[offset + 1]
    offset += 4  # protocol level, flags, and keepalive
    client_id, offset = _field(body, offset)
    if flags & 0x04:  # Will topic and payload
        _, offset = _field(body, offset)
        _, offset = _field(body, offset)
    username = None
    if flags & 0x80:
        username, offset = _field(body, offset)
    if flags & 0x40:
        _, offset = _field(body, offset)
    return ConnectInfo(protocol_name, level, client_id, username)


def parse_subscribe(packet: bytes) -> list[str]:
    if packet_type(packet) != 8:
        raise MQTTParseError("not a SUBSCRIBE packet")
    body = _body(packet)
    _, offset = _u16(body, 0)  # packet identifier
    topics: list[str] = []
    while offset < len(body):
        topic, offset = _field(body, offset)
        if offset >= len(body):
            raise MQTTParseError("missing requested QoS")
        offset += 1
        topics.append(topic)
    if not topics:
        raise MQTTParseError("SUBSCRIBE has no topics")
    return topics


def parse_publish(packet: bytes) -> PublishInfo:
    if packet_type(packet) != 3:
        raise MQTTParseError("not a PUBLISH packet")
    body = _body(packet)
    topic, offset = _field(body, 0)
    qos = (packet[0] >> 1) & 0x03
    if qos:
        _, offset = _u16(body, offset)
    return PublishInfo(topic, body[offset:])


def parse_connack(packet: bytes) -> int:
    if packet_type(packet) != 2:
        raise MQTTParseError("not a CONNACK packet")
    body = _body(packet)
    if len(body) != 2:
        raise MQTTParseError("CONNACK must have a two-byte body")
    return body[1]


def has_dangerous_wildcard(topics: list[str]) -> bool:
    """Flag global or multi-level wildcard reconnaissance."""
    return any(topic == "#" or topic.endswith("/#") or "+/#" in topic for topic in topics)
