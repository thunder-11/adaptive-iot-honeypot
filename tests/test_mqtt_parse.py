import pytest

from pi.proxy.mqtt_parse import (
    MQTTParseError,
    extract_packets,
    has_dangerous_wildcard,
    parse_connack,
    parse_connect,
    parse_publish,
    parse_subscribe,
)


def field(value: str) -> bytes:
    encoded = value.encode()
    return len(encoded).to_bytes(2, "big") + encoded


def packet(header: int, body: bytes) -> bytes:
    assert len(body) < 128
    return bytes((header, len(body))) + body


def test_extract_split_and_multiple_packets():
    first = packet(0xC0, b"")
    second = packet(0xE0, b"")
    buffer = bytearray(first[:1])
    assert extract_packets(buffer, 100) == []
    buffer.extend(first[1:] + second)
    assert extract_packets(buffer, 100) == [first, second]
    assert buffer == b""


def test_multibyte_remaining_length_and_cap():
    body = b"x" * 130
    encoded = bytes((0x30, 0x82, 0x01)) + body
    assert extract_packets(bytearray(encoded), 200) == [encoded]
    with pytest.raises(MQTTParseError):
        extract_packets(bytearray(encoded), 100)


def test_connect_username_and_protocol():
    body = field("MQTT") + bytes((4, 0xC2, 0, 60)) + field("client") + field("user") + field("pass")
    info = parse_connect(packet(0x10, body))
    assert (info.protocol_name, info.protocol_level, info.client_id, info.username) == (
        "MQTT", 4, "client", "user"
    )


def test_subscribe_and_wildcard():
    sub = packet(0x82, b"\x00\x01" + field("home/+/status") + b"\x00" + field("#") + b"\x00")
    topics = parse_subscribe(sub)
    assert topics == ["home/+/status", "#"]
    assert has_dangerous_wildcard(topics)
    assert has_dangerous_wildcard(["home/+/#"])
    assert not has_dangerous_wildcard(["home/+/status"])


def test_publish_and_connack():
    pub = packet(0x30, field("home/door/lock") + b"unlock")
    parsed = parse_publish(pub)
    assert parsed.topic == "home/door/lock"
    assert parsed.payload == b"unlock"
    assert parse_connack(b"\x20\x02\x00\x05") == 5


def test_malformed_packets_raise_clean_errors():
    with pytest.raises(MQTTParseError):
        parse_connect(b"\x10\x03\x00")
    with pytest.raises(MQTTParseError):
        extract_packets(bytearray(b"\x10\xff\xff\xff\xff"), 1024)
