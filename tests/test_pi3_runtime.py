import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from pi.check_pi import validate, wait_port
from pi.config import load_config
from pi.proxy import proxy as proxy_module


@pytest.mark.parametrize("changes", [
    {"REAL_PORT": "1883"}, {"DASH_PORT": "80"}, {"PROXY_PORT": "oops"},
    {"MAX_CONNECTIONS": "0"}, {"MAX_CONNECTIONS": "1.5"},
    {"MAX_CONNECTIONS": "32.0"},
    {"CONNECT_TIMEOUT_SEC": "nan"}, {"STARTUP_TIMEOUT_SEC": "-1"},
    {"TLS_CERT_PATH": "cert.pem", "TLS_KEY_PATH": ""}, {"REAL_PASS": ""},
])
def test_preflight_rejects_unusable_config(changes):
    config = load_config()
    config.update(changes)
    assert validate(config)


def test_preflight_defaults_are_valid():
    assert validate(load_config()) == []


def make_proxy(monkeypatch):
    monkeypatch.setattr(proxy_module.db, "system_state", lambda key: "")
    monkeypatch.setattr(proxy_module.db, "restore_scores", lambda: [])
    proxy = proxy_module.Proxy(load_config())
    monkeypatch.setattr(proxy, "log_event", lambda *args, **kwargs: 0)
    return proxy


class Writer:
    def __init__(self):
        self.closed = False

    def get_extra_info(self, name):
        return ("127.0.0.1", 12345)

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass

    def write(self, data):
        pass

    async def drain(self):
        pass


def test_capacity_rejects_excess_client_without_allocating_state(monkeypatch):
    proxy = make_proxy(monkeypatch)
    proxy.active_connections = proxy.max_connections
    writer = Writer()
    async def exercise():
        await proxy.handle_client(asyncio.StreamReader(), writer)
    asyncio.run(exercise())
    assert writer.closed
    assert not proxy.connections
    assert proxy.active_connections == proxy.max_connections


def test_connect_timeout_releases_slot_and_ip(monkeypatch):
    proxy = make_proxy(monkeypatch)
    proxy.connect_timeout = 0.01

    async def exercise():
        writer = Writer()
        await asyncio.wait_for(proxy.handle_client(asyncio.StreamReader(), writer), 1)
        assert writer.closed

    asyncio.run(exercise())
    assert proxy.active_connections == 0
    assert not proxy.connections


def test_backend_disconnect_cancels_client_pipe_and_releases_slot(monkeypatch):
    proxy = make_proxy(monkeypatch)
    info = SimpleNamespace(protocol_name="MQTT", protocol_level=4, client_id="test",
                           username="user", connect_flags=2, keepalive=30,
                           clean_session=True, has_will=False)
    monkeypatch.setattr(proxy, "read_connect", AsyncMock(return_value=(b"connect", info, [], bytearray())))
    monkeypatch.setattr(proxy_module.db, "start_session", lambda *a, **kw: 1)
    monkeypatch.setattr(proxy_module.db, "end_session", lambda *a: None)
    cancelled = []
    backend_writer = Writer()

    async def blocked_client(*args):
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.append(True)

    monkeypatch.setattr(proxy, "pipe_client", blocked_client)
    monkeypatch.setattr(proxy, "pipe_backend", AsyncMock())
    monkeypatch.setattr(proxy_module.asyncio, "open_connection",
                        AsyncMock(return_value=(None, backend_writer)))

    async def exercise():
        writer = Writer()
        await asyncio.wait_for(proxy.handle_client(asyncio.StreamReader(), writer), 1)
        assert writer.closed and backend_writer.closed

    asyncio.run(exercise())
    assert cancelled == [True]
    assert proxy.active_connections == 0
    assert not proxy.connections


def test_wait_port_times_out_on_refused_connection(monkeypatch):
    def refuse(*args, **kwargs):
        raise ConnectionRefusedError

    monkeypatch.setattr("pi.check_pi.socket.create_connection", refuse)
    monkeypatch.setattr("pi.check_pi.time.sleep", lambda delay: None)
    assert not wait_port(1883, 0.001)
