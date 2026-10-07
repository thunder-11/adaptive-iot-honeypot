from pathlib import Path

import pytest

from pi import db
from pi.config import load_config
from pi.proxy import proxy as proxy_module


def test_proxy_restart_restores_checkpointed_score_with_decay(monkeypatch):
    path = Path("work/test-score-restore.db")
    path.parent.mkdir(exist_ok=True)
    for candidate in (path, Path(str(path) + "-wal"), Path(str(path) + "-shm")):
        candidate.unlink(missing_ok=True)

    db.add_event(90, "10.0.0.8", "throttle", 30, "elevated", path)
    db.checkpoint_scores([(98, "10.0.0.8", 25, "throttle")], path)
    restore_scores = db.restore_scores
    monkeypatch.setattr(proxy_module.db, "restore_scores", lambda: restore_scores(path))
    monkeypatch.setattr(proxy_module.time, "time", lambda: 100)

    config = load_config()
    config.update({"DECAY_POINTS_PER_SEC": "1", "WHITELIST_IPS": ""})
    restarted = proxy_module.Proxy(config)

    assert restarted.scorer.score("10.0.0.8") == pytest.approx(23, abs=0.01)
    assert restarted.scorer.action("10.0.0.8") == "throttle"


def test_tls_context_is_optional_and_loads_configured_paths(monkeypatch):
    assert proxy_module.tls_server_context({"TLS_CERT_PATH": "", "TLS_KEY_PATH": ""}) is None
    with pytest.raises(ValueError):
        proxy_module.tls_server_context({"TLS_CERT_PATH": "cert.pem", "TLS_KEY_PATH": ""})

    loaded = {}

    class FakeContext:
        def __init__(self, protocol):
            loaded["protocol"] = protocol

        def load_cert_chain(self, certfile, keyfile):
            loaded["paths"] = (certfile, keyfile)

    monkeypatch.setattr(proxy_module.ssl, "SSLContext", FakeContext)
    context = proxy_module.tls_server_context({
        "TLS_CERT_PATH": "data/demo-cert.pem", "TLS_KEY_PATH": "data/demo-key.pem",
    })

    assert isinstance(context, FakeContext)
    assert loaded["protocol"] == proxy_module.ssl.PROTOCOL_TLS_SERVER
    assert loaded["paths"] == (
        proxy_module.ROOT / "data/demo-cert.pem", proxy_module.ROOT / "data/demo-key.pem",
    )
