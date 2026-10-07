from pathlib import Path

from pi.config import load_config


def test_config_accepts_windows_bom_crlf_and_environment_override(monkeypatch):
    path = Path("work/test-config.env")
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(b"\xef\xbb\xbfPORT=1883\r\nQUOTED='hello world'\r\nEMPTY=\r\n")
    monkeypatch.setenv("PORT", "2883")

    assert load_config(Path(path)) == {
        "PORT": "2883",
        "QUOTED": "hello world",
        "EMPTY": "",
    }


def test_decoy_broker_defaults_to_loopback_and_templates_are_configurable():
    config = load_config()
    assert config["DECOY_BIND_IP"] == "127.0.0.1"

    native = Path("pi/mosquitto/decoy.conf").read_text(encoding="utf-8")
    rendered = native.replace("@DECOY_PORT@", config["DECOY_PORT"]).replace(
        "@DECOY_BIND_IP@", config["DECOY_BIND_IP"]
    )
    assert "listener 1885 127.0.0.1" in rendered

    docker_template = Path("docker/mosquitto/decoy.conf").read_text(encoding="utf-8")
    compose = Path("docker-compose.yml").read_text(encoding="utf-8")
    assert "@DECOY_BIND_IP@" in docker_template
    assert "DECOY_BIND_IP: 0.0.0.0" in compose
