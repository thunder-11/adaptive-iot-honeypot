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
