"""Small dependency-free loader for the repository's single config.env file."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config.env"


def load_config(path: Path = CONFIG_PATH) -> dict[str, str]:
    """Read KEY=VALUE pairs and allow Docker/CI environment overrides."""
    values: dict[str, str] = {}
    # utf-8-sig also accepts normal UTF-8 while tolerating files saved by
    # Windows editors with a byte-order mark.
    for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    for key in list(values):
        if key in os.environ:
            values[key] = os.environ[key]
    return values


def integer(config: Mapping[str, str], key: str) -> int:
    return int(config[key])


def number(config: Mapping[str, str], key: str) -> float:
    return float(config[key])


def addresses(config: Mapping[str, str], key: str) -> set[str]:
    return {item.strip() for item in config.get(key, "").split(",") if item.strip()}


def boolean(config: Mapping[str, str], key: str, default: bool = False) -> bool:
    return config.get(key, str(default)).strip().lower() in {"1", "true", "yes", "on"}

