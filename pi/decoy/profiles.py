"""Load and choose small data-driven decoy device profiles."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

PROFILE_PATH = Path(__file__).with_name("profiles.json")


def load_profiles(path: Path = PROFILE_PATH) -> dict[str, dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))


def select_profile(configured: str, client_id: str = "") -> tuple[str, dict[str, Any]]:
    profiles = load_profiles()
    if configured in profiles:
        return configured, profiles[configured]
    lowered = client_id.lower()
    name = "thermostat" if any(word in lowered for word in ("therm", "temp", "hvac")) else "smart_lock"
    return name, profiles[name]
