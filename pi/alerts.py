"""Dependency-free cooldown alerting to a local log and optional webhook."""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.request
from pathlib import Path

from pi.config import boolean, number

LOGGER = logging.getLogger("alerts")
ACTION_ORDER = {"allow": 0, "throttle": 1, "restrict": 2, "decoy": 3}


class AlertManager:
    def __init__(self, config: dict[str, str], root: Path):
        self.enabled = boolean(config, "ALERT_ENABLED", True)
        self.minimum = config.get("ALERT_MIN_ACTION", "restrict")
        self.webhook = config.get("ALERT_WEBHOOK_URL", "").strip()
        self.log_path = root / config.get("ALERT_LOG_FILE", "logs/alerts.log")
        self.cooldown = number(config, "ALERT_COOLDOWN_SEC")
        self.last_sent: dict[tuple[str, str], float] = {}

    def emit(self, payload: dict[str, object]) -> bool:
        """Write immediately; send webhooks in a daemon thread to avoid proxy delay."""
        if not self.enabled or ACTION_ORDER.get(str(payload.get("action")), 0) < ACTION_ORDER.get(self.minimum, 2):
            return False
        key = (str(payload.get("ip")), str(payload.get("action")))
        now = time.time()
        if now - self.last_sent.get(key, 0.0) < self.cooldown:
            return False
        self.last_sent[key] = now
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps({"time": now, **payload}, sort_keys=True)
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        LOGGER.warning("security alert %s", line)
        if self.webhook:
            threading.Thread(target=self._post, args=(line.encode(),), daemon=True).start()
        return True

    def _post(self, body: bytes) -> None:
        try:
            request = urllib.request.Request(
                self.webhook, data=body, headers={"Content-Type": "application/json"}, method="POST"
            )
            with urllib.request.urlopen(request, timeout=3):
                pass
        except Exception as exc:  # Alerts must never stop traffic forwarding.
            LOGGER.error("webhook alert failed: %s", exc)
