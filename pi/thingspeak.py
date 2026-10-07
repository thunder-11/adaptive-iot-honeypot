"""Non-blocking, rate-limited ThingSpeak channel updates."""

from __future__ import annotations

import logging
import threading
import time
import urllib.parse
import urllib.request
from collections.abc import Mapping

from pi.config import boolean

LOGGER = logging.getLogger("thingspeak")


class ThingSpeakClient:
    """Coalesce telemetry into the latest field values and upload in the background."""

    def __init__(self, config: Mapping[str, str]):
        self.write_key = config.get("THINGSPEAK_WRITE_API_KEY", "").strip()
        self.enabled = boolean(config, "THINGSPEAK_ENABLED") and bool(self.write_key)
        self.url = config.get("THINGSPEAK_UPDATE_URL", "https://api.thingspeak.com/update").strip()
        self.interval = max(15.0, float(config.get("THINGSPEAK_INTERVAL_SEC", "15")))
        self._pending: dict[str, str] = {}
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._last_sent = 0.0
        if self.enabled:
            threading.Thread(target=self._worker, name="thingspeak-uploader", daemon=True).start()

    def update(self, fields: Mapping[str, object], *, status: str = "") -> None:
        if not self.enabled:
            return
        values = {
            key: str(value) for key, value in fields.items()
            if key in {f"field{index}" for index in range(1, 9)} and value is not None
        }
        if status:
            values["status"] = status[:255]
        if not values:
            return
        with self._lock:
            self._pending.update(values)
        self._wake.set()

    def _worker(self) -> None:
        while True:
            self._wake.wait()
            delay = self.interval - (time.monotonic() - self._last_sent)
            if delay > 0:
                time.sleep(delay)
            with self._lock:
                payload = self._pending
                self._pending = {}
                self._wake.clear()
            if not payload:
                continue
            try:
                body = urllib.parse.urlencode({"api_key": self.write_key, **payload}).encode()
                request = urllib.request.Request(self.url, data=body, method="POST")
                with urllib.request.urlopen(request, timeout=5) as response:
                    result = response.read(32).decode("ascii", errors="replace").strip()
                if result == "0":
                    LOGGER.warning("ThingSpeak rejected an update (response 0)")
                else:
                    LOGGER.info("ThingSpeak update stored as entry %s", result)
            except Exception as exc:  # Cloud telemetry must never interrupt MQTT forwarding.
                LOGGER.error("ThingSpeak update failed: %s", exc)
            self._last_sent = time.monotonic()
