#!/usr/bin/env python3
"""Hardware-free ESP32 behavior simulator for the real MQTT path."""

from __future__ import annotations

import json
import random
import sys
import time
from pathlib import Path

import paho.mqtt.client as mqtt

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from pi.config import integer, load_config

STATE_FILE = Path(__file__).resolve().parent / "relay_state.txt"


class DoorSimulator:
    def __init__(self) -> None:
        self.config = load_config()
        self.locked = True
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="sim-esp32")
        self.client.username_pw_set(self.config["REAL_USER"], self.config["REAL_PASS"])
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.write_state()

    def write_state(self) -> None:
        state = "LOCKED" if self.locked else "UNLOCKED"
        STATE_FILE.write_text(state + "\n", encoding="utf-8")
        print(f"relay={state}", flush=True)

    def publish_status(self) -> None:
        payload = json.dumps({
            "locked": self.locked,
            "led_on": self.locked,
            "source": "sim-esp32",
        })
        self.client.publish("home/door/status", payload, retain=True)

    def on_connect(self, client: mqtt.Client, _userdata: object, _flags: dict,
                   reason_code: int, _properties: object = None) -> None:
        print(f"MQTT connected: {reason_code}", flush=True)
        client.subscribe("home/door/lock")
        self.publish_status()

    def on_message(self, _client: mqtt.Client, _userdata: object,
                   message: mqtt.MQTTMessage) -> None:
        command = message.payload.decode("utf-8", errors="replace").strip().lower()
        if command not in {"lock", "unlock"}:
            print(f"ignored invalid command: {command}", flush=True)
            return
        self.locked = command == "lock"
        self.write_state()
        self.publish_status()

    def run(self) -> None:
        self.client.connect(self.config["PI_IP"], integer(self.config, "PROXY_PORT"), 30)
        self.client.loop_start()
        try:
            while True:
                motion = random.choice([0, 0, 0, 1])
                self.client.publish("home/door/motion", str(motion))
                print(f"motion={motion}", flush=True)
                time.sleep(2)
        except KeyboardInterrupt:
            pass
        finally:
            self.client.loop_stop()
            self.client.disconnect()


if __name__ == "__main__":
    DoorSimulator().run()

