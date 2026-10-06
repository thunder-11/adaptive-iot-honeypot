#!/usr/bin/env python3
"""Publish believable decoy state and print every message seen by the decoy."""

from __future__ import annotations

import json
import random
import sys
import time
from pathlib import Path

import paho.mqtt.client as mqtt

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from pi.config import integer, load_config


def on_connect(client: mqtt.Client, _userdata: object, _flags: dict, reason_code: int,
               _properties: object = None) -> None:
    print(f"decoy publisher connected: {reason_code}", flush=True)
    client.subscribe("#")


def on_message(_client: mqtt.Client, _userdata: object, message: mqtt.MQTTMessage) -> None:
    payload = message.payload.decode("utf-8", errors="replace")
    print(f"decoy received topic={message.topic} payload={payload}", flush=True)


def main() -> None:
    config = load_config()
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="decoy-publisher")
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect("127.0.0.1", integer(config, "DECOY_PORT"), 30)
    client.loop_start()
    try:
        locked = True
        while True:
            motion = random.choice([0, 0, 0, 1])
            client.publish("home/door/motion", str(motion), retain=True)
            client.publish("home/door/status", json.dumps({"locked": locked, "source": "door-node"}), retain=True)
            time.sleep(3)
    except KeyboardInterrupt:
        pass
    finally:
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()

