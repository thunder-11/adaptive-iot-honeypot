# Demo-readiness verification

## Checks completed

- Full Python suite: **79 passed**, using native Mosquitto and Python on Windows.
- Real MQTT integration: every individual scenario produces verified evidence;
  repeating automatic local brute force uses a fresh source and adds three new
  failed-auth events.
- Combined attack: its unlock is recorded in the decoy; a trusted subscriber on
  the real broker receives no attacker unlock and still receives legitimate
  control afterward.
- Live local stack: unlock gives `locked=0, led_on=1`; lock gives
  `locked=1, led_on=0`. Telemetry is fresh. Trusted controls do not increase the
  classified-event count.
- ESP32 Dev Module firmware: BUTTON, PIR, REED, LDR and DHT11_SENSOR all compile
  with Espressif ESP32 core **2.0.17** and PubSubClient **2.8.0**. DHT compilation
  used DHT sensor library **1.4.7** and Adafruit Unified Sensor **1.1.15**.
  Default BUTTON build uses **736,821 bytes of flash** and **44,808 bytes of RAM**.
  Compilation used a separate sketch copy and placeholder credentials; the board
  was not flashed and real credentials were not replaced.
- Pi setup/start/stop and Linux smoke-test scripts pass Bash syntax checks.
  The configuration exporter was also executed in Bash with a BOM/CRLF fixture;
  values remained clean and shell metacharacters stayed literal.
- Python module compilation and dashboard JavaScript syntax checks pass.

## Issues corrected

- Trusted commands, subscriptions and authentication failures no longer create
  false classified attacks while whitelist scoring is disabled.
- Critical-risk handling closes real-route connections and preserves existing
  decoy sessions. Backend connection attempts have a timeout.
- Clock corrections cannot increase restored risk on proxy restart.
- Combined-demo CONNACK reads handle TCP fragmentation; failed sockets are closed.
  Local automatic combined trials avoid the whitelisted loopback identity.
- Repeated automatic local individual demos choose unused loopback identities;
  remote brute-force runs explain when existing state needs an operator reset.
- Pi configuration export tolerates Windows BOM/CRLF and quotes literal values.
  Shutdown no longer needs a readable config file and checks process identity
  before signalling saved PIDs. The smoke test stops the stack before replacing
  its test database and removes old WAL/SHM files with that database.
- Database write contexts close their connections after commit or rollback.
  Alert-log write failures no longer raise into MQTT forwarding.
- ESP32 and simulator use LED off for locked and on for unlocked. Device status
  appears near the top of Overview. Status heartbeats distinguish fresh telemetry
  from old saved state. Invalid device booleans are rejected.
- ESP32 button/contact pull-up inputs now report closure as active. Optional LDR
  readings use GPIO34/ADC1 instead of GPIO27/ADC2 while Wi-Fi is active. Failed
  MQTT subscriptions reconnect, failed status publishes retry, command payload
  size is bounded, and MQTT socket waits are shorter.
- Hardware preflight checks catch loopback Pi addresses, mismatched ESP32
  whitelist entries, conflicting routes, invalid scoring controls and TLS settings
  incompatible with the bundled plaintext sketch.

## Hardware acceptance still required

No Raspberry Pi was available, and the ESP32 was identified from a photo rather
than tested over a live serial connection. ARM installation, Pi power/SD card,
Wi-Fi/subnet settings, board upload, physical sensor wiring and relay polarity
remain unverified. Compilation and desktop integration cannot certify those.

Follow [DEMO_CHECKLIST.md](DEMO_CHECKLIST.md). Before presenting, require a
successful `.venv/bin/python pi/check_pi.py --hardware --running --device`,
physical unlock/lock with the correct LED states, and decoy isolation while the
real device remains responsive. The current Windows `config.env` intentionally
still uses loopback; set the real Pi LAN address in the Pi, laptop and sketch
configuration for the physical demonstration.
