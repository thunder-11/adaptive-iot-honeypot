# Adaptive IoT Honeypot with Risk-Based Traffic Redirection

This mini project puts an inspecting MQTT proxy in front of a real IoT broker and a decoy broker. Explainable behavioral signals raise a persistent per-IP score: low risk reaches the real device, medium risk is throttled, high risk is restricted, and critical risk reconnects to a safe decoy. The same project runs with a simulated ESP32 when no hardware is available.

> Use `attacker/attack.py` only on a network and systems you own or are explicitly authorized to test.

## Assumptions

- Raspberry Pi OS is Debian-based, uses `apt`, has Python 3.11 or newer, and runs the scripts as a normal sudo-capable user.
- Because `config.env` is sourced by Bash, configuration values (especially the password) are shell-safe text without spaces, `#`, quotes, or command-substitution characters.
- Native Windows and Linux/Pi lifecycle and smoke-test scripts are provided; neither Windows path requires WSL, a VM, or Docker.
- MQTT 3.1.1 is the inspected protocol because that is what PubSubClient uses. Other protocol levels are forwarded to the selected backend and explicitly logged without deep inspection.
- The proxy and brokers run on one Pi, so backend connections use `127.0.0.1`. Only values intended to vary are stored in `config.env`; broker templates are rendered from it into `run/`.
- Live scores are checkpointed to SQLite and restored with elapsed-time decay when the proxy restarts. Transient rate windows still restart empty.
- Failed-auth points are capped at 40 per source IP for the proxy lifetime. Scores themselves decay linearly.
- The anonymous decoy broker binds to loopback by default and is reachable through the inspection proxy, not directly from the LAN.
- Relay “locked/unlocked” is a demo abstraction. Adapt the mechanical fail-safe behavior to the actual lock before physical deployment.

## Architecture

```text
 ESP32 / phone / test laptop
            |
   MQTT or MQTT/TLS :1883
            v
 +-------------------------+       +--------------------------+
 | asyncio inspection proxy|------>| real Mosquitto           |
 | score + allow/throttle   |       | 127.0.0.1:1884 + auth    |
 | redirect + SQLite audit  |       +--------------------------+
 +------------+------------+
              | high risk
              v
 +--------------------------+       +--------------------------+
 | decoy Mosquitto          |<------| fake-state publisher     |
 | 127.0.0.1:1885 anonymous|       +--------------------------+
 +--------------------------+
              |
       SQLite + Flask :5000
```

All normal clients, including the ESP32, use the proxy at `PI_IP:1883`. The proxy buffers a complete CONNECT, calculates the route, connects to one backend, and then parses both split and coalesced packets. Whitelisted addresses always have score zero. The default adaptive flow is `LOW 0–20 → REAL`, `MEDIUM 21–40 → delayed REAL`, `HIGH 41–50 → restricted REAL`, and `CRITICAL 51+ → DECOY`. Restricted clients cannot forward wildcard subscriptions or command publishes. Crossing CRITICAL closes existing connections so reconnecting clients land in the decoy.

### Modules for viva questions

- `config.env`: the single operator-edited source for addresses, ports, credentials, thresholds, weights, delay, and IP lists.
- `pi/config.py`: parses that file without another dependency.
- `pi/proxy/mqtt_parse.py`: bounds-checked MQTT framing and CONNECT, CONNACK, SUBSCRIBE, and PUBLISH parsing. It retains incomplete data between reads.
- `pi/proxy/scoring.py`: deterministic scoring for authentication, connection/publish rate, enumeration, wildcard, malformed packet, session, sequence, blacklist, and decoy-engagement signals.
- `pi/proxy/proxy.py`: implements the observe → score → adapt → observe-response loop, restores decayed risk after restart, and enforces throttle/restrict/decoy actions.
- `pi/security.py`: shared risk-level, attack-category, and behavioral-fingerprint rules.
- `pi/db.py`: additive SQLite migrations, WAL/busy timeout, raw evidence, and persistent attacker first/last seen, attack count/types, highest/current risk, fingerprint, and bounded history.
- `pi/decoy/decoy_publisher.py`: publishes configurable smart-lock and thermostat profiles and prints every message it observes.
- `pi/dashboard/app.py`: three-second SOC dashboard plus JSON APIs for statistics, attackers, timelines, risk, sessions, and events.
- `pi/analysis/analyze.py`: reconstructs action sequences and exports classified CSV; `evaluate.py` calculates reproducible observed metrics.
- `sim/sim_esp32.py`: hardware-free door node; its observable relay state is `sim/relay_state.txt`.
- `attacker/attack.py`: authorized four-stage demonstration. The flood plus five failed logins gives 15 + 40 = 55 with default weights, so wildcard reconnaissance and command spoofing occur after redirection.
- `esp32/esp32_node/esp32_node.ino`: physical node with non-blocking Wi-Fi/MQTT reconnect, selectable sensors, relay control, and retained state.

## Configuration

Edit only `config.env` for the gateway and Python tools. Comma-separated IP lists must not contain spaces unless those spaces are intended to be trimmed. Important fields:

- `WHITELIST_IPS`: include `127.0.0.1` and the exact static `ESP32_IP`. These addresses ignore rate, volume, authentication, enumeration, and command-pattern scoring, but malformed packets and an explicit blacklist match still accumulate risk.
- `WHITELIST_MAX_ANOMALY_SCORE`: caps the combined severe-signal score for a whitelisted address (default `40`), preserving availability while making protocol corruption or a contradictory blacklist entry visible.
- `BLACKLIST_IPS`: gets the blacklist weight once on first sight.
- `DECOY_FORCE_IPS`: optional demo safety switch; these addresses route directly to the decoy regardless of score. Leave it empty when demonstrating the complete score transition.
- `MEDIUM=21`, `HIGH=41`, `CRITICAL=51`: throttle, restrict, and decoy boundaries.
- All `WEIGHT_*`, rate/window/limit, decay, and delay fields keep behavioral decisions explainable and configurable.
- `SCORE_CHECKPOINT_SEC` controls how often live non-zero scores are persisted without creating synthetic evidence events.
- `DECOY_PROFILE=auto|smart_lock|thermostat` selects the advertised fake device; `auto` uses the connecting client identifier when possible.
- `DECOY_BIND_IP=127.0.0.1` keeps the native decoy broker off the LAN. Override it with the Pi's LAN address only for a controlled demo that intentionally needs direct decoy access; normal clients must use the proxy. Docker overrides it to `0.0.0.0` only inside the isolated Compose network.
- `ALERT_*` enables cooldown-controlled JSON-line logging and an optional HTTP webhook for high/critical activity.
- `REAL_USER`, `REAL_PASS`: used by the real broker, simulator, ESP32, phone, and legitimate CLI clients.
- `TLS_CERT_PATH` and `TLS_KEY_PATH`: leave both empty for the existing plaintext classroom flow. Set both to PEM paths to terminate TLS on the client-facing proxy port; relative paths resolve from the repository root.

After changing credentials, rerun `pi/setup_pi.sh` on Linux/Pi or `windows/setup.ps1` on Windows to regenerate `data/real.passwd`. When TLS paths are configured and either PEM file is missing, setup uses OpenSSL to generate a one-year self-signed local-demo certificate; provide trusted certificates yourself for any non-lab deployment. Plaintext clients continue to work only when both TLS paths are empty. TLS clients must trust the configured certificate and use the same `PROXY_PORT`.

## Raspberry Pi quick start

```bash
cp -r adaptive-iot-honeypot ~/adaptive-iot-honeypot
cd ~/adaptive-iot-honeypot
nano config.env
bash pi/setup_pi.sh
bash pi/run_all.sh
```

Expected last line:

```text
Stack started: MQTT proxy <PI_IP>:1883; dashboard http://<PI_IP>:5000
```

Stop safely with:

```bash
bash pi/stop_all.sh
```

Logs are in `logs/`, PID files and rendered broker configurations are in `run/`, and durable evidence is in `data/honeypot.db`.

## Numbered demo runbook: where each command runs

Recommended demo layout:

- **Raspberry Pi:** runs both MQTT brokers, inspection proxy, dashboard, database, alerts, and ThingSpeak uploader.
- **ESP32:** runs the flashed smart-lock sketch and controls the physical relay/LED.
- **Windows laptop:** flashes the ESP32, opens the dashboard and ThingSpeak, and acts as the separate attacker machine.

### 1. Windows laptop — flash the ESP32 once

Before opening Arduino IDE, create the local credentials file in Windows PowerShell:

```powershell
Set-Location "E:\Ali\adaptive-iot-honeypot"
Copy-Item .\esp32\esp32_node\secrets.h.example .\esp32\esp32_node\secrets.h
notepad .\esp32\esp32_node\secrets.h
```

Enter the Wi-Fi name/password and MQTT password in `secrets.h`. The real file is ignored by Git so these credentials are not pushed. Then open `esp32/esp32_node/esp32_node.ino` in Arduino IDE. Set the Pi IP, MQTT username, ESP32 static IP, gateway, and subnet in the sketch. Select the actual ESP32 model under **Tools → Board**, select its COM port, and click **Upload**. Open Serial Monitor at `115200` baud after flashing. The upload itself is performed in Arduino IDE.

### 2. Raspberry Pi, Terminal 1 — configure the project

```bash
cd ~/adaptive-iot-honeypot
nano config.env
```

Set `PI_IP`, `ESP32_IP`, `REAL_USER`, `REAL_PASS`, `WHITELIST_IPS`, and the ThingSpeak settings. The laptop's Wi-Fi IP must **not** be in `WHITELIST_IPS` when the laptop is used as the attacker. Save Nano with `Ctrl+O`, Enter, then exit with `Ctrl+X`.

### 3. Raspberry Pi, Terminal 1 — first-time installation

Run this once, and rerun it whenever `REAL_USER` or `REAL_PASS` changes:

```bash
cd ~/adaptive-iot-honeypot
bash pi/setup_pi.sh
```

### 4. Raspberry Pi, Terminal 1 — start the honeypot stack

```bash
cd ~/adaptive-iot-honeypot
bash pi/run_all.sh
```

This starts the real broker, decoy broker, decoy publisher, inspection proxy, dashboard, alerting, and ThingSpeak uploader. The command returns after starting them in the background.

### 5. Windows laptop, browser — open the live displays

Open the Pi dashboard, replacing the example with the actual Pi IP:

```text
http://192.168.1.10:5000
```

Also open the ThingSpeak channel's **Private View**. On the dashboard, click **Desktop alerts: enable** and allow browser notifications.

### 6. Raspberry Pi, Terminal 2 — monitor real MQTT traffic

```bash
cd ~/adaptive-iot-honeypot
set -a
source config.env
set +a
mosquitto_sub -h 127.0.0.1 -p "$PROXY_PORT" -u "$REAL_USER" -P "$REAL_PASS" -t 'home/door/#' -v
```

Expected messages include `home/door/motion` and a retained `home/door/status` JSON object containing `locked`, `led_on`, and `source`.

### 7. Raspberry Pi, Terminal 3 — prove the real LED changes

Load the configuration once in this terminal:

```bash
cd ~/adaptive-iot-honeypot
set -a
source config.env
set +a
```

Legitimate unlock command:

```bash
mosquitto_pub -h 127.0.0.1 -p "$PROXY_PORT" -u "$REAL_USER" -P "$REAL_PASS" -t home/door/lock -m unlock
```

Expected: the ESP32 reports `UNLOCKED`, the external LED turns **OFF**, and the dashboard/ThingSpeak state changes to `0`.

Legitimate lock command:

```bash
mosquitto_pub -h 127.0.0.1 -p "$PROXY_PORT" -u "$REAL_USER" -P "$REAL_PASS" -t home/door/lock -m lock
```

Expected: the ESP32 reports `LOCKED`, the external LED turns **ON**, and the dashboard/ThingSpeak state changes to `1`.

### 8. Raspberry Pi, Terminal 4 — watch security and cloud logs

```bash
cd ~/adaptive-iot-honeypot
tail -f logs/proxy.log
```

In another Pi terminal, the alert-only stream can be watched with:

```bash
cd ~/adaptive-iot-honeypot
tail -f logs/alerts.log
```

Successful cloud uploads appear in `logs/proxy.log` as `ThingSpeak update stored as entry ...`.

### 9. Windows laptop, PowerShell — prepare the attacker client once

The laptop should contain a copy of this repository. From its repository root:

```powershell
Set-Location "E:\Ali\adaptive-iot-honeypot"
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Edit the laptop copy of `config.env` so `PI_IP` is the Raspberry Pi's LAN address. Do not add the laptop's Wi-Fi IP to the Pi's `WHITELIST_IPS`.

### 10. Windows laptop, PowerShell — run the authorized attack

First ensure the real device is locked and its LED is on. Then run:

```powershell
Set-Location "E:\Ali\adaptive-iot-honeypot"
.\.venv\Scripts\python.exe .\attacker\attack.py
```

Do not use `--source-ip 127.0.0.2` when attacking from a separate laptop. The proxy should see the laptop's actual Wi-Fi IP. Expected progression is `allow → throttle → restrict → decoy`. The decoy receives the attacker's final fake `unlock`, while the real ESP32 remains `LOCKED` and its physical LED remains **ON**.

If a second machine is unavailable, run the isolated local demonstration on the Pi instead:

```bash
cd ~/adaptive-iot-honeypot
PI_IP=127.0.0.1 .venv/bin/python attacker/attack.py --source-ip 127.0.0.2
```

Keep `127.0.0.2` out of `WHITELIST_IPS`.

### 11. Windows laptop, browser — export or clear evidence

Open the dashboard's **Events** page. Click **Export CSV** to download `honeypot-attack-events.csv`. Click **Clear logs** only after saving required evidence. To reset both stored logs and the proxy's in-memory scores for a completely fresh demonstration, clear the logs and then restart the Pi stack.

### 12. Raspberry Pi, any terminal — stop or restart

Stop all managed components:

```bash
cd ~/adaptive-iot-honeypot
bash pi/stop_all.sh
```

Restart:

```bash
cd ~/adaptive-iot-honeypot
bash pi/run_all.sh
```

## Native Windows Development

Install 64-bit Python 3.11 or newer and the native [Mosquitto for Windows](https://mosquitto.org/download/). Mosquitto supplies `mosquitto.exe`, `mosquitto_passwd.exe`, and the `mosquitto_sub.exe` client used by the smoke test. Its default `C:\Program Files\Mosquitto` directory is detected automatically; no Bash, WSL, VM, or Docker is required.

Run setup from an elevated PowerShell if the Mosquitto installer created its automatic Windows service; setup stops and disables that conflicting broker, matching the existing Pi setup. The remaining commands can run from a normal PowerShell window at the repository root:

```powershell
.\windows\setup.ps1
.\windows\run_all.ps1
.\tests\smoke_test.ps1
.\windows\stop_all.ps1
```

Setup verifies Python and pip, creates `.venv`, installs `requirements.txt`, creates `data\`, `logs\`, and `run\`, generates the hashed real-broker password file, and renders native broker configurations. The run script starts the same five logical components as `pi/run_all.sh`; process identity and logs are stored under `run\` and `logs\`. No activation or Bash `source` command is needed because Python and PowerShell read `config.env` directly.

With the default configuration, open <http://127.0.0.1:5000>. The Windows smoke test preserves any existing SQLite database while it runs, uses whitelisted `127.0.0.1` for the legitimate simulator, and asks Python sockets to bind suspicious traffic to `127.0.0.2`. Current Windows versions normally route the IPv4 loopback block without a Linux-style loopback alias. If local security/network software prevents that bind, the test fails rather than forging an identity or weakening Pi/production behavior; use a second physical test host for the full source-isolation check. More detail is in `windows/README.md`.

## Laptop-only Linux test

Use Ubuntu/Debian, including a Linux VM whose networking permits loopback aliases. Install base packages, clone/copy the repository, and set `PI_IP=127.0.0.1`, keep `127.0.0.1` in `WHITELIST_IPS`, set `ESP32_IP=127.0.0.1`, leave `DECOY_FORCE_IPS` empty, and ensure `127.0.0.2` is not whitelisted.

```bash
cd adaptive-iot-honeypot
sed -i 's/^PI_IP=.*/PI_IP=127.0.0.1/' config.env
sed -i 's/^ESP32_IP=.*/ESP32_IP=127.0.0.1/' config.env
bash pi/setup_pi.sh
.venv/bin/python -m pytest -q
bash tests/smoke_test.sh
```

Linux normally treats all of `127.0.0.0/8` as loopback. If binding fails, run:

```bash
sudo ip addr add 127.0.0.2/8 dev lo
```

On macOS use `sudo ifconfig lo0 alias 127.0.0.2`, install Mosquitto separately, create the virtual environment manually, and run the individual commands because the Pi lifecycle uses Linux process conventions.

Expected pytest result:

```text
13 passed
```

Expected smoke-test ending (numbers may be higher because connection timing can add events):

```text
PASS: attacker score=55..., decoy_sessions=..., decoy_unlocks=...
PASS: simulated relay stayed LOCKED and legitimate traffic worked before and after
```

To watch the flow manually instead, use four terminals after `bash pi/run_all.sh`:

```bash
.venv/bin/python sim/sim_esp32.py
mosquitto_sub -h 127.0.0.1 -p 1883 -u "$REAL_USER" -P "$REAL_PASS" -t 'home/door/#' -v
.venv/bin/python attacker/attack.py --source-ip 127.0.0.2
.venv/bin/python pi/analysis/analyze.py
```

Shell variables are available after `set -a; source config.env; set +a`. Open `http://127.0.0.1:5000`. The simulator should continue printing motion, its relay file should stay `LOCKED`, and the attacker should show four completed stages. Depending on timing, the timeline shows `allow → throttle → restrict → decoy` and the relevant attack categories.

## Tests and analysis

```bash
.venv/bin/python -m pytest -q
bash tests/smoke_test.sh
.venv/bin/python pi/analysis/analyze.py --output data/analysis.csv
```

On native Windows, use `tests\smoke_test.ps1` in place of the Bash smoke test.

Unit tests cover all scoring signals, four adaptive levels, caps, decay, whitelist, forced routes, persistence, migrations, classification, fingerprints, alert cooldown, profiles, evaluation, APIs, dashboard rendering, malformed packets, and MQTT packet framing. The smoke test deliberately refuses to run when the laptop configuration is unsafe or inconsistent.

## SOC dashboard and APIs

The multi-page dashboard at `http://PI_IP:5000` has a persistent SOC navigation rail and a light/dark theme toggle that follows the system preference initially and remembers the operator's selection. Overview and Events update every three seconds without a full-page refresh.

The Events page can export the complete evidence stream as a spreadsheet-safe CSV and can clear recorded events, sessions, attacker summaries, decoy messages, and the JSON alert log after confirmation. Clearing logs does not erase the latest trusted physical-device state. Because the proxy owns live in-memory scores, restart the stack as well when a completely fresh scoring demonstration is required.

Medium, high, and critical activity creates an in-dashboard alert on every page with the default `ALERT_MIN_ACTION=throttle`. Use **Desktop alerts: enable** once to grant browser notification permission. `ALERT_WEBHOOK_URL` remains available for sending the same cooldown-controlled JSON alert to an external notification service.

### ThingSpeak telemetry

Create a ThingSpeak channel with these numeric fields:

1. Motion
2. Locked (`1` locked, `0` unlocked)
3. External LED (`1` on, `0` off)
4. Risk score
5. Adaptive action (`0` allow, `1` throttle, `2` restrict, `3` decoy)
6. Event points

Then set `THINGSPEAK_ENABLED=true`, `THINGSPEAK_WRITE_API_KEY=<channel write key>`, and optionally `THINGSPEAK_CHANNEL_ID=<channel id>` in `config.env`. Restart the stack. Uploads are performed by the proxy in a background thread and coalesced to ThingSpeak's 15-second minimum interval, so cloud outages never block MQTT traffic. Telemetry fields 1–3 are accepted only from a whitelisted client routed to the real broker; decoy commands therefore cannot falsify the displayed physical state.

### External LED demonstration

The ESP32 sketch uses `STATUS_LED_PIN` (GPIO 2 by default) with the convention **LED ON = LOCKED** and **LED OFF = UNLOCKED**. Connect an external LED through a suitable current-limiting resistor and change `STATUS_LED_PIN` if GPIO 2 is unsuitable for your board. `LED_ACTIVE_HIGH` supports either wiring polarity.

For the demo, send a legitimate `lock` or `unlock` command through the proxy and observe the physical LED plus the Overview device card change. On Windows with the default configuration, for example:

```powershell
& "$env:ProgramFiles\Mosquitto\mosquitto_pub.exe" -h 127.0.0.1 -p 1883 -u iotuser -P change-this-before-demo -t home/door/lock -m unlock
& "$env:ProgramFiles\Mosquitto\mosquitto_pub.exe" -h 127.0.0.1 -p 1883 -u iotuser -P change-this-before-demo -t home/door/lock -m lock
```

Next run the attack from a non-whitelisted IP. Its critical reconnect and `unlock` publish are handled by the decoy broker, so neither the real ESP32 nor its LED changes. The decoy attempt remains visible in Events, the attacker detail, CSV export, and ThingSpeak security fields.

Dashboard pages:

- `/` — live total attackers, high/critical count, sessions, decoy hits, p50/p95 first high-or-critical response latency, risk distribution, and attack distribution.
- `/attackers` — sortable attacker inventory with current risk/action, fingerprints, attack types, and observation times.
- `/attacker/<ip>` — per-IP event timeline, sessions, decoy messages, and attackers sharing the same fingerprint.
- `/events` — live scoring-event timeline with client-side risk and action filters.
- `/sessions` — compact session ledger with backend, profile, timestamps, and duration.

Read-only endpoints:

```text
GET /api/stats
GET /api/attackers
GET /api/events?limit=100
GET /api/sessions?limit=100
GET /api/attacker/<ip>
GET /api/risk/<ip>
GET /api/fingerprint/<label>
```

## Attack categories and decision flow

| Category | Primary evidence |
|---|---|
| Reconnaissance | wildcard subscriptions, repeated short sessions, blacklist sighting |
| Brute Force | failed authentication CONNACK 4/5 |
| MQTT Enumeration | unique topic filters over the configured limit |
| Unauthorized/Suspicious Publish | command-topic or decoy publishes |
| Command/Protocol Abuse | malformed packets, suspicious payloads, wildcard-to-command sequence |
| Flooding/DoS | connection or publish frequency over rolling limits |

Each scored event records the signal, awarded points, resulting score/action, category, detail, and response latency. High-risk clients remain on the authenticated real broker but wildcard and command packets are withheld. Critical clients are disconnected and their next session receives a selected decoy profile. Decoy interaction itself becomes a feedback signal.

## Docker Compose (optional)

Docker does not replace native execution. It provides isolated real/decoy brokers, proxy, dashboard, fake-device publisher, and simulator:

```bash
docker compose up --build
docker compose down
```

Only proxy port 1883 and dashboard port 5000 are published. Named volumes retain SQLite/log/simulator state. Environment overrides supply internal broker hostnames while `config.env` remains the shared configuration.

## Experiments and reproducible evaluation

Run an attack/benign workload, then capture only measurements actually observed:

```bash
python pi/analysis/evaluate.py --database data/honeypot.db --output data/evaluation.json
python pi/analysis/measure_resources.py --pid <proxy-pid> --duration 60 --output data/proxy-resources.csv
```

For detection rate and false positives, supply a CSV with `ip,label` where label is `malicious` or `benign`:

```bash
python pi/analysis/evaluate.py --ground-truth data/ground_truth.csv
```

The report covers detection/false-positive rates when labels exist, mean/p50/p95 first high-or-critical response latency, event throughput, database size/activity, sessions, and decoy engagement. The dashboard `/api/stats` payload uses the same latency calculation under `first_high_critical_latency_ms`. CPU time and RAM are sampled separately on Windows or Linux without third-party packages. Missing measurements are reported as `null`; the scripts never invent results.

## Example workflow

1. Edit `config.env`, run the platform setup/start script, and open the SOC dashboard.
2. Start `sim/sim_esp32.py` and verify normal whitelisted traffic remains at score zero; only malformed packets or an explicit blacklist match can raise it, up to `WHITELIST_MAX_ANOMALY_SCORE`.
3. Run the authorized `attacker/attack.py`; watch the per-IP timeline and adaptive actions.
4. Inspect `/api/attacker/<ip>`, `logs/alerts.log`, and the selected decoy profile/session.
5. Run `analyze.py`, `evaluate.py`, and resource sampling; retain the resulting CSV/JSON as experiment evidence.

## Limitations

- This is a teaching prototype with optional basic TLS termination, not a production IDS, managed PKI, or substitute for network segmentation.
- Enforcement remains IP-based, but fingerprints prioritize normalized MQTT client-ID patterns and CONNECT characteristics so matching behavior can correlate NAT'd or IPv6-rotating sources.
- Fingerprints and the `/api/fingerprint/<label>` correlation are explainable “likely same actor” indicators, not identity attribution.
- In-memory rolling windows reset on restart; current decayed score and historical evidence persist in SQLite.
- MQTT 3.1.1 is deeply inspected. Other protocol levels are forwarded and logged as protocol abuse without full semantic parsing.
- Webhook delivery is best effort and intentionally non-blocking; consult the local alert log as the audit source.

## Project tree

```text
config.env                 single runtime configuration
windows/                   native Windows setup/start/stop lifecycle
pi/                        gateway, brokers, database, dashboard, analysis
esp32/esp32_node/          Arduino sketch
sim/                       hardware-free ESP32 simulator
attacker/                  authorized demonstration traffic
tests/                     deterministic unit and end-to-end smoke tests
README.md                  design and laptop instructions
DEMO.md                    demo-day copy/paste runbook
```
