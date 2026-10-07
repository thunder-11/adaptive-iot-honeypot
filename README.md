# Adaptive IoT Honeypot with Risk-Based Traffic Redirection

This mini project puts an inspecting MQTT proxy in front of a real IoT broker and a decoy broker. Explainable behavioral signals raise a persistent per-IP score: low risk reaches the real device, medium risk is throttled, high risk is restricted, and critical risk reconnects to a safe decoy. The same project runs with a simulated ESP32 when no hardware is available.

> Use `attacker/attack.py` only on a network and systems you own or are explicitly authorized to test.

## Assumptions

- Raspberry Pi OS is Debian-based, uses `apt`, has Python 3.11 or newer, and runs the scripts as a normal sudo-capable user.
- Because `config.env` is sourced by Bash, configuration values (especially the password) are shell-safe text without spaces, `#`, quotes, or command-substitution characters.
- Native Windows and Linux/Pi lifecycle and smoke-test scripts are provided; neither Windows path requires WSL, a VM, or Docker.
- MQTT 3.1.1 is the inspected protocol because that is what PubSubClient uses. Other protocol levels are forwarded to the selected backend and explicitly logged without deep inspection.
- The proxy and brokers run on one Pi, so backend connections use `127.0.0.1`. Only values intended to vary are stored in `config.env`; broker templates are rendered from it into `run/`.
- A score lives in proxy memory and resets when the proxy restarts. Audit records remain in SQLite.
- Failed-auth points are capped at 40 per source IP for the proxy lifetime. Scores themselves decay linearly.
- The decoy broker is deliberately anonymous and listens on all interfaces as requested. Clients should still be told to use only port 1883; no firewall rules are changed.
- Relay “locked/unlocked” is a demo abstraction. Adapt the mechanical fail-safe behavior to the actual lock before physical deployment.

## Architecture

```text
 ESP32 / phone / test laptop
            |
       MQTT :1883
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
 | 0.0.0.0:1885 anonymous  |       +--------------------------+
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

- `WHITELIST_IPS`: include `127.0.0.1` and the exact static `ESP32_IP`. These addresses always score zero.
- `BLACKLIST_IPS`: gets the blacklist weight once on first sight.
- `DECOY_FORCE_IPS`: optional demo safety switch; these addresses route directly to the decoy regardless of score. Leave it empty when demonstrating the complete score transition.
- `MEDIUM=21`, `HIGH=41`, `CRITICAL=51`: throttle, restrict, and decoy boundaries.
- All `WEIGHT_*`, rate/window/limit, decay, and delay fields keep behavioral decisions explainable and configurable.
- `DECOY_PROFILE=auto|smart_lock|thermostat` selects the advertised fake device; `auto` uses the connecting client identifier when possible.
- `ALERT_*` enables cooldown-controlled JSON-line logging and an optional HTTP webhook for high/critical activity.
- `REAL_USER`, `REAL_PASS`: used by the real broker, simulator, ESP32, phone, and legitimate CLI clients.

After changing credentials, rerun `pi/setup_pi.sh` on Linux/Pi or `windows/setup.ps1` on Windows to regenerate `data/real.passwd`.

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

Dashboard pages:

- `/` — live total attackers, high/critical count, sessions, decoy hits, risk distribution, and attack distribution.
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

The report covers detection/false-positive rates when labels exist, first high/critical response latency, event throughput, database size/activity, sessions, and decoy engagement. CPU time and RAM are sampled separately on Windows or Linux without third-party packages. Missing measurements are reported as `null`; the scripts never invent results.

## Example workflow

1. Edit `config.env`, run the platform setup/start script, and open the SOC dashboard.
2. Start `sim/sim_esp32.py` and verify its whitelisted score remains zero.
3. Run the authorized `attacker/attack.py`; watch the per-IP timeline and adaptive actions.
4. Inspect `/api/attacker/<ip>`, `logs/alerts.log`, and the selected decoy profile/session.
5. Run `analyze.py`, `evaluate.py`, and resource sampling; retain the resulting CSV/JSON as experiment evidence.

## Limitations

- This is a teaching prototype, not a TLS terminator, production IDS, or substitute for network segmentation.
- Risk is IP-based; NAT can group clients and IPv6 privacy addresses can split one actor.
- Fingerprints are explainable behavioral similarities, not identity attribution.
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
