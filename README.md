# Adaptive IoT Honeypot with Risk-Based Traffic Redirection

This mini project puts an inspecting MQTT proxy in front of a real IoT broker and a decoy broker. A low-risk client reaches the real device; suspicious behavior raises a per-IP score, adds a delay at medium risk, and sends subsequent connections to a safe decoy at high risk. The same project runs with a simulated ESP32 when no hardware is available.

> Use `attacker/attack.py` only on a network and systems you own or are explicitly authorized to test.

## Assumptions

- Raspberry Pi OS is Debian-based, uses `apt`, has Python 3.11 or newer, and runs the scripts as a normal sudo-capable user.
- Because `config.env` is sourced by Bash, configuration values (especially the password) are shell-safe text without spaces, `#`, quotes, or command-substitution characters.
- The laptop-only smoke test runs on Linux. On macOS, add the loopback alias noted below. The supplied shell lifecycle is not intended for native Windows.
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

All normal clients, including the ESP32, use the proxy at `PI_IP:1883`. The proxy buffers a complete CONNECT, calculates the route, connects to one backend, replays the buffered bytes, and then parses both split and coalesced packets. Whitelisted addresses always have score zero. An address scoring 21–50 reaches the real broker after the configured delay. At 51 or more, existing connections are closed so reconnecting clients land in the decoy.

### Modules for viva questions

- `config.env`: the single operator-edited source for addresses, ports, credentials, thresholds, weights, delay, and IP lists.
- `pi/config.py`: parses that file without another dependency.
- `pi/proxy/mqtt_parse.py`: bounds-checked MQTT framing and CONNECT, CONNACK, SUBSCRIBE, and PUBLISH parsing. It retains incomplete data between reads.
- `pi/proxy/scoring.py`: deterministic scoring state with an injectable clock, linear decay, per-signal caps, and route selection.
- `pi/proxy/proxy.py`: owns TCP sessions, selects a backend after CONNECT, forwards bytes both ways, scores behavior, and disconnects an IP when it crosses HIGH.
- `pi/db.py`: creates the three SQLite tables and enables WAL plus a five-second busy timeout for concurrent writers/readers.
- `pi/decoy/decoy_publisher.py`: makes the decoy look alive and prints every message it observes. The proxy records attacker source IPs because the broker itself sees only the proxy connection.
- `pi/dashboard/app.py`: read-only, three-second auto-refresh dashboard for current scores, events, sessions, and decoy messages.
- `pi/analysis/analyze.py`: reconstructs action sequences, classifies behavior, prints a summary, and writes CSV.
- `sim/sim_esp32.py`: hardware-free door node; its observable relay state is `sim/relay_state.txt`.
- `attacker/attack.py`: authorized four-stage demonstration. The flood plus five failed logins gives 15 + 40 = 55 with default weights, so wildcard reconnaissance and command spoofing occur after redirection.
- `esp32/esp32_node/esp32_node.ino`: physical node with non-blocking Wi-Fi/MQTT reconnect, selectable sensors, relay control, and retained state.

## Configuration

Edit only `config.env` for the gateway and Python tools. Comma-separated IP lists must not contain spaces unless those spaces are intended to be trimmed. Important fields:

- `WHITELIST_IPS`: include `127.0.0.1` and the exact static `ESP32_IP`. These addresses always score zero.
- `BLACKLIST_IPS`: gets the blacklist weight once on first sight.
- `DECOY_FORCE_IPS`: optional demo safety switch; these addresses route directly to the decoy regardless of score. Leave it empty when demonstrating the complete score transition.
- `MEDIUM=21`, `HIGH=51`: routing boundaries.
- `REAL_USER`, `REAL_PASS`: used by the real broker, simulator, ESP32, phone, and legitimate CLI clients.

After changing credentials, rerun `pi/setup_pi.sh` to regenerate `data/real.passwd`.

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

## Laptop-only test

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

Shell variables are available after `set -a; source config.env; set +a`. Open `http://127.0.0.1:5000`. The simulator should continue printing motion, its relay file should stay `LOCKED`, the attacker should show four completed stages, and the analyzer should show `allow -> throttle -> decoy` (very fast runs may skip a persisted throttle event) plus the three attack classifications.

## Tests and analysis

```bash
.venv/bin/python -m pytest -q
bash tests/smoke_test.sh
.venv/bin/python pi/analysis/analyze.py --output data/analysis.csv
```

Unit tests cover signal weights, cap, thresholds, decay, whitelist, forced routes, default attack score, malformed packets, multi-byte lengths, packets split across reads, and several packets in one read. The smoke test deliberately refuses to run when the laptop configuration is unsafe or inconsistent.

## Project tree

```text
config.env                 single runtime configuration
pi/                        gateway, brokers, database, dashboard, analysis
esp32/esp32_node/          Arduino sketch
sim/                       hardware-free ESP32 simulator
attacker/                  authorized demonstration traffic
tests/                     deterministic unit and end-to-end smoke tests
README.md                  design and laptop instructions
DEMO.md                    demo-day copy/paste runbook
```
