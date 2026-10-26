# Demo-Day Runbook

Follow this checklist in order. Replace example network values with the values assigned by your router/hotspot. Do not expose the attack script to systems outside your own authorized lab.

## A. Raspberry Pi

1. For a Raspberry Pi 3 kit, first follow [the Pi 3 guide](pi/README_PI3.md). In Raspberry Pi Imager select your exact board and choose Raspberry Pi OS Lite (32-bit recommended for Pi 3; 64-bit also works), Bookworm or newer with Python 3.11+. Set a hostname, your own username/password, Wi-Fi, locale, and enable SSH. Pi 3 B needs 2.4 GHz Wi-Fi. Flash and boot the card.

2. Find the Pi in the router/hotspot client list and connect:

   ```bash
   ssh <pi-user>@<current-pi-address>
   ```

3. Set a static address with NetworkManager. First identify the active connection, then substitute its exact name and your subnet values:

   ```bash
   nmcli connection show --active
   sudo nmcli connection modify "preconfigured" ipv4.method manual ipv4.addresses 192.168.1.10/24 ipv4.gateway 192.168.1.1 ipv4.dns "1.1.1.1 8.8.8.8"
   sudo nmcli connection up "preconfigured"
   ```

   Expected: SSH briefly disconnects; reconnect to `192.168.1.10`. If your hotspot uses another subnet, use that subnet instead.

4. From the laptop, copy the gateway source without the Windows virtual environment or old runtime state, then reconnect (run the first two commands from the repository root on the laptop):

   ```bash
   ssh <pi-user>@192.168.1.10 "mkdir -p ~/adaptive-iot-honeypot"
   scp -r pi sim attacker tests config.env requirements.txt pytest.ini README.md DEMO.md <pi-user>@192.168.1.10:~/adaptive-iot-honeypot/
   ssh <pi-user>@192.168.1.10
   cd ~/adaptive-iot-honeypot
   ```

5. Edit the one gateway configuration:

   ```bash
   nano config.env
   ```

   Set `PI_IP=192.168.1.10`, `ESP32_IP=192.168.1.50`, strong matching `REAL_USER`/`REAL_PASS`, and `WHITELIST_IPS=127.0.0.1,192.168.1.50`. Keep `DECOY_BIND_IP=127.0.0.1` so the decoy is reachable only through the proxy, and leave `DECOY_FORCE_IPS=` empty for the full scoring demo. Save with Ctrl+O, Enter, Ctrl+X.

6. Install and configure everything (safe to rerun):

   ```bash
   bash pi/setup_pi.sh
   .venv/bin/python -m pytest -q
   bash pi/run_all.sh
   ```

   Expected: pytest passes the complete suite; startup prints the proxy and dashboard addresses. Check processes with:

   ```bash
   tail -n 20 logs/real-broker.log logs/decoy-broker.log logs/proxy.log logs/dashboard.log
   ```

## B. ESP32

1. Install Arduino IDE 2.x. In **File → Preferences → Additional Boards Manager URLs**, add:

   ```text
   https://espressif.github.io/arduino-esp32/package_esp32_index.json
   ```

2. In Boards Manager install **esp32 by Espressif Systems**. In Library Manager install **PubSubClient by Nick O'Leary**. Install **DHT sensor library by Adafruit** and **Adafruit Unified Sensor** only if using `DHT11`.

3. Copy `esp32/esp32_node/secrets.h.example` to `esp32/esp32_node/secrets.h`. Enter Wi-Fi credentials and the MQTT password in that ignored local file. Open `esp32/esp32_node/esp32_node.ino` and set the Pi address, MQTT username, static IP, gateway, subnet, and pins in its top config block. Match `config.env`, then select the connected ESP32 board and port.

4. Choose one sensor line. `BUTTON` is the default and requires no sensor module:

   ```cpp
   #define SENSOR_TYPE BUTTON
   ```

5. Wire with USB power disconnected:

   | Mode/device | ESP32 pin | Other connection / note |
   |---|---:|---|
   | Button (`BUTTON`) | GPIO 27 | Other leg to GND; internal pull-up is enabled |
   | PIR (`PIR`) | GPIO 27 | OUT to GPIO 27, VCC/GND per module rating |
   | Reed switch (`REED`) | GPIO 27 | Other leg to GND; internal pull-up is enabled |
   | DHT11 data (`DHT11`) | GPIO 27 | VCC to 3.3 V, GND to GND; bare sensor needs ~10 kΩ pull-up |
   | LDR (`LDR`) | GPIO 27 | Use as midpoint of a 3.3 V resistor divider; never exceed 3.3 V |
   | Relay IN | GPIO 26 | Set `RELAY_ACTIVE_LOW` to match the module |
   | Relay GND | GND | Pi, ESP32, and external driver supply grounds must be common where required |
   | Status LED | GPIO 2 | Built-in LED on many boards; otherwise LED plus resistor to GND |

   **Relay safety:** ESP32 GPIO is 3.3 V only. Use a genuinely 3.3 V-compatible relay module or a transistor/optocoupler driver. Do not power a relay coil from a GPIO and do not put 5 V on a GPIO. Do not switch mains voltage for this classroom demo; use a low-voltage LED or safe actuator.

6. Click Verify, then Upload. Open Serial Monitor at 115200 baud.

   Expected output:

   ```text
   Connecting WiFi...
   Connecting MQTT to 192.168.1.10:1883...
   MQTT connected
   Sensor published: 0
   ```

## C. Verify the legitimate path and relay

On the Pi, load config values and subscribe:

```bash
cd ~/adaptive-iot-honeypot
set -a; source config.env; set +a
mosquitto_sub -h "$PI_IP" -p "$PROXY_PORT" -u "$REAL_USER" -P "$REAL_PASS" -t 'home/door/#' -v
```

Expected: `home/door/motion` every two seconds and a retained `home/door/status` message.

In a second Pi terminal, test both commands:

```bash
set -a; source config.env; set +a
mosquitto_pub -h "$PI_IP" -p "$PROXY_PORT" -u "$REAL_USER" -P "$REAL_PASS" -t home/door/lock -m unlock
mosquitto_pub -h "$PI_IP" -p "$PROXY_PORT" -u "$REAL_USER" -P "$REAL_PASS" -t home/door/lock -m lock
```

Expected: the low-voltage relay/LED changes twice, Serial Monitor prints `Command applied`, and status changes from `locked:false` back to `locked:true`.

## D. Authorized attack laptop

1. Copy the same repository to a Linux laptop and edit `config.env`. Set `PI_IP` to the Pi address and keep ports/thresholds/weights identical. The combined `attack.py` deliberately uses invalid/anonymous authentication. Individual authenticated scenarios use the matching `REAL_USER` and `REAL_PASS` to model a compromised client. Set `DECOY_FORCE_IPS=` empty.

2. Create the Python environment (Mosquitto is not required on this laptop for the attack):

   ```bash
   python3 -m venv .venv
   .venv/bin/python -m pip install -r requirements.txt
   ```

3. Determine the laptop's Wi-Fi IP:

   ```bash
   hostname -I
   ```

4. Run the authorized sequence, substituting that IP:

   ```bash
   .venv/bin/python attacker/attack.py --source-ip <laptop-wifi-ip>
   ```

   Expected: four stages finish. Stage 2 causes the score to exceed 51; the proxy closes the connection; stages 3 and 4 reconnect into the decoy.

5. Open `http://192.168.1.10:5000` in the laptop browser. Expected: the laptop IP is `decoy`, sessions include the decoy backend, and the decoy messages table contains `home/door/lock = unlock`.

## D1. Dashboard preflight and black appearance

1. Start the complete gateway stack from section A. For native Windows, follow
   [the startup guide](STARTUP_GUIDE.md) or [Windows README](windows/README.md).
   If the stack is already running, do not start a second copy. A standalone
   dashboard process is enough for browsing stored evidence, but cannot inspect
   MQTT traffic without the proxy and brokers.
2. Open `http://PI_IP:5000`. In **Settings → Appearance**, select **Dark** for a
   pure black page/navigation background, or **Light** for the default white
   console. The header toggle switches themes too. Preferences persist in this
   browser. Hard-refresh with Ctrl+F5 after an update.
3. In **Settings**, select the refresh interval (3 seconds by default) and click
   **Test connection**. Expect 10 core endpoint checks to pass. When an attacker
   exists, three more checks cover its detail, risk, and fingerprint group.
   These checks verify the API/database; verify MQTT and the ESP32 separately.
4. Show **Response Policy**. Its weights and tiers come from config.env. It is a
   read-only configuration view; restart the proxy after changing enforcement.
5. Keep **Events & Alerts**, **Attackers**, and **Honeypot / Decoy** ready. The
   **Security Alerts** and full **Sessions** pages open from those views.

## D2. Demonstrate individual attack categories

Use [the scenario guide](attacker/README.md) for the signal/category mapping and
options. From a Windows test laptop, run one file at a time:

```powershell
.\.venv\Scripts\python.exe .\attacker\brute_force.py
.\.venv\Scripts\python.exe .\attacker\reconnaissance.py
.\.venv\Scripts\python.exe .\attacker\topic_enumeration.py
.\.venv\Scripts\python.exe .\attacker\command_spoofing.py
.\.venv\Scripts\python.exe .\attacker\protocol_abuse.py
.\.venv\Scripts\python.exe .\attacker\connection_flood.py
.\.venv\Scripts\python.exe .\attacker\publish_flood.py
.\.venv\Scripts\python.exe .\attacker\command_sequence.py
.\.venv\Scripts\python.exe .\attacker\benign.py
```

On Pi/Linux, use `.venv/bin/python attacker/FILE.py`. Localhost demos
(`PI_IP=127.0.0.1`) automatically use distinct loopback addresses
`127.0.0.2`–`127.0.0.10`; keep them out of the whitelist, blacklist, and forced
routes. On a separate LAN laptop, omit `--source-ip` and use the Pi address in
its config. All scenarios then share the laptop's actual LAN IP: export and
clear evidence/scores between independent trials, and wait at least two seconds
for the proxy to process the reset. Do not run concurrent scenarios on one IP.

Each file prints PASS only if its expected new signal is recorded; the benign
control requires observed traffic without classified events. JSON reports go to
`data/demo-results/`; failure exits with code 1. These reports verify detection
and do not themselves establish an accuracy percentage. The combined `attack.py`
remains the original four-stage routing demonstration without these JSON reports.

The **command_spoofing** and **command_sequence** scenarios publish `lock`.
At low risk a standalone command can reach and lock the real device. The original
combined script's final `unlock` is intended to occur inside the decoy.

## D3. Show counters, live evidence, and exports

1. On **Overview**, show **Attack categories** and the **classified events**
   total. Event counts increase when new detections are recorded. **Total
   attackers** counts distinct source IPs, so repeating one IP does not add a new
   attacker. Risk scores decay; durable event counts do not decay.
2. On **Events & Alerts**, filter by the exact source IP, category, risk/action,
   or time. Filters search the full database. One scenario may trigger several
   signals/categories, such as short-session reconnaissance.
3. Click **Load older events** to browse history. This pauses streaming so rows
   stay stable; **Resume stream** returns to live updates.
4. Open the source from **Attackers** or an event row. Its count, risk, timeline,
   sessions, messages, and behavior group update automatically. Some individual
   demos add points without independently reaching the critical threshold.
5. On **Honeypot / Decoy**, show real/decoy routing, configured profiles, and
   recorded decoy messages. The linked **Sessions** ledger supports source and
   backend filters and live duration updates.
6. **Export CSV** includes every event matching the current filters, even records
   not loaded in the table. **Full evidence ZIP** saves all datasets without
   those filters. Save evidence before **Clear logs + scores**; trusted physical
   device state is retained, and the proxy resets live risk when it processes
   the request.
7. If **DATA STALE** appears, show the named failed endpoint and **Retry now**.
   The console retains its last snapshot during outages and recovers when the
   API returns. Background tabs pause polling.
8. To demonstrate detection quality, retain repeated attack and benign trial
   results, including failures. Supply `ip,label` ground truth to evaluate.py for
   detection rate, false-positive rate, and TP/FN/FP/TN counts. Separate trials
   when a LAN source IP is reused; do not claim per-type accuracy from the
   combined attack alone.

## E. Phone as a legitimate user

In MQTT Explorer (or another MQTT 3.1.1 client), create this connection:

| Setting | Value |
|---|---|
| Host | Pi address, for example `192.168.1.10` |
| Port | `1883` |
| Protocol | MQTT 3.1.1 |
| Username | `REAL_USER` value |
| Password | `REAL_PASS` value |
| TLS | Off when both TLS paths are empty; on when the proxy is configured with the generated/trusted certificate |

Subscribe to `home/door/#`. Publish `lock` or `unlock` to `home/door/lock`. The phone follows the real path while its score remains below MEDIUM.

## F. Live demonstration script

1. **Show the architecture:** point to port 1883 and say, “Every client sees one endpoint; the proxy decides whether its TCP stream reaches the real or decoy broker.”

2. **Show normal operation:** move the sensor/button and show MQTT Explorer plus the relay. Say, “The ESP32 IP is explicitly whitelisted from rate and volume scoring, so normal availability and control are preserved; malformed traffic or an explicit blacklist match is still visible under the configured anomaly cap.”

3. **Open the dashboard:** use Events & Alerts or the session ledger to show legitimate activity. Whitelisted device traffic is not counted as an attacker. Say, “SQLite keeps the evidence while WAL mode lets the proxy and dashboard work concurrently.”

   Point out Overview’s **Response & evidence** p50/p95 measurements; they measure elapsed time from first observation to each source's first `restrict` or `decoy` action using the same calculation as the evaluation report.

   Open an attacker detail page to show sources with the same fingerprint and the **Behavior group** of sources sharing a label. `/api/fingerprint/<label>` returns that label group. These are correlation aids, not identity proof.

4. **Run attack stages 1–2:** execute the laptop command. Point out connection rate, failed CONNACK 4/5 events, `throttle`, `restrict`, then score 51+. Say, “Risk is behavior-based, explainable, checkpointed across proxy restarts, and decays over time; failed-auth and short-session contributions have caps. The total score is not globally capped at 100.”

5. **Explain the forced reconnect:** show the real session ending and a decoy session starting. Say, “HIGH restricts dangerous packets; crossing CRITICAL closes open attacker sockets, so its reconnect is routed using the new score.”

6. **Run/show stages 3–4:** the same script continues automatically. State clearly: **“The wildcard subscription and fake unlock—the attack's stages 3 and 4—are happening inside the decoy after redirection.”**

7. **Prove isolation:** show `home/door/lock = unlock` under decoy messages while the physical relay remains locked; use the phone to show legitimate traffic still works. Say, “The honeypot captures intent without forwarding the dangerous command to the real device.”

8. **Generate evidence:** on the Pi run:

   ```bash
   cd ~/adaptive-iot-honeypot
   .venv/bin/python pi/analysis/analyze.py
   cat data/analysis.csv
   ```

   Say, “The analyzer reconstructs per-IP actions and labels brute force, wildcard reconnaissance, and command spoofing.”

## G. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Laptop/phone cannot reach Pi although all use the same Wi-Fi | Wi-Fi client isolation | Disable AP/client isolation or use a phone hotspot that permits peer-to-peer clients |
| ESP32 repeatedly prints MQTT/Wi-Fi failures | Wrong subnet, credentials, or temporary disconnect | Check the config block, ping the Pi from another client, then reset ESP32; reconnect attempts occur every 5 s/3 s without blocking |
| Relay action is inverted | Module is active-low vs active-high | Toggle `#define RELAY_ACTIVE_LOW true/false`, reflash, and retest with low voltage |
| A process log says address already in use | Previous process or system Mosquitto owns a port | Run `bash pi/stop_all.sh`, `sudo systemctl disable --now mosquitto`, then `sudo ss -ltnp | grep -E ':1883|:1884|:1885|:5000'` and stop only the identified process |
| Dashboard/proxy reports `database is locked` | Slow storage or an external tool holds a write transaction | Close the external SQLite editor, keep `data/` writable, and restart with `bash pi/stop_all.sh && bash pi/run_all.sh`; WAL and 5 s busy timeout are already enabled |
| ESP32 connects but is throttled/redirected | DHCP/new static IP no longer matches whitelist | Read its IP in Serial Monitor/router, update both `ESP32_IP` and `WHITELIST_IPS` in `config.env`, then restart the stack |
| Attack remains on the real broker | Source was accidentally whitelisted or score decayed between slow manual steps | Remove laptop IP from `WHITELIST_IPS`, leave `DECOY_FORCE_IPS` empty for scoring, restart, and run the automated attack continuously |
| Dashboard API checks pass but attacks do not appear | Only the dashboard is running, or source is whitelisted | Start the complete MQTT stack, verify proxy port 1883 and the actual source IP; do not mistake API health for MQTT availability |
| DATA STALE is shown | A named API endpoint failed | Restore the service and use Retry now; the last snapshot is intentionally retained |
| Dark theme still looks green or old | Browser cached earlier assets | Press Ctrl+F5, then Settings → Appearance → Dark |
| Attack goes directly to decoy | Laptop IP is in `DECOY_FORCE_IPS` | Clear it to demonstrate scoring; forced routing is only a safety shortcut |

## H. Record a backup before demo day

1. On the laptop-only Linux setup, set `PI_IP=127.0.0.1`, `ESP32_IP=127.0.0.1`, whitelist only loopback/ESP32, and leave `127.0.0.2` unwhitelisted.
2. Start a screen recorder showing a terminal and `http://127.0.0.1:5000`.
3. Run:

   ```bash
   bash pi/setup_pi.sh
   .venv/bin/python -m pytest -q
   bash tests/smoke_test.sh
   .venv/bin/python pi/analysis/analyze.py
   ```

4. Capture the two `PASS` lines, dashboard decoy message, unchanged `sim/relay_state.txt`, and analysis CSV. Save the recording locally and on a second drive. This provides evidence if venue Wi-Fi or hardware fails.

