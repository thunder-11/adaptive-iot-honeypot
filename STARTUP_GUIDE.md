# Complete startup guide: Raspberry Pi 3, ESP32 and Windows fallback

Read the mode table first, then follow one route. Commands are labeled by the
device and terminal where they run. Do not paste this whole file into a terminal.
Commands below are instructions; creating this guide does not install software,
change your network, flash a board, or start an attack.

## 1. Choose the route

| Route | Gateway running the five services | Real device | Attacker | Start here |
| --- | --- | --- | --- | --- |
| A: full hardware demo | Raspberry Pi 3 | ESP32 | Windows laptop | Sections 2–7 |
| B: Pi unavailable, ESP32 available | Windows laptop | ESP32 | Same laptop with a separate loopback source, or second laptop | Section 8 after sections 2–3 |
| C: no working hardware | Windows laptop | Python ESP32 simulator | Same laptop, separate loopback source | Section 9 after section 2 |

The five services are the real broker, decoy broker, decoy publisher, MQTT proxy
and dashboard. The simulator is a separate sixth process, started only for route C
or a hardware-free rehearsal. Do not run it alongside the real ESP32: both listen
to the same command topic and publish the same device-state topic.

For route A, no gateway services run on Windows. Windows flashes the ESP32, opens
the dashboard and generates the authorized attack. For route B/C, stop the Pi
stack if it is still reachable and host the services on Windows instead.

### Example values used throughout

| Setting | Example | Where to change it |
| --- | --- | --- |
| Windows project folder | `E:\Ali\adaptive-iot-honeypot` | Every Windows `Set-Location` if your folder differs |
| Pi SSH username | `your-user` | Every SSH/SCP command; use the user created in Imager |
| Pi address | `192.168.1.10` | Pi/laptop config and ESP32 sketch in route A |
| Windows address for route B | `192.168.1.20` | Windows config and ESP32 sketch in route B |
| ESP32 address | `192.168.1.50` | Config whitelist and ESP32 sketch |
| Router | `192.168.1.1` | ESP32 sketch; adapt to your actual subnet |
| MQTT user | `iotuser` | Gateway config and ESP32 sketch |
| MQTT password | Your own shell-safe password | Gateway config and `secrets.h` |
| Proxy / dashboard ports | `1883` / `5000` | Gateway config; MQTT port also in ESP32 sketch |

These IPs are examples, not addresses assigned automatically by the project.
Check the actual network first. Reserve the Pi/ESP32 IPs in the router and avoid
duplicate addresses. Keep `REAL_HOST`, `DECOY_HOST`, and `DECOY_BIND_IP` set to
`127.0.0.1` for all native routes.

Use the attack tool only against your own lab gateway. Keep this demo on your
local network. Do not forward MQTT or dashboard ports to the Internet.

## 2. Windows laptop: prepare the source and Python once

### W1 — normal PowerShell: check location and tools

Open PowerShell from Start. A PowerShell prompt starts with `PS`; Pi commands
belong in an SSH session or Pi terminal, not at this Windows prompt.

```powershell
Set-Location 'E:\Ali\adaptive-iot-honeypot'
Get-Item .\config.env, .\requirements.txt, .\windows\setup.ps1, .\pi\setup_pi.sh
py -3 --version
ssh -V
Get-NetIPConfiguration
```

Expected: the files exist, Python is 3.11 or newer, and the active Wi-Fi/Ethernet
adapter has an IPv4 address. Note the IPv4 address and default gateway. Ignore
disconnected adapters, VPN and virtual-switch addresses.

If `py` is missing, install a supported 64-bit Python 3.11+ from the
[official Windows downloads](https://www.python.org/downloads/windows/), including
the launcher or PATH option, then open a fresh PowerShell. This project has been
locally regression-tested with Python 3.14.3. If only `python` works, use
`python -m venv .venv` instead of `py -3 -m venv .venv` below.

If `ssh`/`scp` is missing, install **OpenSSH Client** in Windows Optional Features,
then reopen PowerShell. You can instead use a monitor/keyboard attached to the Pi
for its terminal steps and transfer the same source folders by USB.

### W1 — create the Windows virtual environment

Run once; skip creation if `.venv\Scripts\python.exe` already exists and works:

```powershell
Set-Location 'E:\Ali\adaptive-iot-honeypot'
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r .\requirements.txt
.\.venv\Scripts\python.exe -m pip check
```

If you copied a Linux `.venv` here, stop project services first, then rename it
to an unused backup name and create a Windows environment. Example:

```powershell
Rename-Item -LiteralPath .\.venv -NewName '.venv-linux-backup'
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r .\requirements.txt
```

Do not rename a working Windows environment unnecessarily. There is no need to
activate `.venv`: all commands use its Python explicitly.

## 3. Windows + ESP32: flash the physical node once

Skip this section for route C. If switching from Pi to Windows gateway, repeat
the sketch-address edit and upload with the Windows address.

### W1 — prepare the credentials file

```powershell
Set-Location 'E:\Ali\adaptive-iot-honeypot'
if (-not (Test-Path .\esp32\esp32_node\secrets.h)) {
    Copy-Item .\esp32\esp32_node\secrets.h.example .\esp32\esp32_node\secrets.h
}
notepad .\esp32\esp32_node\secrets.h
```

Enter the Wi-Fi SSID/password and MQTT password. `MQTT_PASS` must exactly match
`REAL_PASS` on the active gateway. Keep the C++ quotes and semicolons. Do not
publish `secrets.h`; it is ignored by Git.

### Windows — Arduino IDE actions, not PowerShell commands

1. Open Arduino IDE 2.x. Follow the
   [official ESP32 Arduino installation instructions](https://docs.espressif.com/projects/arduino-esp32/en/latest/installing.html).
   Add the stable board package URL in **File → Preferences → Additional Boards
   Manager URLs**:

   ```text
   https://espressif.github.io/arduino-esp32/package_esp32_index.json
   ```

2. In Boards Manager install **esp32 by Espressif Systems**. In Library Manager
   install **PubSubClient by Nick O'Leary**. The default `BUTTON` sketch does not
   require DHT libraries. If selecting DHT11, install Adafruit's DHT sensor and
   Adafruit Unified Sensor libraries as well.
3. Open `esp32/esp32_node/esp32_node.ino` from this project. Set:

   ```cpp
   // Route A: Pi gateway. Route B: replace with the Windows gateway LAN IP.
   const char* PI_IP = "192.168.1.10";
   const char* MQTT_USER = "iotuser";
   IPAddress ESP32_STATIC_IP(192, 168, 1, 50);
   IPAddress GATEWAY(192, 168, 1, 1);
   IPAddress SUBNET(255, 255, 255, 0);
   ```

   Edit the existing declarations; do not append duplicate declarations. Match
   `MQTT_PORT` to `PROXY_PORT`, normally 1883. Leave TLS disabled for this sketch:
   it uses plaintext `WiFiClient`.
4. Connect the ESP32 with a data-capable USB cable. Select its actual board and
   COM port under **Tools**. Click Verify, then Upload. Use BOOT only if your
   board's upload procedure requires it.
5. Open Serial Monitor at **115200 baud**. After the gateway starts, expect
   `Wi-Fi connected`, the ESP32 IP, `MQTT connected`, and a subscription to
   `home/door/lock`. MQTT retries before gateway startup are expected.

The current sketch assigns sensor GPIO27, relay GPIO26 and status LED GPIO2.
Use the wiring for your actual ESP32/relay module; onboard LEDs and active-low
logic vary. These are ESP32 GPIO numbers, not Raspberry Pi header pins. No Pi
GPIO wiring is required. Start with an LED demo before connecting a physical lock.

## 4. Route A: prepare the Raspberry Pi 3 once

### Windows — flash and boot the Pi SD card

Use [Raspberry Pi Imager](https://www.raspberrypi.com/software/), select your
actual Pi 3 model and Raspberry Pi OS Lite (32-bit recommended), Bookworm or
newer. The project needs Python 3.11+. Lite 64-bit can also run the code.
Set your username/password, hostname, country, Wi-Fi and SSH in Imager before
writing the card. Use a good micro-USB supply and the hardware guidance in
[the Pi 3 guide](pi/README_PI3.md). Pi 3 B needs 2.4 GHz Wi-Fi.

Connect the Pi, laptop and ESP32 to the same reachable LAN. Guest/client isolation
can prevent communication. Find the Pi's actual address in the router client list.
These examples assume it is `192.168.1.10`.

### W1 — transfer the gateway source from Windows

```powershell
Set-Location 'E:\Ali\adaptive-iot-honeypot'
Test-NetConnection 192.168.1.10 -Port 22
ssh your-user@192.168.1.10 "mkdir -p ~/adaptive-iot-honeypot"
scp -r pi sim attacker tests config.env requirements.txt pytest.ini README.md DEMO.md STARTUP_GUIDE.md your-user@192.168.1.10:~/adaptive-iot-honeypot/
ssh your-user@192.168.1.10
```

On first SSH connection, verify the host fingerprint against your Pi before
accepting it. Enter the Pi user's password when prompted; no characters display
while typing. The last command changes this terminal into **P1**, the Pi shell.

Do not copy `.venv`, `.git`, `run`, `logs`, or an old database from Windows. Run
the SCP step before editing the Pi configuration; repeating it later overwrites
the Pi's `config.env` with your Windows copy.

### P1 — confirm OS, normalize Windows line endings, edit configuration

```bash
cd ~/adaptive-iot-honeypot
cat /proc/device-tree/model
cat /etc/os-release
python3 --version
hostname -I
free -h
df -h .
sed -i 's/\r$//' config.env pi/*.sh tests/*.sh
nano config.env
```

Edit these existing entries in `config.env`; leave the other scoring settings:

```dotenv
PI_IP=192.168.1.10
ESP32_IP=192.168.1.50
REAL_USER=iotuser
REAL_PASS=REPLACE_WITH_YOUR_PASSWORD
PROXY_PORT=1883
REAL_PORT=1884
DECOY_PORT=1885
DASH_PORT=5000
REAL_HOST=127.0.0.1
DECOY_HOST=127.0.0.1
DECOY_BIND_IP=127.0.0.1
WHITELIST_IPS=127.0.0.1,192.168.1.50
BLACKLIST_IPS=
DECOY_FORCE_IPS=
TLS_CERT_PATH=
TLS_KEY_PATH=
MAX_CONNECTIONS=32
CONNECT_TIMEOUT_SEC=15
STARTUP_TIMEOUT_SEC=60
THINGSPEAK_ENABLED=false
```

Replace `REPLACE_WITH_YOUR_PASSWORD` before saving. Use letters, digits, hyphens
and underscores for a shell-safe lab password; avoid spaces, quotes, `#`, `$`,
backticks and shell operators because Pi scripts source this file. Save in Nano
with **Ctrl+O**, Enter, then **Ctrl+X**.

The Windows attack laptop's LAN IP must not appear in the Pi whitelist. The Pi's
loopback address and the real ESP32 IP must be there. Keep ThingSpeak disabled
until local MQTT works; section 10 covers cloud setup.

### P1 — install and verify

```bash
cd ~/adaptive-iot-honeypot
bash pi/setup_pi.sh
.venv/bin/python -m pip check
.venv/bin/python -m pytest -q
.venv/bin/python pi/check_pi.py
```

Run scripts as your normal Pi user, without `sudo bash`. Setup uses sudo for apt
and the system broker service. It installs Mosquitto and Python packages and
generates `data/real.passwd`. It disables the system Mosquitto service so this
project can own port 1883. Internet is needed for installation.

Expected: tests pass, dependencies are consistent, and preflight says PASS.
Test counts may grow; this revision passed 44 tests on Windows. That result is
not a physical Pi acceptance test. If the Pi reports a failure, use section 12.

## 5. Route A: start and prove the legitimate hardware path

### P1 — start gateway services

```bash
cd ~/adaptive-iot-honeypot
bash pi/run_all.sh
.venv/bin/python pi/check_pi.py --running
```

Expected final startup line:

```text
Stack started: MQTT proxy 192.168.1.10:1883; dashboard http://192.168.1.10:5000
```

Startup returns to the prompt. Services continue in the background. Do not start
individual duplicate proxy/broker processes. Keep ESP32 powered and check Serial
Monitor for `MQTT connected`.

### W2 — new normal PowerShell: verify LAN and open dashboard

```powershell
Test-NetConnection 192.168.1.10 -Port 1883
Test-NetConnection 192.168.1.10 -Port 5000
Start-Process 'http://192.168.1.10:5000'
```

Both TCP checks should succeed. Visit Overview, Events, Alerts, Attackers and
Sessions. HTTP on a LAN may not support browser desktop notifications; the
dashboard alert list is the reliable local record.

### P2 — new Pi terminal / second SSH session: watch real device traffic

From a new Windows PowerShell, connect:

```powershell
ssh your-user@192.168.1.10
```

Then run **on the Pi**:

```bash
cd ~/adaptive-iot-honeypot
set -a
source config.env
set +a
mosquitto_sub -h 127.0.0.1 -p "$PROXY_PORT" -u "$REAL_USER" -P "$REAL_PASS" -t 'home/door/#' -v
```

Leave P2 open. Expected: motion messages and retained `home/door/status` JSON
with `source=esp32`. Stop this subscriber later with Ctrl+C.

### P1 — send legitimate unlock, then lock

```bash
cd ~/adaptive-iot-honeypot
set -a
source config.env
set +a
mosquitto_pub -h 127.0.0.1 -p "$PROXY_PORT" -u "$REAL_USER" -P "$REAL_PASS" -t home/door/lock -m unlock
```

Expected: the ESP32 prints UNLOCKED, configured LED goes OFF and status changes.
Now lock it again before the attack:

```bash
mosquitto_pub -h 127.0.0.1 -p "$PROXY_PORT" -u "$REAL_USER" -P "$REAL_PASS" -t home/door/lock -m lock
```

Expected: LOCKED, configured LED ON. Stop here and fix the legitimate path if
these commands do not work. Send legitimate control commands from Pi loopback;
using the attack laptop for controls would mix both roles under one source IP.

### P3 — optional third Pi terminal: watch proxy events

```bash
cd ~/adaptive-iot-honeypot
tail -n 30 -f logs/proxy.log
```

Ctrl+C stops only the log viewer. For alert-file output, run in another terminal
after an alert has been generated:

```bash
cd ~/adaptive-iot-honeypot
tail -n 20 -f logs/alerts.log
```

## 6. Route A: run the authorized attacker from Windows

### W1 or W2 — a Windows prompt, not an SSH prompt

If W1 is still connected to the Pi, use another PowerShell or type `exit` to
return to Windows. Prepare the laptop's independent config copy:

```powershell
Set-Location 'E:\Ali\adaptive-iot-honeypot'
notepad .\config.env
```

Set the Windows copy's `PI_IP=192.168.1.10` to target the Pi. This does not edit
the Pi copy. Keep both copies' scoring defaults aligned for this demonstration.
Do not start `windows/run_all.ps1` in route A.

Confirm the real ESP32 is locked and its LED is ON, then run:

```powershell
Set-Location 'E:\Ali\adaptive-iot-honeypot'
.\.venv\Scripts\python.exe .\attacker\attack.py
```

Do not bind `127.0.0.2` for a remote attack against the Pi. The Pi must see the
laptop's actual LAN IP. Expected: four stages complete and the final fake unlock
is recorded on the decoy. The real ESP32 stays LOCKED and continues publishing.
The exact intermediate action sequence depends on timing and prior scores; the
important final condition is attacker in decoy and legitimate device responsive.

### P1 — confirm legitimate service still works after the attack

```bash
cd ~/adaptive-iot-honeypot
set -a
source config.env
set +a
mosquitto_pub -h 127.0.0.1 -p "$PROXY_PORT" -u "$REAL_USER" -P "$REAL_PASS" -t home/door/lock -m lock
```

P2 should still receive device telemetry. Check Events/Attackers/Sessions in the
browser: attacker sessions should show decoy, while ESP32 sessions use real.

## 7. Route A: evidence, daily restart and shutdown

### W2 — save evidence on Windows while the Pi stack is running

```powershell
Set-Location 'E:\Ali\adaptive-iot-honeypot'
New-Item -ItemType Directory -Force .\work | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
Invoke-WebRequest -UseBasicParsing -Uri 'http://192.168.1.10:5000/api/evidence/export.zip' -OutFile ".\work\pi-evidence-$stamp.zip"
```

Or use **Events → Full evidence ZIP** in the dashboard. Save evidence before
using **Clear logs + scores**. Scores persist across restarts; restarting alone
does not reset the attack history.

### P1 — stop services and shut down the Pi

First Ctrl+C any P2 subscriber/P3 log viewer. Then:

```bash
cd ~/adaptive-iot-honeypot
bash pi/stop_all.sh
sudo shutdown -h now
```

Wait for shutdown before removing power. SSH disconnecting is expected.

### Next day — the short route after successful first-time setup

1. Power Pi, ESP32 and router; confirm IPs have not changed.
2. Windows PowerShell:

   ```powershell
   ssh your-user@192.168.1.10
   ```

3. In that Pi session:

   ```bash
   cd ~/adaptive-iot-honeypot
   bash pi/run_all.sh
   .venv/bin/python pi/check_pi.py --running
   ```

4. Windows browser: open `http://192.168.1.10:5000`.
5. Check ESP32 connection, send the legitimate lock from section 5, then use
   section 6 for the attack. Export evidence, then stop with the commands above.

Do not rerun setup on every boot. Rerun it when dependencies or MQTT credentials
change, after stopping the stack. Update and reflash ESP32 credentials as needed.

## 8. Route B: Windows gateway + real ESP32 if the Pi fails

This runs the actual gateway on Windows without Docker or WSL. The ESP32 still
uses Wi-Fi and the physical relay/LED. Keep the laptop awake during the demo.

### B1 — install Windows broker once

Install the native Windows Mosquitto package from the
[official download page](https://mosquitto.org/download/). Use the usual
`C:\Program Files\Mosquitto` path. The project scripts detect it automatically.
Python preparation is in section 2.

### B1 — normal PowerShell: set the Windows gateway address

```powershell
Set-Location 'E:\Ali\adaptive-iot-honeypot'
Get-NetIPConfiguration
notepad .\config.env
```

Assuming the active Windows LAN address is `192.168.1.20`, set:

```dotenv
PI_IP=192.168.1.20
ESP32_IP=192.168.1.50
REAL_USER=iotuser
REAL_PASS=REPLACE_WITH_YOUR_PASSWORD
WHITELIST_IPS=127.0.0.1,192.168.1.50
REAL_HOST=127.0.0.1
DECOY_HOST=127.0.0.1
DECOY_BIND_IP=127.0.0.1
DECOY_FORCE_IPS=
BLACKLIST_IPS=
TLS_CERT_PATH=
TLS_KEY_PATH=
THINGSPEAK_ENABLED=false
```

Keep ports 1883/1884/1885/5000 distinct. Do not whitelist `127.0.0.2`. Do not
whitelist the address of a second attack laptop. The name `PI_IP` now denotes the
Windows gateway; the code does not require that host to be a Pi.

Reflash the ESP32 as in section 3 with `PI_IP="192.168.1.20"` and the matching
credentials. This firmware change is required when moving the gateway.

### B-admin — PowerShell opened with Run as administrator: initial setup

```powershell
Set-Location 'E:\Ali\adaptive-iot-honeypot'
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\windows\setup.ps1
```

Process scope expires when this window closes. Setup stops/disables an installed
system Mosquitto service to free port 1883. On a machine already hosting another
MQTT project, resolve that project's service/port needs before doing this.

For LAN access, on your trusted lab network use the Windows **Private** network
profile. Inspect it before adding the following narrowly scoped rules:

```powershell
Get-NetConnectionProfile
New-NetFirewallRule -DisplayName 'IoT Honeypot MQTT lab' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 1883 -Profile Private -RemoteAddress LocalSubnet
New-NetFirewallRule -DisplayName 'IoT Honeypot Dashboard lab' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5000 -Profile Private -RemoteAddress LocalSubnet
```

Add these rules once; skip if already present. A Public network profile will not
match them. Change the trusted network's profile through Windows Network settings
if appropriate. Leave backend ports 1884/1885 closed to the LAN.

### B1 — normal PowerShell: start the stack

```powershell
Set-Location 'E:\Ali\adaptive-iot-honeypot'
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\windows\run_all.ps1
Test-NetConnection 127.0.0.1 -Port 1883
(Invoke-WebRequest -UseBasicParsing 'http://127.0.0.1:5000/').StatusCode
Start-Process 'http://127.0.0.1:5000'
```

Expected: stack started, TCP success, HTTP 200. Check ESP32 Serial Monitor for
MQTT connected. On another LAN device the dashboard is at
`http://192.168.1.20:5000`. Do not use `pi/check_pi.py` as the Windows doctor:
it expects Unix executable names. Use these native checks instead.

### B2 — new normal PowerShell: watch physical device messages

```powershell
Set-Location 'E:\Ali\adaptive-iot-honeypot'
. .\windows\common.ps1
$Config = Import-ConfigEnv (Join-Path (Get-Location) 'config.env')
$Sub = Get-RequiredExecutable 'mosquitto_sub.exe'
& $Sub -h 127.0.0.1 -p $Config.PROXY_PORT -u $Config.REAL_USER -P $Config.REAL_PASS -t 'home/door/#' -v
```

Leave this window open. Expected source is `esp32`, not `sim-esp32`.

### B1 — legitimate commands use local trusted loopback

```powershell
Set-Location 'E:\Ali\adaptive-iot-honeypot'
. .\windows\common.ps1
$Config = Import-ConfigEnv (Join-Path (Get-Location) 'config.env')
$Pub = Get-RequiredExecutable 'mosquitto_pub.exe'
& $Pub -h 127.0.0.1 -p $Config.PROXY_PORT -u $Config.REAL_USER -P $Config.REAL_PASS -t home/door/lock -m unlock
```

Confirm UNLOCKED/LED OFF, then relock:

```powershell
& $Pub -h 127.0.0.1 -p $Config.PROXY_PORT -u $Config.REAL_USER -P $Config.REAL_PASS -t home/door/lock -m lock
```

### B3 — new normal PowerShell: isolated attacker on the same Windows laptop

First check the separate source can bind:

```powershell
Set-Location 'E:\Ali\adaptive-iot-honeypot'
.\.venv\Scripts\python.exe -c "import socket; s=socket.socket(); s.bind(('127.0.0.2',0)); s.close(); print('Attacker source bind OK')"
```

Then override the target only in this terminal for this local attack. The ESP32
continues using the LAN address stored in its sketch:

```powershell
$env:PI_IP = '127.0.0.1'
try {
    .\.venv\Scripts\python.exe .\attacker\attack.py --source-ip 127.0.0.2
} finally {
    Remove-Item Env:\PI_IP -ErrorAction SilentlyContinue
}
```

Expected: the proxy sees attacker `127.0.0.2`, legitimate control `127.0.0.1`,
and the actual ESP32 LAN IP separately. ESP32 stays locked during fake unlock.
If binding fails or the source is not distinct in Events, use a second laptop:
prepare Python as in section 2 there, set its config target to `192.168.1.20`,
and run `attack.py` without `--source-ip`. Do not remove trusted loopback from
the whitelist as a workaround. A single-machine source-isolated attack demo
cannot be guaranteed when local security/network software blocks that source.

### B1 — export and stop

```powershell
Set-Location 'E:\Ali\adaptive-iot-honeypot'
New-Item -ItemType Directory -Force .\work | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:5000/api/evidence/export.zip' -OutFile ".\work\windows-esp32-evidence-$stamp.zip"
.\windows\stop_all.ps1
```

Ctrl+C the B2 subscriber as well. To remove the optional lab firewall rules
when LAN access is no longer needed, run in administrator PowerShell:

```powershell
Remove-NetFirewallRule -DisplayName 'IoT Honeypot MQTT lab'
Remove-NetFirewallRule -DisplayName 'IoT Honeypot Dashboard lab'
```

For later starts, use `windows/run_all.ps1`; setup is not needed every time.

## 9. Route C: Windows-only demo when Pi or ESP32 is unavailable

This proves routing, scoring, audit, dashboard and simulated lock behavior. It
does not prove physical ESP32 wiring or Raspberry Pi performance. No LAN inbound
firewall rules are needed for this loopback-only route.

### C1 — normal PowerShell: configure local mode

Install Python and Mosquitto as described in sections 2 and 8. Disconnect the
real ESP32 or power it down so it cannot mix with simulator state. Stop any
existing Windows stack before changing config:

```powershell
Set-Location 'E:\Ali\adaptive-iot-honeypot'
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\windows\stop_all.ps1
notepad .\config.env
```

Set these existing entries, preserving the scoring defaults and other keys:

```dotenv
PI_IP=127.0.0.1
ESP32_IP=127.0.0.1
WHITELIST_IPS=127.0.0.1
REAL_USER=iotuser
REAL_PASS=REPLACE_WITH_YOUR_PASSWORD
REAL_HOST=127.0.0.1
DECOY_HOST=127.0.0.1
DECOY_BIND_IP=127.0.0.1
DECOY_FORCE_IPS=
BLACKLIST_IPS=
TLS_CERT_PATH=
TLS_KEY_PATH=
THINGSPEAK_ENABLED=false
```

Keep `127.0.0.2` out of the whitelist. Keep the standard ports and weights for
the automated smoke test. All tools read the same password from config.

### C-admin — administrator PowerShell: setup once / after changing credentials

```powershell
Set-Location 'E:\Ali\adaptive-iot-honeypot'
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\windows\setup.ps1
```

### C1 — normal PowerShell: automated rehearsal first

```powershell
Set-Location 'E:\Ali\adaptive-iot-honeypot'
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\python.exe -m pytest -q
.\tests\smoke_test.ps1
```

The smoke test starts its own stack and simulator, exercises the attack, verifies
legitimate messages before/after, then stops them. It temporarily backs up and
restores the previous database/relay file. It writes test logs. Do not interrupt
it; if interrupted, preserve `run/smoke-backup` for recovery. Successful final
lines include `PASS` and `relay stayed LOCKED`. It leaves the stack stopped,
and its temporary attack records are not a persistent presentation dataset.

If the test fails due to loopback-source binding, see B3. You can still run the
legitimate simulator, dashboard and unit tests, but need a second host for the
full separated-source attack proof in that Windows environment.

### C1 — start the live demonstration after the rehearsal

```powershell
Set-Location 'E:\Ali\adaptive-iot-honeypot'
.\windows\run_all.ps1
Start-Process 'http://127.0.0.1:5000'
```

### C2 — new normal PowerShell: simulator, leave running

```powershell
Set-Location 'E:\Ali\adaptive-iot-honeypot'
.\.venv\Scripts\python.exe .\sim\sim_esp32.py
```

Expected: `relay=LOCKED`, MQTT success, repeated `motion=0`/`motion=1`. The
dashboard device source is `sim-esp32`. Do not close C2 until the demo is finished.

### C3 — new normal PowerShell: legitimate subscriber

```powershell
Set-Location 'E:\Ali\adaptive-iot-honeypot'
. .\windows\common.ps1
$Config = Import-ConfigEnv (Join-Path (Get-Location) 'config.env')
$Sub = Get-RequiredExecutable 'mosquitto_sub.exe'
& $Sub -h 127.0.0.1 -p $Config.PROXY_PORT -u $Config.REAL_USER -P $Config.REAL_PASS -t 'home/door/#' -v
```

### C1 — prove simulated unlock/lock before attacking

```powershell
Set-Location 'E:\Ali\adaptive-iot-honeypot'
. .\windows\common.ps1
$Config = Import-ConfigEnv (Join-Path (Get-Location) 'config.env')
$Pub = Get-RequiredExecutable 'mosquitto_pub.exe'
& $Pub -h 127.0.0.1 -p $Config.PROXY_PORT -u $Config.REAL_USER -P $Config.REAL_PASS -t home/door/lock -m unlock
Start-Sleep -Seconds 1
Get-Content .\sim\relay_state.txt
& $Pub -h 127.0.0.1 -p $Config.PROXY_PORT -u $Config.REAL_USER -P $Config.REAL_PASS -t home/door/lock -m lock
Start-Sleep -Seconds 1
Get-Content .\sim\relay_state.txt
```

Expected: UNLOCKED followed by LOCKED. The simulator in C2 should print both.

### C4 — new normal PowerShell: attack the local gateway

```powershell
Set-Location 'E:\Ali\adaptive-iot-honeypot'
.\.venv\Scripts\python.exe .\attacker\attack.py --source-ip 127.0.0.2
Get-Content .\sim\relay_state.txt
```

Expected: four stages complete; relay file is still LOCKED. C2/C3 keep printing
legitimate traffic. Open Events/Attackers/Sessions and select attacker
`127.0.0.2`; verify decoy sessions and the fake unlock. Simulator connections
from `127.0.0.1` must remain real.

### C1 — save evidence, then stop everything

```powershell
Set-Location 'E:\Ali\adaptive-iot-honeypot'
New-Item -ItemType Directory -Force .\work | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:5000/api/evidence/export.zip' -OutFile ".\work\windows-simulator-evidence-$stamp.zip"
```

Press Ctrl+C in C2 and C3, then in C1:

```powershell
.\windows\stop_all.ps1
```

The launcher manages only the five services. A manually started simulator,
subscriber or log viewer must be stopped in its own window.

## 10. Optional: enable ThingSpeak after local startup works

Use the active gateway's `config.env`: Pi copy for A, Windows copy for B/C.
In your ThingSpeak account create a channel with these six fields:

| Field | Data |
| --- | --- |
| 1 | motion |
| 2 | locked |
| 3 | LED on |
| 4 | risk score |
| 5 | action code: allow 0, throttle 1, restrict 2, decoy 3 |
| 6 | event points |

Set `THINGSPEAK_ENABLED=true`, `THINGSPEAK_WRITE_API_KEY` to the channel's Write
API Key, `THINGSPEAK_CHANNEL_ID` to its ID and `THINGSPEAK_INTERVAL_SEC=15`.
Do not use the Read API Key. Do not commit the configured write key.

Restart only the active gateway after saving:

**Pi, P1:**

```bash
cd ~/adaptive-iot-honeypot
bash pi/stop_all.sh
bash pi/run_all.sh
tail -n 30 -f logs/proxy.log
```

**Windows, B1/C1:**

```powershell
Set-Location 'E:\Ali\adaptive-iot-honeypot'
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\windows\stop_all.ps1
.\windows\run_all.ps1
Get-Content .\logs\proxy.err.log -Tail 30 -Wait
```

Ctrl+C stops the log viewer only. Open ThingSpeak Private View in the laptop
browser and allow time for the configured upload interval. Cloud delivery is
optional; local control/decoy routing does not require cloud availability.

## 11. Hardware-free Pi rehearsal, optional

Use this only on a disposable/fresh Pi demo dataset: the existing Linux smoke
test **deletes the current demo database and relay-state file**. Export required
evidence first. Power down/disconnect the real ESP32 while simulating it.

On Pi, stop services, edit `config.env` to `PI_IP=127.0.0.1`, include
`127.0.0.1` in the whitelist and exclude `127.0.0.2`:

```bash
cd ~/adaptive-iot-honeypot
bash pi/stop_all.sh
nano config.env
bash tests/smoke_test.sh
```

The test starts/stops its own services. Restore the Pi LAN `PI_IP`, actual
`ESP32_IP` and whitelist afterward before returning to physical route A.

## 12. Recovery commands and how to choose a fallback

### Pi will not boot or cannot be reached by SSH

Check power, SD image and router client list. Attach a local monitor/keyboard
if available. If SSH fails but the Pi desktop/console works, run sections 4–5
directly in a Pi terminal; only transfer depends on SSH. If the board still
cannot be used, take route B with ESP32 or route C without it.

### Pi script says CRLF / `$'\r'` / bad interpreter

**Pi terminal:**

```bash
cd ~/adaptive-iot-honeypot
sed -i 's/\r$//' config.env pi/*.sh tests/*.sh
bash pi/setup_pi.sh
```

Use `bash script.sh` as shown; executable permission is not required.

### Pi setup rejects Python or a copied virtual environment

**Pi terminal:**

```bash
python3 --version
ls -ld ~/adaptive-iot-honeypot/.venv
```

Python below 3.11: install OS Lite Bookworm or newer, or use Windows fallback.
For an accidentally copied Windows environment, stop project processes and
rename it to an unused backup name before recreating it:

```bash
cd ~/adaptive-iot-honeypot
mv .venv .venv-windows-backup
bash pi/setup_pi.sh
```

### Pi startup fails or a port is busy

**Pi terminal:**

```bash
cd ~/adaptive-iot-honeypot
bash pi/stop_all.sh
sudo ss -ltnp
tail -n 50 logs/real-broker.log logs/decoy-broker.log logs/proxy.log logs/dashboard.log
.venv/bin/python pi/check_pi.py
```

Stop the identified conflicting service or choose distinct ports in config,
then update matching clients. Do not kill arbitrary Python processes. For an
unneeded default system Mosquitto service occupying 1883:

```bash
sudo systemctl disable --now mosquitto
bash pi/run_all.sh
```

### Windows cannot execute `.ps1`

**Normal PowerShell, each new window that runs project scripts:**

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

If Group Policy overrides this, use an approved PowerShell environment; do not
disable system security controls. The Python unit tests can still run directly.

### Windows cannot find Mosquitto / startup fails

**Normal PowerShell:**

```powershell
Set-Location 'E:\Ali\adaptive-iot-honeypot'
Test-Path 'C:\Program Files\Mosquitto\mosquitto.exe'
Test-Path 'C:\Program Files\Mosquitto\mosquitto_sub.exe'
Test-Path 'C:\Program Files\Mosquitto\mosquitto_pub.exe'
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -in 1883,1884,1885,5000 } | Select-Object LocalAddress,LocalPort,OwningProcess
Get-ChildItem .\logs\*.err.log | ForEach-Object { Write-Output $_.Name; Get-Content $_.FullName -Tail 20 }
```

If installed elsewhere, prepend its actual folder in each relevant PowerShell:

```powershell
$env:Path = 'D:\YourMosquittoFolder;' + $env:Path
```

If the default Windows service owns 1883, use administrator PowerShell to run
`windows/setup.ps1` as in section 8. Otherwise identify the owning process using
`Get-Process -Id <OwningProcess>` (replace the placeholder with the number).
Stop only the identified conflicting service through its normal controls.

### Dashboard works locally but the ESP32 or another laptop cannot connect

Check the active gateway LAN IP, Wi-Fi subnet, private-profile firewall rules
for Windows route B, and router guest/client isolation. Port 1883 is for clients;
1884 is a loopback backend and must not be used by ESP32. On a second Windows
host, run against the active gateway address:

```powershell
Test-NetConnection 192.168.1.20 -Port 1883
Test-NetConnection 192.168.1.20 -Port 5000
```

For route A replace `.20` with the Pi's address. A failed ping alone does not
prove MQTT is down; use the TCP port result. If Wi-Fi works but MQTT auth fails,
match `REAL_USER`, `REAL_PASS`, sketch `MQTT_USER`, and `secrets.h` `MQTT_PASS`,
stop the stack, rerun setup to regenerate password hashes, then restart/reflash.

### Attacker still reaches real / simulator is redirected

Inspect Events for the actual source IP. Attacker must not be whitelisted.
Simulator/control loopback must be whitelisted. The real ESP32 address must be
whitelisted. Keep `DECOY_FORCE_IPS` empty for adaptive scoring. Use B3/C4 for
local attacks, section 6 for remote attacks. Never use the same source IP for
both roles. Existing scores persist; export evidence before deliberately clearing
scores with the dashboard control for a clean rerun.

### Interrupted Windows smoke test

Stop the managed stack first. Inspect the backup rather than deleting it:

```powershell
Set-Location 'E:\Ali\adaptive-iot-honeypot'
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\windows\stop_all.ps1
Get-ChildItem .\run\smoke-backup -Force
```

If a simulator was left open, stop it too. Copy the backup to a separate safe
folder before recovery. It may contain the original SQLite database, WAL/SHM
files and relay state; preserve them as a set. Do not rerun the smoke test until
the backup has been recovered or deliberately archived out of that path.

### Low memory, disk full or Pi instability

**Pi terminal:**

```bash
cd ~/adaptive-iot-honeypot
free -h
df -h .
du -sh data logs
vcgencmd get_throttled
top
```

Press `q` to leave top. Use Lite, close local desktop/browser workloads and
reduce demo traffic. Investigate power/temperature when throttling is reported.
Export evidence and stop services before archiving old data/logs. Use route B/C
for presentation continuity if the physical kit remains unstable.

## 13. Final demo checklist

- Exactly one gateway is running; target IP matches the chosen route.
- Exactly one device source is active: physical ESP32 or simulator.
- Legitimate unlock and lock work before the attack; start the attack locked.
- Attacker and legitimate sources have different IPs and whitelist treatment.
- Attacker's final unlock is logged in decoy; real/simulated device stays locked.
- Legitimate telemetry and commands still work afterward.
- Export the evidence ZIP before clearing history or shutting down.
- Stop manual simulator/subscribers, stop gateway services, then shut down Pi.

This guide was checked against the repository scripts and API routes. The Pi
installation, physical wiring and LAN/firewall behavior still need testing on
your actual devices; the Windows-only route is a fallback for those dependencies.
