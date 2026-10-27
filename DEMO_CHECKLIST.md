# Raspberry Pi + ESP32 demonstration checklist

Use this checklist for the physical demonstration. The gateway code is tested
with native Mosquitto on Windows; installation, Wi-Fi, wiring and relay polarity
still need verification on your Pi and ESP32 before presenting.

## 1. Match the hardware and network

Your photo appears to show a classic 30-pin ESP32 development board with a CP2102
USB chip. In Arduino IDE, start with **ESP32 Dev Module** and select the actual
COM port. The board's red indicator may be a power LED; it is not evidence that
GPIO2 is following the lock state. The underside wiring was not visible.

For the default `BUTTON` sketch, wire with USB power disconnected:

| Connection | ESP32 pin |
| --- | --- |
| Button to ground | D27 / GPIO27 and GND |
| External LED anode, through a 220–330 ohm resistor | D2 / GPIO2 |
| External LED cathode | GND |
| Compatible relay input, if using a relay | D26 / GPIO26 |

The default LED wiring uses `LED_ACTIVE_HIGH=true`: locked means LED off,
unlocked means LED on. `RELAY_ACTIVE_LOW=true` is a separate setting; confirm
it matches the relay module. Use a 3.3 V-compatible driver and a low-voltage demo
load. The sketch cannot control the output during the board's power-on reset;
the relay input needs an appropriate inactive hardware bias if glitches matter.

For the optional LDR mode, use **D34 / GPIO34 (ADC1)** for the divider output.
GPIO27 is ADC2 on this classic ESP32 and cannot provide reliable analog readings
while Wi-Fi is active ([Espressif ADC documentation](https://docs.espressif.com/projects/esp-idf/en/v4.2.1/esp32/api-reference/peripherals/adc.html)).
DHT mode is selected with `DHT11_SENSOR`, not `DHT11`.

Put the Pi, ESP32 and Windows laptop on the same network. Use a 2.4 GHz network
for the ESP32; disable guest/client isolation. Reserve separate Pi and ESP32
addresses in the router to avoid collisions with the sketch's static address.

## 2. Configure and flash the ESP32 on Windows

Install **esp32 by Espressif Systems** in Boards Manager and **PubSubClient** in
Library Manager. All five sensor modes were compile-checked with **ESP32 core
2.0.17** and **PubSubClient 2.8.0**; select those versions to reproduce that build.
The default button mode requires no sensor libraries. DHT mode additionally
requires Adafruit DHT sensor library and Adafruit Unified Sensor.

From PowerShell:

```powershell
cd E:\Ali\adaptive-iot-honeypot
if (-not (Test-Path .\esp32\esp32_node\secrets.h)) {
    Copy-Item .\esp32\esp32_node\secrets.h.example .\esp32\esp32_node\secrets.h
}
notepad .\esp32\esp32_node\secrets.h
```

Set the actual Wi-Fi name, Wi-Fi password and MQTT password. In
`esp32/esp32_node/esp32_node.ino`, set `PI_IP`, `MQTT_USER`, `ESP32_STATIC_IP`,
`GATEWAY`, and `SUBNET` for the demonstration network. Keep MQTT port 1883 unless
you changed the gateway's proxy port. Verify and upload. Open Serial Monitor at
**115200 baud**. Keep the original firmware/configuration values available.

Expected after the Pi stack starts: `Wi-Fi connected`, the correct ESP32 IP,
`MQTT connected`, `Subscribed to: home/door/lock`, and status JSON containing
`"locked":true,"led_on":false`. Status is refreshed every ten seconds.

## 3. Transfer the updated gateway sources

On Windows, replace `YOUR_USER` and `PI_LAN_IP` in these commands:

```powershell
cd E:\Ali\adaptive-iot-honeypot
ssh YOUR_USER@PI_LAN_IP "mkdir -p ~/adaptive-iot-honeypot"
scp -r pi sim attacker tests config.env requirements.txt pytest.ini README.md DEMO.md DEMO_CHECKLIST.md YOUR_USER@PI_LAN_IP:~/adaptive-iot-honeypot/
ssh YOUR_USER@PI_LAN_IP
```

Do not copy the Windows `.venv`, `run`, or old `data` folders to the Pi. Copying
`config.env` replaces the Pi copy, so preserve any Pi-specific configuration
before updating an existing installation.

## 4. Pi terminal 1: configure and start the gateway

Use Raspberry Pi OS Bookworm or newer with Python 3.11+. Run as your normal Pi
user; the setup script uses sudo where required.

```bash
cd ~/adaptive-iot-honeypot
nano config.env
```

Set these values to match the sketch:

```text
PI_IP=<actual Pi LAN IP>
ESP32_IP=<actual ESP32 LAN IP>
REAL_USER=<same MQTT username as sketch>
REAL_PASS=<same MQTT password as secrets.h>
WHITELIST_IPS=127.0.0.1,<actual ESP32 LAN IP>
BLACKLIST_IPS=
DECOY_FORCE_IPS=
DECOY_BIND_IP=127.0.0.1
TLS_CERT_PATH=
TLS_KEY_PATH=
```

Remove the angle-bracket placeholders. Keep the Windows attack laptop's IP out
of the whitelist. Leave TLS paths empty: the bundled ESP32 sketch uses plaintext
MQTT. Keep default weights and thresholds for the demonstrated sequence.

For first-time installation or after changing the broker password:

```bash
bash pi/setup_pi.sh
```

Start and check the stack:

```bash
.venv/bin/python pi/check_pi.py --hardware
bash pi/run_all.sh
.venv/bin/python pi/check_pi.py --hardware --running
```

After powering the ESP32, allow time for Wi-Fi/MQTT connection, then run:

```bash
.venv/bin/python pi/check_pi.py --hardware --running --device
```

The device check requires recent status from the configured ESP32 IP, so an old
database row or running dashboard alone cannot pass it. If it fails, check Serial
Monitor, address/credentials, Wi-Fi isolation and the whitelist before presenting.

To watch gateway activity:

```bash
tail -f logs/proxy.log
```

## 5. Pi terminal 2: show real device traffic

```bash
cd ~/adaptive-iot-honeypot
eval "$(.venv/bin/python pi/config.py --shell)"
mosquitto_sub -h 127.0.0.1 -p "$PROXY_PORT" -u "$REAL_USER" -P "$REAL_PASS" -t 'home/door/#' -v
```

This runs from trusted loopback on the Pi. Expect sensor messages every two
seconds and retained status. Do not run the simulated ESP32 alongside the physical
ESP32: both publish the same status topics.

## 6. Pi terminal 3: prove legitimate control

```bash
cd ~/adaptive-iot-honeypot
eval "$(.venv/bin/python pi/config.py --shell)"
mosquitto_pub -h 127.0.0.1 -p "$PROXY_PORT" -u "$REAL_USER" -P "$REAL_PASS" -t home/door/lock -m unlock
```

Confirm the physical external LED turns on, Serial Monitor says UNLOCKED, and
the dashboard reports UNLOCKED / LED ON. Then relock:

```bash
mosquitto_pub -h 127.0.0.1 -p "$PROXY_PORT" -u "$REAL_USER" -P "$REAL_PASS" -t home/door/lock -m lock
```

Confirm physical LED off and dashboard LOCKED / LED OFF. Do this before running
attacks. Trusted commands should not add classified attacks.

## 7. Windows terminal 4: attack your lab gateway

On Windows, edit the laptop copy of `config.env`: set `PI_IP` to the actual Pi
LAN IP and use the same ports and real-broker credentials. The default
`PI_IP=127.0.0.1` would target Windows rather than the Pi.

```powershell
cd E:\Ali\adaptive-iot-honeypot
.\.venv\Scripts\python.exe .\attacker\brute_force.py
```

Require **PASS** and retain the JSON report. Check the Brute force category count
and Events & Alerts on `http://PI_LAN_IP:5000`. Three failed logins alone need not
reach CRITICAL; this scenario demonstrates authentication detection.

All trials from one remote laptop share its LAN IP. Before an independent next
trial, export the evidence, use **Clear logs + scores**, and wait at least two
seconds. This deliberately removes recorded evidence and resets live risk. It is
not done automatically. Otherwise earlier risk, decoy routing or authentication
caps can change the next result. Total attackers counts IPs, not attack attempts.

For the full redirect demonstration, start with fresh trial state and run:

```powershell
.\.venv\Scripts\python.exe .\attacker\attack.py
```

On the Pi, watch `tail -f logs/proxy.log` or the dashboard's Events & Alerts,
Attackers, and Honeypot / Decoy pages. Require evidence of a decoy session and
the decoy `home/door/lock = unlock` message. The physical device must remain
LOCKED / LED OFF. Finally repeat a legitimate unlock/lock from Pi terminal 3
to prove the real device remains available.

## 8. Stop and recover

Stop subscribers/log watchers with Ctrl+C. On the Pi:

```bash
cd ~/adaptive-iot-honeypot
bash pi/stop_all.sh
```

For startup failures, inspect `logs/real-broker.log`, `logs/decoy-broker.log`,
`logs/proxy.log` and `logs/dashboard.log`. If shell scripts acquired CRLF during
transfer, run `sed -i 's/\r$//' pi/*.sh tests/*.sh` before retrying with Bash.
The config loader already accepts BOM/CRLF in `config.env`.

Prepare today: flash the board, verify the actual network addresses and
lock/unlock behavior, save a successful report, and keep this checklist locally.
