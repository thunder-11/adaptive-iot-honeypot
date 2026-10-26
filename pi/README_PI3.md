# Raspberry Pi 3 first-boot guide

The intended target is a Pi 3 Model B or B+ with 1 GB RAM, running the native
Mosquitto/Python stack. The same code can run on 32-bit ARM or 64-bit ARM; no
GPIO libraries, machine-learning runtime, or compiled Python extensions are needed
by the application. Pi 3 A+ has less RAM: use Lite and start with a small demo;
its capacity has not been measured. Physical Pi/ARM testing is still required.

## Prepare the kit

1. Use Raspberry Pi Imager, select your actual Pi 3 model, and install **Raspberry
   Pi OS Lite (32-bit), Bookworm or newer**. Lite 64-bit is also compatible with
   the code. The 32-bit Lite recommendation keeps OS memory use lower. Python
   **3.11 or newer** is required; an old Bullseye card with Python 3.9 will not work.
2. Configure your own username, password, SSH, Wi-Fi country and Wi-Fi credentials
   in Imager before flashing. There is no assumed `pi` user. Use a reliable microSD
   card (16 GB minimum suggested; 32 GB gives more space for evidence).
3. Use a good **5.1 V / 2.5 A micro-USB supply**, as recommended by
   [Raspberry Pi](https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#power-supply).
   Leave ventilation around the board. Power the ESP32/relay as specified by its
   hardware; the Pi is the network gateway, and this project requires no Pi GPIO wiring.
4. Pi 3 B Wi-Fi uses **2.4 GHz**; configure a 2.4 GHz network usable by the ESP32
   too. Ethernet is useful on B/B+. Disable guest/client isolation so your laptop,
   ESP32 and Pi can communicate. Reserve the Pi/ESP32 addresses in your router's
   DHCP settings. See the [official Pi 3 B specifications](https://www.raspberrypi.com/products/raspberry-pi-3-model-b/).

## Transfer the source from Windows

Find the Pi address in your router and use it below. In PowerShell, from this
project folder (replace the sample username and address):

```powershell
ssh your-user@192.168.1.10 "mkdir -p ~/adaptive-iot-honeypot"
scp -r pi sim attacker tests config.env requirements.txt pytest.ini README.md DEMO.md your-user@192.168.1.10:~/adaptive-iot-honeypot/
ssh your-user@192.168.1.10
```

These are the gateway sources and tests. Keep ESP32 flashing on Windows. Do not
copy the Windows `.venv`, `run/`, or old `data/` onto the Pi. If a previous copy
included `.venv`, move it aside before setup (`mv .venv .venv.windows-backup`,
using an unused backup name). Linux needs its own virtual environment.

## Install and start on the Pi

Run as the normal user, without prefixing these scripts with sudo:

```bash
cd ~/adaptive-iot-honeypot
python3 --version
hostname -I
nano config.env
```

Set `PI_IP` to the Pi's LAN address, `ESP32_IP` to the reserved ESP32 address,
`REAL_USER`/`REAL_PASS` to the same credentials used by the ESP32, and
`WHITELIST_IPS=127.0.0.1,<ESP32-address>`. Replace the angle-bracket placeholder.
Keep the attack laptop off that whitelist. Keep the backend hosts and
`DECOY_BIND_IP` at `127.0.0.1`. Keep TLS paths empty for the plaintext demo.
Passwords must follow the shell-safe restrictions in the main README.

```bash
bash pi/setup_pi.sh
.venv/bin/python pi/check_pi.py
.venv/bin/python -m pytest -q
bash pi/run_all.sh
.venv/bin/python pi/check_pi.py --running
```

Setup needs Internet for apt/pip and sudo access. It disables the system
Mosquitto service because the project starts its own two brokers. If this Pi
already serves another MQTT project, resolve its ports/service needs first.
The launcher waits up to `STARTUP_TIMEOUT_SEC=60` per listener and rolls back a
failed partial launch. Read the named service log if startup fails.

Open `http://<Pi-LAN-IP>:5000` **on the laptop**. The ESP32 must connect to that
same Pi address on port 1883, with the matching credentials. Only ports 1883 and
5000 need LAN access; keep 1884/1885 local. Do not forward these ports to the Internet.

## Hardware-free rehearsal on the Pi

Before setting real LAN addresses, keep `PI_IP=127.0.0.1`, include `127.0.0.1`
in `WHITELIST_IPS`, and leave `127.0.0.2` out of it. On a **fresh demo copy with
no evidence to preserve**, run:

```bash
bash tests/smoke_test.sh
```

This existing test clears the demo database, starts the simulator, exercises
real and decoy routes, checks the relay remains locked, then stops the stack.
Afterward restore the Pi/ESP32 LAN settings before using hardware. No ESP32 is
needed for this rehearsal. Live hardware acceptance is complete only after a
legitimate lock/unlock works and the authorized attacker remains in the decoy
while the real ESP32 stays responsive; follow the main README runbook.

## Keep the Pi 3 responsive

- Use the native scripts; the multi-container Docker demo is optional and has
  more overhead. Open the dashboard on the laptop and run attack tools there.
- The proxy defaults to **32 concurrent connections** and a **15-second MQTT
  CONNECT deadline**. Excess connections close so clients can retry. These are
  conservative guardrails, not measured throughput guarantees. Completed
  connections release both forwarding tasks and their connection slots.
- Keep initial tests small. Check `free -h`, `df -h .`, `top`, and
  `vcgencmd get_throttled` (0x0 means no reported current/historical throttling).
  A nonzero result needs decoding; power/temperature problems are hardware issues.
- Measure the proxy on the actual board before increasing load:

  ```bash
  .venv/bin/python pi/analysis/measure_resources.py --pid "$(cat run/proxy.pid)" --duration 60
  ```

- Evidence and logs grow with traffic. Check `du -sh data logs`, archive evidence
  and rotate logs between runs. This is a classroom demo, not unattended storage
  with automatic retention. Shut down with `bash pi/stop_all.sh` and then
  `sudo shutdown -h now` before disconnecting power.

## Common first-boot fixes

| Symptom | Action |
| --- | --- |
| `$'\r': command not found` | Windows line endings: run `sed -i 's/\r$//' config.env pi/*.sh tests/*.sh`, then retry with `bash`. |
| Python version rejected | Flash OS Lite Bookworm or newer; do not replace the OS system Python manually. |
| `.venv/bin/python` missing | Move the Windows environment aside and rerun Pi setup. |
| Port busy | Stop the conflicting service; `sudo ss -ltnp` shows listeners. |
| Broker permission denied | Keep the source under your user's home and run setup/start as that user. Check the broker log. |
| Laptop cannot open dashboard | Confirm Pi address, same LAN, client isolation, and any firewall rules for 1883/5000. Run `check_pi.py --running` locally. |
| ESP32 fails but dashboard works | Match Pi IP, credentials, static subnet and whitelist in config and sketch; watch ESP32 Serial Monitor. |
| Cloud updates fail | Local MQTT works offline; ThingSpeak needs Internet and a valid write key. |

No physical Pi was available when these changes were authored. Passing desktop
tests does not certify the kit's SD card, power supply, Wi-Fi, ARM installation,
or performance under attack; the on-board checks above cover that final step.

## Updated console and demo workflow

After starting the stack, open `http://PI_IP:5000` from the laptop. In Settings,
Test connection verifies the dashboard data endpoints; it does not prove that
MQTT brokers or the ESP32 are available. Appearance offers the default light
console and a pure black dark background. Saved refresh intervals are 3, 5, 10,
or 30 seconds. Hard-refresh the browser after copying updated sources.

See [DEMO.md](../DEMO.md) for the presentation sequence and
[attacker/README.md](../attacker/README.md) for eight individual attack scenarios
and a benign control with verified JSON evidence reports. Use Events & Alerts
for full-history filters and CSV/ZIP exports, and Honeypot / Decoy for recorded
sessions/messages. Attacker details and session durations refresh automatically.
