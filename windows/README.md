# Native Windows development

This directory runs the same five services as `pi/run_all.sh` directly on Windows: the authenticated real Mosquitto broker, anonymous decoy broker, decoy publisher, inspection proxy, and Flask dashboard. It does not use WSL, a VM, Docker, or a Windows service.

## Prerequisites

- 64-bit Python 3.11 or newer, with the `py` launcher or `python.exe` on `PATH`.
- Mosquitto for Windows. The scripts detect its normal `C:\Program Files\Mosquitto` installation even when it is not on `PATH`. The smoke test also requires `mosquitto_sub.exe` from that installation.
- Windows PowerShell 5.1 or PowerShell 7. Run the initial setup from an elevated PowerShell if the Mosquitto installer registered its automatic Windows service; setup stops and disables that conflicting broker just as `pi/setup_pi.sh` disables the Linux system service.

From the repository root:

```powershell
.\windows\setup.ps1
.\windows\run_all.ps1
# Dashboard: http://127.0.0.1:5000 (with the default config.env)
.\tests\smoke_test.ps1
.\windows\stop_all.ps1
```

No activation step is needed; scripts call `.venv\Scripts\python.exe` directly. `config.env` remains the runtime configuration source. Setup creates `data\`, `logs\`, and `run\`, installs `requirements.txt`, creates the hashed real-broker password file, and renders both broker configurations.

Process IDs plus start time and executable identity are recorded in `run\windows-processes.json`. `stop_all.ps1` validates all three before stopping a process, so a stale/reused PID cannot cause an unrelated Python or Mosquitto process to be killed.

## Loopback test behavior

The smoke test asks Python to bind the attacker socket to `127.0.0.2`; Windows routes the IPv4 `127.0.0.0/8` loopback block without the Linux `ip addr` alias command on supported current Windows releases. Legitimate simulator traffic remains on whitelisted `127.0.0.1`, so the test exercises the real per-IP scoring and routing behavior.

If the initial bind check fails on a particular Windows/network security configuration, the test stops with a clear error. It does not weaken the production proxy, forge a client identity, or fall back to mixing legitimate and attack traffic under one IP. Run the unit tests and lifecycle checks, but use a second physical host for the full source-isolation smoke test in that environment.

Logs are written to `logs\`. The dashboard URL is controlled by `PI_IP` and `DASH_PORT`; the default is <http://127.0.0.1:5000>.

## Dashboard and individual demonstrations

With the full stack running, open <http://127.0.0.1:5000>. **Settings → Appearance
→ Dark** selects a pure black background; Light is the default. Ctrl+F5 reloads
updated styles. Settings also saves a 3/5/10/30-second refresh interval and tests
the data endpoints. Expect 10 core checks, plus three source-specific checks when
an attacker is recorded. API health does not confirm MQTT or ESP32 availability.

For browsing evidence without starting MQTT, run this in a normal PowerShell:

```powershell
.\.venv\Scripts\python.exe .\pi\dashboard\app.py
```

Do not run that standalone command alongside the full stack: both use the same
dashboard port. Stop it with Ctrl+C before using `windows/run_all.ps1`.

For the complete demonstration, see [DEMO.md](../DEMO.md) and the
[individual scenario guide](../attacker/README.md). For example:

```powershell
.\.venv\Scripts\python.exe .\attacker\brute_force.py
```

Overview's Attack categories chart counts classified events. Total attackers
counts distinct IPs. Events & Alerts provides full-history filters, stable older
pages, matching CSV export, and Full evidence ZIP. Attacker details and the
Sessions ledger update live. Scenario scripts save verified JSON reports under
`data/demo-results/`; no dashboard data is synthesized.
