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
