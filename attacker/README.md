# Individual MQTT attack demonstrations

Start the normal honeypot stack first. These are bounded demonstrations for your
own MQTT lab, covering all six categories implemented by this detector. They do
not simulate unrelated web attacks such as SQL injection, XSS, or ransomware.

From the repository root on Windows, run any individual file:

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

On Pi/Linux, replace `.\.venv\Scripts\python.exe .\attacker\` with
`.venv/bin/python attacker/`.

| File | Traffic with default configuration | Required recorded signal | Dashboard category |
| --- | --- | --- | --- |
| `brute_force.py` | Three wrong-password logins | `failed_auth` | Brute Force |
| `reconnaissance.py` | One `#` subscription | `wildcard_subscription` | Reconnaissance |
| `topic_enumeration.py` | Six distinct exact topic subscriptions | `topic_enumeration` | MQTT Enumeration |
| `command_spoofing.py` | Authenticated command publish, payload `lock` | `suspicious_publish` | Unauthorized/Suspicious Publish |
| `protocol_abuse.py` | One malformed CONNECT | `malformed_packet` | Command/Protocol Abuse |
| `connection_flood.py` | Eleven rapid TCP connections | `connection_rate` | Flooding/DoS |
| `publish_flood.py` | Twenty-one telemetry publishes | `publish_rate` | Flooding/DoS |
| `command_sequence.py` | Wildcard subscription followed by `lock` | `command_sequence` | Command/Protocol Abuse |
| `benign.py` | One ordinary telemetry publish; session held open | No classified events | Benign control |

Command demos use the configured real credentials to model a compromised client.
The standalone command-spoofing scenario can reach the real device at low risk
and sends **lock**. It can physically lock an unlocked device. The original
`attack.py` remains the combined decoy/unlock demonstration.

For a laptop-only stack (`PI_IP=127.0.0.1`), each file automatically binds a
different loopback address, starting at `127.0.0.2` through `127.0.0.10`.
If that source already has evidence or risk, automatic local runs choose an unused
address (for example `127.0.1.2` for another brute-force trial). This avoids old
decoy routing and failed-auth caps without deleting evidence. Each new source adds
a unique attacker; category counts increase only when new detections are verified.
An explicit `--source-ip` keeps the requested address and its existing history.
Keep these addresses
out of `WHITELIST_IPS`, `BLACKLIST_IPS`, and `DECOY_FORCE_IPS`. For a separate
attacker laptop, set its `config.env` to the Pi address and matching credentials;
omit `--source-ip` so its actual LAN address is used. Local loopback aliases
cannot be used to reach a remote Pi. `--source-ip` must be an address assigned to
the testing machine.

Open `http://PI_IP:5000` and watch the **Attack categories** chart and its
**classified events** total on Overview, **Events & Alerts**, and the attacker's
live detail page. They refresh every three seconds by default; Settings lets
you choose 3, 5, 10, or 30 seconds. **Settings → Appearance → Dark** selects the
pure black page/navigation background; the selection is saved in this browser. **Total attackers** counts distinct IPs and stays the same when you
repeat a scenario from the same IP. Scores decay, so event counts are the durable
demonstration. Short connections can additionally trigger Reconnaissance.

Each file compares the attacker's event timeline before and after real traffic,
prints PASS only when the expected new signal exists (or no classified event for
the benign control), and saves JSON evidence in `data/demo-results/`. Exit code
1 means the run failed or was not verified. Dashboard unavailability is a failure;
the script never inserts synthetic events or increments counters itself.

Options: `--dashboard-url http://PI_IP:5000`, `--source-ip LOCAL_ADDRESS`,
`--output data/my-demo.json`. TLS follows `TLS_CERT_PATH`; the certificate must
be trusted and match `PI_IP`.

Before repeating experiments on one LAN IP, export evidence, then use **Clear
logs + scores** and wait at least two seconds. Accumulated risk may otherwise
route new attempts to the anonymous decoy, where wrong passwords cannot exercise
real-broker authentication. Enumeration and rate awards also have caps/windows.
Do not run scenarios concurrently from the same IP. Clearing removes recorded
evidence; it is an operator action, never done automatically by these scripts.

For accuracy experiments, run repeated independent attack and benign trials and
retain every result, including failures. A scenario PASS is evidence that its
signal was detected, not an accuracy percentage. The existing `evaluate.py`
uses per-IP malicious/benign labels; isolate trials when reusing a source IP.

## Dashboard checks during the demonstration

1. Start the complete MQTT stack, not only `pi/dashboard/app.py`. A working
   dashboard API does not establish that the MQTT proxy/brokers are running.
2. In Settings click **Test connection**. Expect 10 core endpoints to pass, plus
   three source-specific checks when a recorded attacker exists.
3. Open **Events & Alerts**. Filter by the exact source IP and the category in
   the scenario table. Filters search the complete database. **Load older events**
   pauses streaming; click **Resume stream** to return to live updates.
4. Run one scenario and retain its JSON PASS/FAIL report. Open the source's
   detail page to see live risk, attack count, timeline, sessions, messages, and
   behavior groups. **Total attackers** may remain unchanged for a repeated IP.
5. Use **Honeypot / Decoy** to show routing and decoy messages. A low-risk
   standalone scenario may be detected while still routed to the real broker;
   every scenario does not independently reach CRITICAL.
6. **Export CSV** saves all matching events, including older records not loaded
   in the table. **Full evidence ZIP** saves the full dataset without filters.
7. If **DATA STALE** appears, keep the report and check the named endpoint.
   **Retry now** refreshes data; the last snapshot is retained during outages.

For a clean test on a reused LAN source, save evidence before clearing it. Run
benign and malicious trials independently; accumulated risk can change routing.
The original combined `attack.py` does not produce the per-scenario JSON reports.
