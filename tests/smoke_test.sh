#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
set -a
# shellcheck disable=SC1090
source "$ROOT/config.env"
set +a
ATTACK_IP="127.0.0.2"
SIM_PID=""

cleanup() {
  [[ -n "$SIM_PID" ]] && kill "$SIM_PID" 2>/dev/null || true
  bash "$ROOT/pi/stop_all.sh" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [[ "$PI_IP" != "127.0.0.1" ]]; then
  echo "FAIL: set PI_IP=127.0.0.1 for the laptop-only test" >&2
  exit 1
fi
if [[ ",$WHITELIST_IPS," == *",$ATTACK_IP,"* ]]; then
  echo "FAIL: $ATTACK_IP must not be whitelisted" >&2
  exit 1
fi

rm -f "$ROOT/data/honeypot.db" "$ROOT/sim/relay_state.txt"
bash "$ROOT/pi/run_all.sh"
"$ROOT/.venv/bin/python" "$ROOT/sim/sim_esp32.py" >"$ROOT/logs/simulator.log" 2>&1 &
SIM_PID=$!
sleep 3

echo "Checking legitimate real-path traffic..."
timeout 12 mosquitto_sub -h "$PI_IP" -p "$PROXY_PORT" -u "$REAL_USER" -P "$REAL_PASS" \
  -t home/door/motion -C 1 >"$ROOT/logs/legitimate-before.txt"
grep -Eq '^[01]$' "$ROOT/logs/legitimate-before.txt"
grep -qx 'LOCKED' "$ROOT/sim/relay_state.txt"

"$ROOT/.venv/bin/python" "$ROOT/attacker/attack.py" --source-ip "$ATTACK_IP"
sleep 1

read -r SCORE DECOY_SESSIONS UNLOCKS < <("$ROOT/.venv/bin/python" - "$ROOT" "$ATTACK_IP" <<'PY'
import sqlite3, sys
from pathlib import Path
root = Path(sys.argv[1])
db = sqlite3.connect(root / "data" / "honeypot.db")
ip = sys.argv[2]
score = db.execute("SELECT COALESCE(MAX(score),0) FROM events WHERE ip=?", (ip,)).fetchone()[0]
sessions = db.execute("SELECT COUNT(*) FROM sessions WHERE ip=? AND backend='decoy'", (ip,)).fetchone()[0]
unlocks = db.execute("SELECT COUNT(*) FROM decoy_messages WHERE ip=? AND topic='home/door/lock' AND payload='unlock'", (ip,)).fetchone()[0]
print(score, sessions, unlocks)
PY
)
"$ROOT/.venv/bin/python" - "$SCORE" "$HIGH" <<'PY'
import sys
assert float(sys.argv[1]) >= float(sys.argv[2]), f"score {sys.argv[1]} is below HIGH {sys.argv[2]}"
PY
[[ "$DECOY_SESSIONS" -ge 1 ]] || { echo "FAIL: attacker never reached decoy" >&2; exit 1; }
[[ "$UNLOCKS" -ge 1 ]] || { echo "FAIL: decoy did not log unlock" >&2; exit 1; }
grep -qx 'LOCKED' "$ROOT/sim/relay_state.txt" || { echo "FAIL: simulated relay changed" >&2; exit 1; }

echo "Checking legitimate traffic after the attack..."
timeout 12 mosquitto_sub -h "$PI_IP" -p "$PROXY_PORT" -u "$REAL_USER" -P "$REAL_PASS" \
  -t home/door/motion -C 1 >"$ROOT/logs/legitimate-after.txt"
grep -Eq '^[01]$' "$ROOT/logs/legitimate-after.txt"

echo "PASS: attacker score=$SCORE, decoy_sessions=$DECOY_SESSIONS, decoy_unlocks=$UNLOCKS"
echo "PASS: simulated relay stayed LOCKED and legitimate traffic worked before and after"
