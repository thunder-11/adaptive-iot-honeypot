#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
set -a
# shellcheck disable=SC1090
source "$ROOT/config.env"
set +a
VENV="$ROOT/.venv"
LOGS="$ROOT/logs"
RUN="$ROOT/run"
mkdir -p "$LOGS" "$RUN" "$ROOT/data"

if [[ ! -x "$VENV/bin/python" ]]; then
  echo "Missing $VENV. Run ./pi/setup_pi.sh first." >&2
  exit 1
fi

bash "$ROOT/pi/stop_all.sh" >/dev/null 2>&1 || true

PASSWORD_FILE="$ROOT/data/real.passwd"
if [[ ! -f "$PASSWORD_FILE" ]]; then
  mosquitto_passwd -b -c "$PASSWORD_FILE" "$REAL_USER" "$REAL_PASS"
  chmod 600 "$PASSWORD_FILE"
fi

sed -e "s|@REAL_PORT@|$REAL_PORT|g" -e "s|@PASSWORD_FILE@|$PASSWORD_FILE|g" \
  "$ROOT/pi/mosquitto/real.conf" > "$RUN/real.conf"
sed -e "s|@DECOY_PORT@|$DECOY_PORT|g" -e "s|@DECOY_BIND_IP@|$DECOY_BIND_IP|g" \
  "$ROOT/pi/mosquitto/decoy.conf" > "$RUN/decoy.conf"

start_process() {
  local name="$1"
  shift
  nohup "$@" >"$LOGS/$name.log" 2>&1 &
  echo $! >"$RUN/$name.pid"
  sleep 0.4
  if ! kill -0 "$(cat "$RUN/$name.pid")" 2>/dev/null; then
    echo "$name failed to start; inspect $LOGS/$name.log" >&2
    exit 1
  fi
}

start_process real-broker mosquitto -c "$RUN/real.conf"
start_process decoy-broker mosquitto -c "$RUN/decoy.conf"
start_process decoy-publisher "$VENV/bin/python" "$ROOT/pi/decoy/decoy_publisher.py"
start_process proxy "$VENV/bin/python" "$ROOT/pi/proxy/proxy.py"
start_process dashboard "$VENV/bin/python" "$ROOT/pi/dashboard/app.py"

echo "Stack started: MQTT proxy $PI_IP:$PROXY_PORT; dashboard http://$PI_IP:$DASH_PORT"
