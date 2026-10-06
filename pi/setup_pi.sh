#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$ROOT/config.env"
set -a
# shellcheck disable=SC1090
source "$CONFIG"
set +a

sudo apt-get update
sudo apt-get install -y mosquitto mosquitto-clients python3-venv
python3 -m venv "$ROOT/.venv"
"$ROOT/.venv/bin/python" -m pip install --upgrade pip
"$ROOT/.venv/bin/pip" install paho-mqtt flask pytest
sudo systemctl disable --now mosquitto 2>/dev/null || true

mkdir -p "$ROOT/data" "$ROOT/logs" "$ROOT/run"
PASSWORD_FILE="$ROOT/data/real.passwd"
# -b supports an idempotent, non-interactive setup; protect the resulting hash file.
mosquitto_passwd -b -c "$PASSWORD_FILE" "$REAL_USER" "$REAL_PASS"
chmod 600 "$PASSWORD_FILE"
echo "Pi setup complete. Next: ./pi/run_all.sh"

