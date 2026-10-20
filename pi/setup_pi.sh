#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
if [[ "$EUID" -eq 0 ]]; then
  echo "Run as your normal Pi user: bash pi/setup_pi.sh (sudo is used for apt only)." >&2
  exit 1
fi
if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))'; then
  echo "Python 3.11+ required. Install Raspberry Pi OS Lite Bookworm or newer." >&2
  exit 1
fi
CONFIG="$ROOT/config.env"
set -a
# shellcheck disable=SC1090
source "$CONFIG"
set +a

sudo apt-get update
sudo apt-get install -y mosquitto mosquitto-clients openssl python3-venv
if [[ -d "$ROOT/.venv" && ! -x "$ROOT/.venv/bin/python" ]]; then
  echo "This .venv is not a Linux environment. Move it aside, then rerun setup; do not copy the Windows .venv to the Pi." >&2
  exit 1
fi
python3 -m venv "$ROOT/.venv"
"$ROOT/.venv/bin/python" -m pip install --upgrade pip
"$ROOT/.venv/bin/pip" install -r "$ROOT/requirements.txt"
sudo systemctl disable --now mosquitto 2>/dev/null || true

mkdir -p "$ROOT/data" "$ROOT/logs" "$ROOT/run"
PASSWORD_FILE="$ROOT/data/real.passwd"
# -b supports an idempotent, non-interactive setup; protect the resulting hash file.
mosquitto_passwd -b -c "$PASSWORD_FILE" "$REAL_USER" "$REAL_PASS"
chmod 600 "$PASSWORD_FILE"

if [[ -n "${TLS_CERT_PATH:-}" || -n "${TLS_KEY_PATH:-}" ]]; then
  if [[ -z "${TLS_CERT_PATH:-}" || -z "${TLS_KEY_PATH:-}" ]]; then
    echo "TLS_CERT_PATH and TLS_KEY_PATH must both be set or both be empty." >&2
    exit 1
  fi
  [[ "$TLS_CERT_PATH" = /* ]] || TLS_CERT_PATH="$ROOT/$TLS_CERT_PATH"
  [[ "$TLS_KEY_PATH" = /* ]] || TLS_KEY_PATH="$ROOT/$TLS_KEY_PATH"
  mkdir -p "$(dirname "$TLS_CERT_PATH")" "$(dirname "$TLS_KEY_PATH")"
  if [[ ! -f "$TLS_CERT_PATH" || ! -f "$TLS_KEY_PATH" ]]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
      -keyout "$TLS_KEY_PATH" -out "$TLS_CERT_PATH" -subj "/CN=$PI_IP"
    chmod 600 "$TLS_KEY_PATH"
    echo "Generated local demo TLS certificate: $TLS_CERT_PATH"
  fi
fi
"$ROOT/.venv/bin/python" -m pip check
echo "Pi setup complete. Next: bash pi/run_all.sh"

