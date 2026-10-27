#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN="$ROOT/run"
for name in dashboard proxy decoy-publisher decoy-broker real-broker; do
  pidfile="$RUN/$name.pid"
  if [[ -f "$pidfile" ]]; then
    pid="$(cat "$pidfile")"
    expected=""
    case "$name" in
      dashboard) expected="$ROOT/pi/dashboard/app.py" ;;
      proxy) expected="$ROOT/pi/proxy/proxy.py" ;;
      decoy-publisher) expected="$ROOT/pi/decoy/decoy_publisher.py" ;;
      real-broker) expected="$ROOT/run/real.conf" ;;
      decoy-broker) expected="$ROOT/run/decoy.conf" ;;
    esac
    if [[ "$pid" =~ ^[0-9]+$ && -O "/proc/$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      command_line="$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null || true)"
      startfile="$RUN/$name.start"
      if [[ "$command_line" != *"$expected"* ]] ||
         { [[ -f "$startfile" ]] && [[ "$(cat "$startfile")" != "$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null)" ]]; }; then
        echo "Ignoring stale PID for $name ($pid): process identity differs." >&2
        rm -f "$pidfile" "$RUN/$name.start"
        continue
      fi
      kill "$pid" 2>/dev/null || true
      for _ in {1..20}; do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
      done
      # Recheck identity before escalating; the original process may have exited.
      if [[ -f "$startfile" && -r "/proc/$pid/stat" ]] &&
         [[ "$(cat "$startfile")" == "$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null)" ]]; then
        kill -9 "$pid" 2>/dev/null || true
      fi
    fi
    rm -f "$pidfile" "$RUN/$name.start"
  fi
done
echo "Stack stopped."
