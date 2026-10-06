#!/usr/bin/env python3
"""Sample CPU time and resident memory for a process without extra packages."""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import time
from pathlib import Path


def snapshot(pid: int) -> tuple[float, int]:
    if os.name == "nt":
        command = ["powershell", "-NoProfile", "-Command",
                   f"Get-Process -Id {pid} | Select-Object CPU,WorkingSet64 | ConvertTo-Json -Compress"]
        value = json.loads(subprocess.check_output(command, text=True))
        return float(value.get("CPU") or 0.0), int(value["WorkingSet64"])
    stat = Path(f"/proc/{pid}/stat").read_text().split()
    cpu = (int(stat[13]) + int(stat[14])) / os.sysconf("SC_CLK_TCK")
    rss = int(stat[23]) * os.sysconf("SC_PAGE_SIZE")
    return cpu, rss


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--duration", type=float, default=30)
    parser.add_argument("--interval", type=float, default=1)
    parser.add_argument("--output", type=Path, default=Path("data/resource_samples.csv"))
    args = parser.parse_args()
    samples: list[tuple[float, float, int]] = []
    deadline = time.monotonic() + args.duration
    while time.monotonic() <= deadline:
        cpu, rss = snapshot(args.pid)
        samples.append((time.time(), cpu, rss))
        time.sleep(args.interval)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["time", "cpu_seconds", "rss_bytes"])
        writer.writerows(samples)
    print(f"wrote {len(samples)} samples to {args.output}")


if __name__ == "__main__":
    main()
