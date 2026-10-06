#!/usr/bin/env python3
"""Summarize and classify recorded decoy sessions, then export a CSV."""

from __future__ import annotations

import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from pi import db


def classify(details: list[str], topics: list[str]) -> list[str]:
    labels: list[str] = []
    if sum("failed auth" in item for item in details) >= 3:
        labels.append("brute-force")
    if any("wildcard subscribe" in item for item in details):
        labels.append("wildcard recon")
    if "home/door/lock" in topics or any("command publish" in item for item in details):
        labels.append("unauthorized publish/spoof")
    return labels or ["unclassified"]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "data" / "analysis.csv")
    args = parser.parse_args()
    events = db.rows("SELECT time, ip, action, score, detail FROM events ORDER BY time")
    messages = db.rows("SELECT time, ip, topic, payload FROM decoy_messages ORDER BY time")
    details: dict[str, list[str]] = defaultdict(list)
    actions: dict[str, list[str]] = defaultdict(list)
    max_score: dict[str, float] = defaultdict(float)
    topics: dict[str, list[str]] = defaultdict(list)
    for row in events:
        details[row["ip"]].append(row["detail"])
        if not actions[row["ip"]] or actions[row["ip"]][-1] != row["action"]:
            actions[row["ip"]].append(row["action"])
        max_score[row["ip"]] = max(max_score[row["ip"]], row["score"])
    for row in messages:
        topics[row["ip"]].append(row["topic"])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["ip", "max_score", "action_sequence", "classifications", "decoy_topics"])
        for ip in sorted(set(details) | set(topics)):
            labels = classify(details[ip], topics[ip])
            writer.writerow([ip, f"{max_score[ip]:.1f}", " -> ".join(actions[ip]),
                             "; ".join(labels), "; ".join(topics[ip])])
            print(f"{ip}: score={max_score[ip]:.1f}; actions={' -> '.join(actions[ip])}; "
                  f"classification={', '.join(labels)}")
    print(f"CSV written to {args.output}")


if __name__ == "__main__":
    main()

