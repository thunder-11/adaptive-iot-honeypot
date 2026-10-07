#!/usr/bin/env python3
"""Reproducible evaluation from SQLite and optional labeled ground truth."""

from __future__ import annotations

import argparse
import csv
import json
import sqlite3
from pathlib import Path
from typing import Iterable, Mapping

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB = ROOT / "data" / "honeypot.db"


def ground_truth(path: Path | None) -> dict[str, bool]:
    if path is None:
        return {}
    with path.open(newline="", encoding="utf-8") as handle:
        return {
            row["ip"]: row["label"].strip().lower() in {"1", "true", "malicious", "attack"}
            for row in csv.DictReader(handle)
        }


def safe_rate(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def first_high_critical_latencies(
    events: Iterable[Mapping[str, object]], first_seen: Mapping[str, float]
) -> list[float]:
    """Milliseconds from first observation to each IP's first restrict/decoy action."""
    latencies: list[float] = []
    responded: set[str] = set()
    for row in events:
        ip = str(row["ip"])
        if ip in responded or ip not in first_seen or row["action"] not in {"restrict", "decoy"}:
            continue
        latencies.append((float(row["time"]) - first_seen[ip]) * 1000)
        responded.add(ip)
    return latencies


def percentile(values: Iterable[float], quantile: float) -> float | None:
    ordered = sorted(values)
    if not ordered:
        return None
    position = (len(ordered) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return round(ordered[lower] + (ordered[upper] - ordered[lower]) * fraction, 3)


def evaluate(database: Path, truth_path: Path | None = None) -> dict[str, object]:
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    attackers = list(connection.execute("SELECT * FROM attackers"))
    events = list(connection.execute("SELECT * FROM events ORDER BY time"))
    sessions = list(connection.execute("SELECT * FROM sessions"))
    decoy_hits = connection.execute("SELECT COUNT(*) FROM decoy_messages").fetchone()[0]
    truth = ground_truth(truth_path)
    predicted = {row["ip"]: row["attack_count"] > 0 for row in attackers}
    tp = sum(predicted.get(ip, False) and malicious for ip, malicious in truth.items())
    fn = sum(not predicted.get(ip, False) and malicious for ip, malicious in truth.items())
    fp = sum(predicted.get(ip, False) and not malicious for ip, malicious in truth.items())
    tn = sum(not predicted.get(ip, False) and not malicious for ip, malicious in truth.items())
    first_seen = {row["ip"]: row["first_seen"] for row in attackers}
    response_latencies = first_high_critical_latencies(events, first_seen)
    duration = (events[-1]["time"] - events[0]["time"]) if len(events) > 1 else 0.0
    result = {
        "ground_truth_rows": len(truth),
        "detection_rate": safe_rate(tp, tp + fn),
        "false_positive_rate": safe_rate(fp, fp + tn),
        "confusion": {"true_positive": tp, "false_negative": fn,
                      "false_positive": fp, "true_negative": tn},
        "mean_response_latency_ms": round(sum(response_latencies) / len(response_latencies), 3)
        if response_latencies else None,
        "p50_response_latency_ms": percentile(response_latencies, 0.50),
        "p95_response_latency_ms": percentile(response_latencies, 0.95),
        "throughput_events_per_second": round(len(events) / duration, 3) if duration > 0 else None,
        "database": {"bytes": database.stat().st_size, "events": len(events),
                     "attackers": len(attackers), "sessions": len(sessions)},
        "decoy_engagement": {"messages": decoy_hits,
                             "decoy_sessions": sum(row["backend"] == "decoy" for row in sessions)},
        "note": "null rates mean the required ground truth or elapsed interval was unavailable",
    }
    connection.close()
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, default=DEFAULT_DB)
    parser.add_argument("--ground-truth", type=Path,
                        help="CSV with columns ip,label where label is malicious or benign")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = evaluate(args.database, args.ground_truth)
    rendered = json.dumps(result, indent=2)
    print(rendered)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
