"""Shared explainable attack classification, risk naming, and fingerprints."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import Iterable, Mapping

ATTACK_CATEGORIES = (
    "Reconnaissance",
    "Brute Force",
    "MQTT Enumeration",
    "Unauthorized/Suspicious Publish",
    "Command/Protocol Abuse",
    "Flooding/DoS",
)

SIGNAL_CATEGORY = {
    "connection_rate": "Flooding/DoS",
    "publish_rate": "Flooding/DoS",
    "failed_auth": "Brute Force",
    "wildcard_subscription": "Reconnaissance",
    "topic_enumeration": "MQTT Enumeration",
    "suspicious_publish": "Unauthorized/Suspicious Publish",
    "command_sequence": "Command/Protocol Abuse",
    "malformed_packet": "Command/Protocol Abuse",
    "protocol_abuse": "Command/Protocol Abuse",
    "short_session": "Reconnaissance",
    "decoy_engagement": "Unauthorized/Suspicious Publish",
    "blacklist": "Reconnaissance",
}


def category_for_signal(signal: str) -> str:
    """Map a machine-readable signal to one stable SOC category."""
    return SIGNAL_CATEGORY.get(signal, "")


def risk_level(score: float, medium: float, high: float, critical: float) -> str:
    if score >= critical:
        return "CRITICAL"
    if score >= high:
        return "HIGH"
    if score >= medium:
        return "MEDIUM"
    return "LOW"


def action_for_score(score: float, medium: float, high: float, critical: float) -> str:
    return {
        "LOW": "allow",
        "MEDIUM": "throttle",
        "HIGH": "restrict",
        "CRITICAL": "decoy",
    }[risk_level(score, medium, high, critical)]


def behavior_fingerprint(categories: Iterable[str], signals: Iterable[str],
                         details: Iterable[str] = ()) -> tuple[str, str]:
    """Return a stable short hash plus an explainable behavioral label."""
    category_counts = Counter(item for item in categories if item)
    signal_counts = Counter(item for item in signals if item)
    features = {
        "categories": sorted(category_counts.items()),
        "signals": sorted(signal_counts.items()),
        "payload_traits": sorted({
            trait for detail in details for trait in (
                "unlock" if "unlock" in detail.lower() else "",
                "wildcard" if "wildcard" in detail.lower() else "",
                "credential" if "username=" in detail.lower() else "",
            ) if trait
        }),
    }
    signature = hashlib.sha256(json.dumps(features, sort_keys=True).encode()).hexdigest()[:12]
    if signal_counts.get("failed_auth", 0) >= 3:
        label = "credential-bruteforcer"
    elif signal_counts.get("topic_enumeration", 0) or signal_counts.get("wildcard_subscription", 0):
        label = "mqtt-enumerator"
    elif signal_counts.get("publish_rate", 0) or signal_counts.get("connection_rate", 0):
        label = "high-rate-client"
    elif signal_counts.get("suspicious_publish", 0) or signal_counts.get("command_sequence", 0):
        label = "command-spoofer"
    elif signal_counts.get("malformed_packet", 0):
        label = "protocol-fuzzer"
    else:
        label = "low-information"
    return signature, label


def split_categories(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]
