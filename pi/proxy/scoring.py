"""Deterministic per-IP risk scoring with linear time decay."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Callable
import time


@dataclass(frozen=True)
class ScoreConfig:
    medium: float = 21
    high: float = 51
    connection_weight: float = 15
    failed_auth_weight: float = 8
    failed_auth_cap: float = 40
    wildcard_weight: float = 25
    command_weight: float = 20
    blacklist_weight: float = 30
    connection_limit: int = 10
    connection_window: float = 10
    decay_per_second: float = 0.1
    whitelist: frozenset[str] = frozenset()
    blacklist: frozenset[str] = frozenset()
    force_decoy: frozenset[str] = frozenset()


@dataclass
class IpState:
    score: float = 0.0
    updated_at: float = 0.0
    connects: deque[float] = field(default_factory=deque)
    rate_window_awarded_at: float | None = None
    failed_auth_points: float = 0.0
    blacklist_applied: bool = False


class RiskScorer:
    """Own mutable score state; clock injection keeps unit tests exact."""

    def __init__(self, config: ScoreConfig, clock: Callable[[], float] = time.monotonic):
        self.config = config
        self.clock = clock
        self.states: dict[str, IpState] = defaultdict(IpState)

    def score(self, ip: str, now: float | None = None) -> float:
        if ip in self.config.whitelist:
            return 0.0
        timestamp = self.clock() if now is None else now
        state = self.states[ip]
        if state.updated_at == 0.0:
            state.updated_at = timestamp
        elapsed = max(0.0, timestamp - state.updated_at)
        state.score = max(0.0, state.score - elapsed * self.config.decay_per_second)
        state.updated_at = timestamp
        return state.score

    def _add(self, ip: str, points: float, now: float | None = None) -> float:
        if ip in self.config.whitelist:
            return 0.0
        timestamp = self.clock() if now is None else now
        self.score(ip, timestamp)
        self.states[ip].score += points
        return self.states[ip].score

    def record_connection(self, ip: str, now: float | None = None) -> tuple[float, bool]:
        """Award once per rolling window after more than the configured limit."""
        timestamp = self.clock() if now is None else now
        current = self.score(ip, timestamp)
        if ip in self.config.whitelist:
            return current, False
        state = self.states[ip]
        while state.connects and timestamp - state.connects[0] > self.config.connection_window:
            state.connects.popleft()
        state.connects.append(timestamp)
        should_award = len(state.connects) > self.config.connection_limit
        already_awarded = (
            state.rate_window_awarded_at is not None
            and timestamp - state.rate_window_awarded_at <= self.config.connection_window
        )
        if should_award and not already_awarded:
            state.rate_window_awarded_at = timestamp
            return self._add(ip, self.config.connection_weight, timestamp), True
        return current, False

    def record_failed_auth(self, ip: str, now: float | None = None) -> tuple[float, float]:
        timestamp = self.clock() if now is None else now
        current = self.score(ip, timestamp)
        if ip in self.config.whitelist:
            return current, 0.0
        state = self.states[ip]
        available = max(0.0, self.config.failed_auth_cap - state.failed_auth_points)
        points = min(self.config.failed_auth_weight, available)
        state.failed_auth_points += points
        return self._add(ip, points, timestamp), points

    def record_wildcard(self, ip: str, now: float | None = None) -> float:
        return self._add(ip, self.config.wildcard_weight, now)

    def record_command_publish(self, ip: str, now: float | None = None) -> float:
        return self._add(ip, self.config.command_weight, now)

    def apply_blacklist(self, ip: str, now: float | None = None) -> tuple[float, bool]:
        timestamp = self.clock() if now is None else now
        current = self.score(ip, timestamp)
        state = self.states[ip]
        if ip in self.config.whitelist or ip not in self.config.blacklist or state.blacklist_applied:
            return current, False
        state.blacklist_applied = True
        return self._add(ip, self.config.blacklist_weight, timestamp), True

    def action(self, ip: str, now: float | None = None) -> str:
        if ip in self.config.whitelist:
            return "allow"
        current = self.score(ip, now)
        if ip in self.config.force_decoy or current >= self.config.high:
            return "decoy"
        if current >= self.config.medium:
            return "throttle"
        return "allow"
