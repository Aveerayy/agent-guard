"""SLO (Service Level Objectives) — define and track agent reliability targets."""

from __future__ import annotations

import time
import threading
from typing import Any

from pydantic import BaseModel, Field


class SLOTarget(BaseModel):
    """A single service level objective."""

    name: str
    description: str = ""
    target_percent: float = Field(default=99.0, ge=0, le=100)
    window_seconds: float = 3600.0  # 1 hour default
    metric: str = "success_rate"  # success_rate, latency_p99, error_rate


class SLOStatus(BaseModel):
    """Current status of an SLO."""

    target: SLOTarget
    current_value: float
    meeting_target: bool
    error_budget_remaining: float
    total_events: int
    window_start: float
    window_end: float


class SLO:
    """Track service level objectives for agent operations.

    Usage:
        slo = SLO("agent-availability", target_percent=99.5)

        # Record outcomes
        slo.record_success()
        slo.record_success()
        slo.record_failure()

        # Check status
        status = slo.status()
        print(f"Meeting target: {status.meeting_target}")
        print(f"Error budget remaining: {status.error_budget_remaining:.1%}")

        # Use as a gate
        if slo.error_budget_exhausted():
            # slow down, switch to safe mode
            ...
    """

    def __init__(
        self,
        name: str,
        *,
        target_percent: float = 99.0,
        window_seconds: float = 3600.0,
    ):
        self.target = SLOTarget(
            name=name,
            target_percent=target_percent,
            window_seconds=window_seconds,
        )
        self._events: list[tuple[float, bool]] = []  # (timestamp, success)
        self._lock = threading.Lock()

    def record_success(self) -> None:
        with self._lock:
            self._events.append((time.time(), True))
            self._trim_window()

    def record_failure(self) -> None:
        with self._lock:
            self._events.append((time.time(), False))
            self._trim_window()

    def record(self, success: bool) -> None:
        if success:
            self.record_success()
        else:
            self.record_failure()

    def _trim_window(self) -> None:
        cutoff = time.time() - self.target.window_seconds
        self._events = [(t, s) for t, s in self._events if t >= cutoff]

    def status(self) -> SLOStatus:
        with self._lock:
            self._trim_window()
            total = len(self._events)
            successes = sum(1 for _, s in self._events if s)
            current = (successes / total * 100) if total > 0 else 100.0
            allowed_failures = (100 - self.target.target_percent) / 100 * total if total else 0
            actual_failures = total - successes
            budget_remaining = (
                (allowed_failures - actual_failures) / allowed_failures
                if allowed_failures > 0
                else 1.0 if actual_failures == 0 else 0.0
            )

            now = time.time()
            return SLOStatus(
                target=self.target,
                current_value=current,
                meeting_target=current >= self.target.target_percent,
                error_budget_remaining=max(0.0, budget_remaining),
                total_events=total,
                window_start=now - self.target.window_seconds,
                window_end=now,
            )

    def error_budget_exhausted(self) -> bool:
        return self.status().error_budget_remaining <= 0

    def reset(self) -> None:
        with self._lock:
            self._events.clear()

    def stats(self) -> dict[str, Any]:
        s = self.status()
        return {
            "name": self.target.name,
            "target": f"{self.target.target_percent}%",
            "current": f"{s.current_value:.1f}%",
            "meeting_target": s.meeting_target,
            "error_budget_remaining": f"{s.error_budget_remaining:.1%}",
            "total_events": s.total_events,
        }
