"""Rate limiting — token bucket rate limiter for agent actions."""

from __future__ import annotations

import threading
import time
from typing import Any


class RateLimiter:
    """Token bucket rate limiter for agent governance.

    Usage:
        limiter = RateLimiter(rate=10, burst=20)  # 10 requests/sec, burst of 20

        if limiter.allow("agent-1"):
            proceed()
        else:
            reject("Rate limit exceeded")

        # Per-agent limits
        limiter = RateLimiter(rate=5, burst=10, per_agent=True)
    """

    def __init__(
        self,
        rate: float = 10.0,
        burst: int = 20,
        *,
        per_agent: bool = False,
    ):
        self._rate = rate
        self._burst = burst
        self._per_agent = per_agent
        self._buckets: dict[str, _Bucket] = {}
        self._global_bucket = _Bucket(rate, burst)
        self._lock = threading.Lock()

    def allow(self, agent_id: str = "global") -> bool:
        """Check if a request is allowed under the rate limit."""
        if self._per_agent:
            with self._lock:
                if agent_id not in self._buckets:
                    self._buckets[agent_id] = _Bucket(self._rate, self._burst)
                return self._buckets[agent_id].consume()
        return self._global_bucket.consume()

    def remaining(self, agent_id: str = "global") -> int:
        """How many tokens remain in the bucket."""
        if self._per_agent:
            with self._lock:
                bucket = self._buckets.get(agent_id)
                if not bucket:
                    return self._burst
                return bucket.remaining()
        return self._global_bucket.remaining()

    def stats(self) -> dict[str, Any]:
        return {
            "rate": self._rate,
            "burst": self._burst,
            "per_agent": self._per_agent,
            "active_buckets": len(self._buckets) if self._per_agent else 1,
        }


class _Bucket:
    """Internal token bucket implementation."""

    def __init__(self, rate: float, burst: int):
        self._rate = rate
        self._burst = burst
        self._tokens = float(burst)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def consume(self, tokens: int = 1) -> bool:
        with self._lock:
            self._refill()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    def remaining(self) -> int:
        with self._lock:
            self._refill()
            return int(self._tokens)

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
        self._last_refill = now
