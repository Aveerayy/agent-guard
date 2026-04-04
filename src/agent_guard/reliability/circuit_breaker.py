"""Circuit breaker — prevent cascading failures in agent systems."""

from __future__ import annotations

import time
import threading
from enum import Enum
from typing import Any
from collections.abc import Callable


class CircuitState(str, Enum):
    CLOSED = "closed"       # Normal operation
    OPEN = "open"           # Failing — reject calls
    HALF_OPEN = "half_open" # Testing recovery


class CircuitBreaker:
    """Circuit breaker pattern for agent tool calls and external services.

    Usage:
        breaker = CircuitBreaker("openai-api", failure_threshold=3, recovery_time=60)

        try:
            with breaker:
                result = call_openai(prompt)
        except CircuitOpenError:
            # fallback logic
            ...

        # Or as a decorator
        @breaker.protect
        def call_openai(prompt: str):
            ...

        # Check status
        print(breaker.state)       # CircuitState.CLOSED
        print(breaker.stats())     # {failures: 0, successes: 5, ...}
    """

    def __init__(
        self,
        name: str = "default",
        *,
        failure_threshold: int = 5,
        recovery_time: float = 60.0,
        success_threshold: int = 2,
        half_open_max_calls: int = 1,
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_time = recovery_time
        self.success_threshold = success_threshold
        self.half_open_max_calls = half_open_max_calls

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._half_open_calls = 0
        self._last_failure_time: float = 0
        self._total_calls = 0
        self._total_failures = 0
        self._total_successes = 0
        self._lock = threading.Lock()

    @property
    def state(self) -> CircuitState:
        with self._lock:
            if self._state == CircuitState.OPEN:
                if time.time() - self._last_failure_time >= self.recovery_time:
                    self._state = CircuitState.HALF_OPEN
                    self._half_open_calls = 0
                    self._success_count = 0
            return self._state

    def record_success(self) -> None:
        with self._lock:
            self._total_calls += 1
            self._total_successes += 1
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.success_threshold:
                    self._state = CircuitState.CLOSED
                    self._failure_count = 0
                    self._success_count = 0
            elif self._state == CircuitState.CLOSED:
                self._failure_count = 0

    def record_failure(self) -> None:
        with self._lock:
            self._total_calls += 1
            self._total_failures += 1
            self._last_failure_time = time.time()
            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                self._half_open_calls = 0
            elif self._state == CircuitState.CLOSED:
                self._failure_count += 1
                if self._failure_count >= self.failure_threshold:
                    self._state = CircuitState.OPEN

    def allow_request(self) -> bool:
        state = self.state
        if state == CircuitState.CLOSED:
            return True
        if state == CircuitState.OPEN:
            return False
        with self._lock:
            if self._half_open_calls < self.half_open_max_calls:
                self._half_open_calls += 1
                return True
            return False

    def reset(self) -> None:
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._success_count = 0
            self._half_open_calls = 0

    def force_open(self) -> None:
        with self._lock:
            self._state = CircuitState.OPEN
            self._last_failure_time = time.time()

    def protect(self, fn: Callable) -> Callable:
        """Decorator to protect a function with this circuit breaker."""
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if not self.allow_request():
                raise CircuitOpenError(
                    f"Circuit breaker '{self.name}' is OPEN — call rejected"
                )
            try:
                result = fn(*args, **kwargs)
                self.record_success()
                return result
            except Exception as e:
                self.record_failure()
                raise
        wrapper.__name__ = fn.__name__
        wrapper.__doc__ = fn.__doc__
        return wrapper

    def __enter__(self) -> CircuitBreaker:
        if not self.allow_request():
            raise CircuitOpenError(
                f"Circuit breaker '{self.name}' is OPEN — call rejected"
            )
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if exc_type is None:
            self.record_success()
        else:
            self.record_failure()

    def stats(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "state": self.state.value,
            "total_calls": self._total_calls,
            "total_successes": self._total_successes,
            "total_failures": self._total_failures,
            "current_failures": self._failure_count,
            "failure_threshold": self.failure_threshold,
            "recovery_time": self.recovery_time,
        }


class CircuitOpenError(Exception):
    """Raised when a call is rejected because the circuit breaker is open."""
    pass
