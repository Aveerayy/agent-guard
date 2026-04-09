"""Tests for circuit breaker and SLO."""

import pytest

from agent_guard import SLO, CircuitBreaker
from agent_guard.reliability.circuit_breaker import CircuitOpenError, CircuitState


class TestCircuitBreaker:
    def test_starts_closed(self):
        cb = CircuitBreaker("test")
        assert cb.state == CircuitState.CLOSED

    def test_opens_after_threshold(self):
        cb = CircuitBreaker("test", failure_threshold=3)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.CLOSED
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

    def test_rejects_when_open(self):
        cb = CircuitBreaker("test", failure_threshold=1)
        cb.record_failure()
        assert not cb.allow_request()

    def test_context_manager_success(self):
        cb = CircuitBreaker("test")
        with cb:
            pass
        assert cb._total_successes == 1

    def test_context_manager_failure(self):
        cb = CircuitBreaker("test", failure_threshold=5)
        with pytest.raises(ValueError), cb:
            raise ValueError("boom")
        assert cb._total_failures == 1

    def test_context_manager_rejects_when_open(self):
        cb = CircuitBreaker("test", failure_threshold=1)
        cb.record_failure()
        with pytest.raises(CircuitOpenError), cb:
            pass

    def test_decorator(self):
        cb = CircuitBreaker("test")

        @cb.protect
        def good_func():
            return 42

        assert good_func() == 42
        assert cb._total_successes == 1

    def test_reset(self):
        cb = CircuitBreaker("test", failure_threshold=1)
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        cb.reset()
        assert cb.state == CircuitState.CLOSED

    def test_stats(self):
        cb = CircuitBreaker("test-cb")
        cb.record_success()
        cb.record_failure()
        stats = cb.stats()
        assert stats["name"] == "test-cb"
        assert stats["total_calls"] == 2


class TestSLO:
    def test_starts_meeting_target(self):
        slo = SLO("test", target_percent=99.0)
        assert slo.status().meeting_target

    def test_tracks_success_rate(self):
        slo = SLO("test", target_percent=90.0)
        for _ in range(9):
            slo.record_success()
        slo.record_failure()
        status = slo.status()
        assert status.current_value == 90.0
        assert status.meeting_target

    def test_detects_below_target(self):
        slo = SLO("test", target_percent=99.0)
        slo.record_success()
        slo.record_failure()
        assert not slo.status().meeting_target

    def test_error_budget(self):
        slo = SLO("test", target_percent=90.0)
        for _ in range(10):
            slo.record_success()
        assert not slo.error_budget_exhausted()
        for _ in range(5):
            slo.record_failure()
        assert slo.error_budget_exhausted()

    def test_reset(self):
        slo = SLO("test")
        slo.record_failure()
        slo.reset()
        assert slo.status().total_events == 0

    def test_stats(self):
        slo = SLO("availability", target_percent=99.5)
        slo.record_success()
        stats = slo.stats()
        assert stats["name"] == "availability"
        assert stats["target"] == "99.5%"
