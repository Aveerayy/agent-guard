"""Tests for observability bus and hooks."""

from agent_guard import GuardEvent, ObservabilityBus
from agent_guard.observability.hooks import metrics_collector


class TestObservabilityBus:
    def test_emit_and_handle(self):
        bus = ObservabilityBus()
        received = []
        bus.on(GuardEvent.POLICY_DECISION, lambda e: received.append(e))
        bus.emit(GuardEvent(event_type=GuardEvent.POLICY_DECISION, action="test"))
        assert len(received) == 1

    def test_global_handler(self):
        bus = ObservabilityBus()
        received = []
        bus.on_all(lambda e: received.append(e))
        bus.emit(GuardEvent(event_type="anything"))
        bus.emit(GuardEvent(event_type="something_else"))
        assert len(received) == 2

    def test_event_count(self):
        bus = ObservabilityBus()
        bus.emit(GuardEvent(event_type="a"))
        bus.emit(GuardEvent(event_type="b"))
        assert bus.event_count == 2

    def test_handler_isolation(self):
        bus = ObservabilityBus()
        a_events = []
        b_events = []
        bus.on("type_a", lambda e: a_events.append(e))
        bus.on("type_b", lambda e: b_events.append(e))
        bus.emit(GuardEvent(event_type="type_a"))
        assert len(a_events) == 1
        assert len(b_events) == 0

    def test_stats(self):
        bus = ObservabilityBus()
        bus.on("x", lambda e: None)
        bus.on("x", lambda e: None)
        stats = bus.stats()
        assert stats["registered_handlers"] == 2


class TestMetricsCollector:
    def test_counts_decisions(self):
        handler, get_metrics = metrics_collector()
        handler(GuardEvent(event_type=GuardEvent.POLICY_DECISION, allowed=True))
        handler(GuardEvent(event_type=GuardEvent.POLICY_DECISION, allowed=False))
        handler(GuardEvent(event_type=GuardEvent.POLICY_DENY, allowed=False))
        metrics = get_metrics()
        assert metrics["policy_decisions_total"] == 3
        assert metrics["policy_allows_total"] == 1
        assert metrics["policy_denials_total"] == 2

    def test_counts_scans(self):
        handler, get_metrics = metrics_collector()
        handler(GuardEvent(event_type=GuardEvent.MCP_SCAN))
        assert get_metrics()["mcp_scans_total"] == 1
