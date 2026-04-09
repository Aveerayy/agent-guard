"""Observability hooks — structured events for OpenTelemetry, Prometheus, or any collector.

Agent Guard emits structured events through a pluggable hook system. Connect
any telemetry backend (OTel, Prometheus, Datadog, custom) with zero coupling.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Any, ClassVar

from pydantic import BaseModel, Field

logger = logging.getLogger("agent_guard.observability")


class GuardEvent(BaseModel):
    """A structured governance event for telemetry export."""

    event_type: str
    timestamp: float = Field(default_factory=time.time)
    agent_id: str = ""
    action: str = ""
    allowed: bool | None = None
    duration_ms: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)

    POLICY_DECISION: ClassVar[str] = "agent_guard.policy.decision"
    POLICY_DENY: ClassVar[str] = "agent_guard.policy.deny"
    TRUST_CHANGE: ClassVar[str] = "agent_guard.trust.change"
    CIRCUIT_STATE: ClassVar[str] = "agent_guard.circuit.state_change"
    SLO_BREACH: ClassVar[str] = "agent_guard.slo.breach"
    MCP_SCAN: ClassVar[str] = "agent_guard.mcp.scan"
    AUDIT_EVENT: ClassVar[str] = "agent_guard.audit.event"
    KILL_SWITCH: ClassVar[str] = "agent_guard.kill_switch"
    SANDBOX_EXEC: ClassVar[str] = "agent_guard.sandbox.exec"
    MESH_MESSAGE: ClassVar[str] = "agent_guard.mesh.message"


EventHandler = Callable[[GuardEvent], None]


class ObservabilityBus:
    """Central event bus for Agent Guard telemetry.

    Usage:
        bus = ObservabilityBus()

        # Subscribe to events
        bus.on("agent_guard.policy.deny", lambda e: alert(e))
        bus.on_all(lambda e: send_to_otel(e))

        # Emit events (called internally by Guard components)
        bus.emit(GuardEvent(
            event_type=GuardEvent.POLICY_DECISION,
            agent_id="agent-1",
            action="web_search",
            allowed=True,
        ))
    """

    def __init__(self) -> None:
        self._handlers: dict[str, list[EventHandler]] = {}
        self._global_handlers: list[EventHandler] = []
        self._event_count = 0

    def on(self, event_type: str, handler: EventHandler) -> None:
        """Subscribe to a specific event type."""
        self._handlers.setdefault(event_type, []).append(handler)

    def on_all(self, handler: EventHandler) -> None:
        """Subscribe to all events."""
        self._global_handlers.append(handler)

    def emit(self, event: GuardEvent) -> None:
        """Emit an event to all matching handlers."""
        self._event_count += 1

        for handler in self._global_handlers:
            try:
                handler(event)
            except Exception as e:
                logger.warning(f"Global event handler error: {e}")

        for handler in self._handlers.get(event.event_type, []):
            try:
                handler(event)
            except Exception as e:
                logger.warning(f"Event handler error for {event.event_type}: {e}")

    def remove(self, event_type: str) -> None:
        """Remove all handlers for a specific event type."""
        self._handlers.pop(event_type, None)

    def clear(self) -> None:
        """Remove all handlers."""
        self._handlers.clear()
        self._global_handlers.clear()

    @property
    def event_count(self) -> int:
        return self._event_count

    def stats(self) -> dict[str, Any]:
        return {
            "total_events_emitted": self._event_count,
            "registered_handlers": sum(len(h) for h in self._handlers.values()),
            "global_handlers": len(self._global_handlers),
            "event_types": list(self._handlers.keys()),
        }


def logging_handler(event: GuardEvent) -> None:
    """Built-in handler that logs all events to Python logging."""
    level = logging.WARNING if event.allowed is False else logging.INFO
    logger.log(
        level,
        f"[{event.event_type}] agent={event.agent_id} action={event.action} "
        f"allowed={event.allowed} duration={event.duration_ms:.2f}ms",
    )


def metrics_collector() -> tuple[EventHandler, Callable[[], dict[str, Any]]]:
    """Built-in handler that collects Prometheus-style metrics in memory.

    Returns (handler, get_metrics) tuple.

    Usage:
        handler, get_metrics = metrics_collector()
        bus.on_all(handler)
        ...
        print(get_metrics())
    """
    counters: dict[str, int] = {
        "policy_decisions_total": 0,
        "policy_denials_total": 0,
        "policy_allows_total": 0,
        "mcp_scans_total": 0,
        "trust_changes_total": 0,
        "circuit_state_changes_total": 0,
        "slo_breaches_total": 0,
    }

    def handler(event: GuardEvent) -> None:
        if event.event_type in (GuardEvent.POLICY_DECISION, GuardEvent.POLICY_DENY):
            counters["policy_decisions_total"] += 1
            if event.allowed:
                counters["policy_allows_total"] += 1
            else:
                counters["policy_denials_total"] += 1
        elif event.event_type == GuardEvent.MCP_SCAN:
            counters["mcp_scans_total"] += 1
        elif event.event_type == GuardEvent.TRUST_CHANGE:
            counters["trust_changes_total"] += 1
        elif event.event_type == GuardEvent.CIRCUIT_STATE:
            counters["circuit_state_changes_total"] += 1
        elif event.event_type == GuardEvent.SLO_BREACH:
            counters["slo_breaches_total"] += 1

    def get_metrics() -> dict[str, Any]:
        return dict(counters)

    return handler, get_metrics
