"""Audit logging — tamper-evident record of all governance decisions."""

from __future__ import annotations

import hashlib
import json
import time
import threading
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class AuditEvent(BaseModel):
    """A single auditable event in the governance system."""

    event_id: str = ""
    timestamp: float = Field(default_factory=time.time)
    event_type: str = "policy_decision"
    agent_id: str = ""
    action: str = ""
    allowed: bool = False
    effect: str = ""
    matched_rule: str = ""
    reason: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    hash: str = ""

    def compute_hash(self, previous_hash: str = "") -> str:
        """Compute a chain hash linking this event to the previous one."""
        data = f"{previous_hash}:{self.timestamp}:{self.agent_id}:{self.action}:{self.allowed}"
        self.hash = hashlib.sha256(data.encode()).hexdigest()[:32]
        return self.hash


class AuditLog:
    """Append-only, hash-chained audit log for governance events.

    Usage:
        audit = AuditLog()

        # Log events
        audit.log("policy_decision", agent_id="agent-1", action="web_search", allowed=True)
        audit.log("policy_violation", agent_id="agent-2", action="shell_exec", allowed=False)

        # Query
        events = audit.query(agent_id="agent-1")
        violations = audit.violations()

        # Export
        audit.export_json("audit_trail.json")

        # Verify integrity
        assert audit.verify_chain()
    """

    def __init__(self, *, persist_path: str | Path | None = None):
        self._events: list[AuditEvent] = []
        self._lock = threading.Lock()
        self._persist_path = Path(persist_path) if persist_path else None
        self._counter = 0

    def log(
        self,
        event_type: str = "policy_decision",
        *,
        agent_id: str = "",
        action: str = "",
        allowed: bool = False,
        effect: str = "",
        matched_rule: str = "",
        reason: str = "",
        parameters: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Record an audit event."""
        with self._lock:
            self._counter += 1
            event = AuditEvent(
                event_id=f"evt-{self._counter:06d}",
                event_type=event_type,
                agent_id=agent_id,
                action=action,
                allowed=allowed,
                effect=effect,
                matched_rule=matched_rule,
                reason=reason,
                parameters=parameters or {},
                metadata=metadata or {},
            )
            prev_hash = self._events[-1].hash if self._events else ""
            event.compute_hash(prev_hash)
            self._events.append(event)

            if self._persist_path:
                self._append_to_file(event)

        return event

    def log_decision(self, decision: Any) -> AuditEvent:
        """Log a PolicyDecision object directly."""
        return self.log(
            "policy_decision",
            agent_id=getattr(decision, "agent_id", ""),
            action=getattr(decision, "action_name", ""),
            allowed=getattr(decision, "allowed", False),
            effect=getattr(decision, "effect", ""),
            matched_rule=getattr(decision, "matched_rule", ""),
            reason=getattr(decision, "reason", ""),
        )

    def query(
        self,
        *,
        agent_id: str | None = None,
        action: str | None = None,
        event_type: str | None = None,
        allowed: bool | None = None,
        since: float | None = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """Query the audit log with filters."""
        results = []
        for event in reversed(self._events):
            if agent_id and event.agent_id != agent_id:
                continue
            if action and event.action != action:
                continue
            if event_type and event.event_type != event_type:
                continue
            if allowed is not None and event.allowed != allowed:
                continue
            if since and event.timestamp < since:
                continue
            results.append(event)
            if len(results) >= limit:
                break
        return list(reversed(results))

    def violations(self, limit: int = 100) -> list[AuditEvent]:
        """Get recent policy violations."""
        return self.query(allowed=False, limit=limit)

    def verify_chain(self) -> bool:
        """Verify the hash chain integrity — detect tampering."""
        prev_hash = ""
        for event in self._events:
            expected = hashlib.sha256(
                f"{prev_hash}:{event.timestamp}:{event.agent_id}:"
                f"{event.action}:{event.allowed}".encode()
            ).hexdigest()[:32]
            if event.hash != expected:
                return False
            prev_hash = event.hash
        return True

    def export_json(self, path: str | Path) -> None:
        """Export the full audit trail as JSON."""
        data = [e.model_dump() for e in self._events]
        Path(path).write_text(json.dumps(data, indent=2, default=str))

    def export_dict(self) -> list[dict[str, Any]]:
        return [e.model_dump() for e in self._events]

    def summary(self) -> dict[str, Any]:
        total = len(self._events)
        allowed = sum(1 for e in self._events if e.allowed)
        agents = {e.agent_id for e in self._events if e.agent_id}
        actions = {e.action for e in self._events if e.action}
        return {
            "total_events": total,
            "allowed": allowed,
            "denied": total - allowed,
            "unique_agents": len(agents),
            "unique_actions": len(actions),
            "chain_valid": self.verify_chain(),
            "first_event": self._events[0].timestamp if self._events else None,
            "last_event": self._events[-1].timestamp if self._events else None,
        }

    def _append_to_file(self, event: AuditEvent) -> None:
        with open(self._persist_path, "a") as f:  # type: ignore[arg-type]
            f.write(json.dumps(event.model_dump(), default=str) + "\n")

    def __len__(self) -> int:
        return len(self._events)

    @property
    def events(self) -> list[AuditEvent]:
        return list(self._events)
