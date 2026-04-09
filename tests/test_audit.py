"""Tests for audit logging."""

from agent_guard import AuditLog


class TestAuditLog:
    def test_log_event(self):
        audit = AuditLog()
        event = audit.log("policy_decision", agent_id="agent-1", action="search", allowed=True)
        assert event.event_id == "evt-000001"
        assert event.hash

    def test_chain_integrity(self):
        audit = AuditLog()
        audit.log("test", agent_id="a", action="x", allowed=True)
        audit.log("test", agent_id="b", action="y", allowed=False)
        audit.log("test", agent_id="c", action="z", allowed=True)
        assert audit.verify_chain()

    def test_tamper_detection(self):
        audit = AuditLog()
        audit.log("test", agent_id="a", action="x", allowed=True)
        audit.log("test", agent_id="b", action="y", allowed=False)
        audit._events[0].hash = "tampered"
        assert not audit.verify_chain()

    def test_query_by_agent(self):
        audit = AuditLog()
        audit.log("test", agent_id="alice", action="search", allowed=True)
        audit.log("test", agent_id="bob", action="write", allowed=False)
        audit.log("test", agent_id="alice", action="read", allowed=True)
        results = audit.query(agent_id="alice")
        assert len(results) == 2

    def test_query_violations(self):
        audit = AuditLog()
        audit.log("test", agent_id="a", action="search", allowed=True)
        audit.log("test", agent_id="b", action="shell", allowed=False)
        violations = audit.violations()
        assert len(violations) == 1
        assert violations[0].action == "shell"

    def test_summary(self):
        audit = AuditLog()
        audit.log("test", agent_id="a", action="x", allowed=True)
        audit.log("test", agent_id="b", action="y", allowed=False)
        summary = audit.summary()
        assert summary["total_events"] == 2
        assert summary["allowed"] == 1
        assert summary["denied"] == 1
        assert summary["chain_valid"]

    def test_export_dict(self):
        audit = AuditLog()
        audit.log("test", agent_id="a", action="x", allowed=True)
        data = audit.export_dict()
        assert len(data) == 1
        assert data[0]["agent_id"] == "a"

    def test_len(self):
        audit = AuditLog()
        assert len(audit) == 0
        audit.log("test")
        assert len(audit) == 1
