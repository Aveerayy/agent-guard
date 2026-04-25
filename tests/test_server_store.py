"""Tests for agent_guard.server.store — PgAuditLog and PgTokenInventory.

These tests exercise the in-memory (no database) code paths.
PostgreSQL persistence is tested via integration tests that require
a running database (skipped when asyncpg is not available).
"""

from __future__ import annotations

from agent_guard.server.store import PgAuditLog, PgTokenInventory
from agent_guard.tokens.inventory import (
    RiskLevel,
    TokenProvider,
    TokenRecord,
    TokenSource,
    TokenType,
)


class TestPgAuditLogInMemory:
    """Test PgAuditLog without a database pool (fallback to in-memory)."""

    def test_log_event(self):
        audit = PgAuditLog(team_id="team-a")
        event = audit.log("policy_decision", agent_id="agent-1", action="search", allowed=True)
        assert event.event_id == "evt-000001"
        assert event.agent_id == "agent-1"

    def test_chain_integrity(self):
        audit = PgAuditLog(team_id="team-a")
        audit.log("test", agent_id="a", action="x", allowed=True)
        audit.log("test", agent_id="b", action="y", allowed=False)
        audit.log("test", agent_id="c", action="z", allowed=True)
        assert audit.verify_chain()

    def test_query_filters(self):
        audit = PgAuditLog(team_id="team-a")
        audit.log("test", agent_id="a", action="read", allowed=True)
        audit.log("test", agent_id="b", action="write", allowed=False)
        audit.log("test", agent_id="a", action="delete", allowed=False)

        violations = audit.violations()
        assert len(violations) == 2
        agent_a = audit.query(agent_id="a")
        assert len(agent_a) == 2

    def test_summary(self):
        audit = PgAuditLog(team_id="team-a")
        audit.log("test", agent_id="a", action="read", allowed=True)
        audit.log("test", agent_id="b", action="write", allowed=False)
        s = audit.summary()
        assert s["total_events"] == 2
        assert s["allowed"] == 1
        assert s["denied"] == 1

    def test_export_dict(self):
        audit = PgAuditLog(team_id="team-a")
        audit.log("test", agent_id="a", action="x", allowed=True)
        exported = audit.export_dict()
        assert len(exported) == 1
        assert exported[0]["agent_id"] == "a"


class TestPgTokenInventoryInMemory:
    """Test PgTokenInventory without a database pool."""

    def _make_record(self, provider="github", token_id="tok-1"):
        return TokenRecord(
            token_id=token_id,
            provider=TokenProvider(provider),
            token_type=TokenType.API_KEY,
            masked_value="ghp_ab...ef",
            source=TokenSource.ENV_VAR,
        )

    def test_register_and_list(self):
        inv = PgTokenInventory(team_id="team-a")
        inv.register(self._make_record())
        tokens = inv.list_tokens()
        assert len(tokens) == 1
        assert tokens[0].token_id == "tok-1"

    def test_deduplication(self):
        inv = PgTokenInventory(team_id="team-a")
        inv.register(self._make_record())
        inv.register(self._make_record())
        assert inv.count == 1

    def test_summary(self):
        inv = PgTokenInventory(team_id="team-a")
        inv.register(self._make_record("github", "tok-1"))
        inv.register(self._make_record("aws", "tok-2"))
        s = inv.summary()
        assert s["total_tokens"] == 2
        assert "github" in s["by_provider"]
        assert "aws" in s["by_provider"]

    def test_risk_update(self):
        inv = PgTokenInventory(team_id="team-a")
        inv.register(self._make_record())
        inv.update_risk("tok-1", 85, RiskLevel.CRITICAL)
        tok = inv.get_token("tok-1")
        assert tok is not None
        assert tok.risk_score == 85
        assert tok.risk_level == RiskLevel.CRITICAL
