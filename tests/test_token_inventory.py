"""Tests for token inventory — CRUD, dedup, usage tracking, queries."""

from __future__ import annotations

import time

import pytest

from agent_guard.tokens.inventory import (
    RiskLevel,
    TokenInventory,
    TokenProvider,
    TokenRecord,
    TokenSource,
    TokenStatus,
    TokenType,
    _compute_token_id,
    _mask_value,
)


@pytest.fixture
def inventory():
    return TokenInventory()


def _make_record(
    provider=TokenProvider.AWS,
    token_type=TokenType.API_KEY,
    source=TokenSource.ENV_VAR,
    **kwargs,
):
    token_id = kwargs.pop("token_id", _compute_token_id(provider.value, "test12345678"))
    return TokenRecord(
        token_id=token_id,
        provider=provider,
        token_type=token_type,
        masked_value="test12...5678",
        source=source,
        source_detail=kwargs.pop("source_detail", "TEST_KEY"),
        **kwargs,
    )


class TestTokenRecord:
    def test_age_days(self):
        record = _make_record()
        record.first_seen = time.time() - (10 * 86400)
        assert 9.9 < record.age_days < 10.1

    def test_to_summary(self):
        record = _make_record()
        summary = record.to_summary()
        assert summary["provider"] == "aws"
        assert summary["token_type"] == "api_key"
        assert "token_id" in summary
        assert "risk_score" in summary


class TestMaskValue:
    def test_long_value(self):
        masked = _mask_value("sk-proj-abc123def456ghi789")
        assert masked.startswith("sk-pro")
        assert masked.endswith("i789")
        assert "..." in masked

    def test_short_value(self):
        masked = _mask_value("abcdefgh")
        assert masked.startswith("ab")
        assert masked.endswith("gh")
        assert "***" in masked


class TestComputeTokenId:
    def test_deterministic(self):
        id1 = _compute_token_id("aws", "AKIAIOSFODNN")
        id2 = _compute_token_id("aws", "AKIAIOSFODNN")
        assert id1 == id2

    def test_different_inputs(self):
        id1 = _compute_token_id("aws", "AKIAIOSFODNN")
        id2 = _compute_token_id("github", "ghp_ABCDEF")
        assert id1 != id2


class TestTokenInventory:
    def test_register_and_get(self, inventory):
        record = _make_record()
        inventory.register(record)
        assert inventory.count == 1
        fetched = inventory.get_token(record.token_id)
        assert fetched is not None
        assert fetched.provider == TokenProvider.AWS

    def test_dedup_merge(self, inventory):
        r1 = _make_record(agents=["agent-1"], tools=["tool-a"])
        r2 = _make_record(agents=["agent-2"], tools=["tool-b"])
        inventory.register(r1)
        inventory.register(r2)
        assert inventory.count == 1
        merged = inventory.get_token(r1.token_id)
        assert merged is not None
        assert "agent-1" in merged.agents
        assert "agent-2" in merged.agents
        assert "tool-a" in merged.tools
        assert "tool-b" in merged.tools
        assert merged.use_count == 2

    def test_record_usage(self, inventory):
        record = _make_record()
        inventory.register(record)
        result = inventory.record_usage(record.token_id, "agent-3", "tool-c")
        assert result is not None
        assert result.use_count == 2
        assert "agent-3" in result.agents
        assert "tool-c" in result.tools

    def test_record_usage_nonexistent(self, inventory):
        result = inventory.record_usage("nonexistent-id")
        assert result is None

    def test_list_tokens_no_filter(self, inventory):
        inventory.register(_make_record(provider=TokenProvider.AWS))
        inventory.register(
            _make_record(
                provider=TokenProvider.GITHUB,
                token_id=_compute_token_id("github", "ghp_test1234"),
            )
        )
        tokens = inventory.list_tokens()
        assert len(tokens) == 2

    def test_list_tokens_filter_provider(self, inventory):
        inventory.register(_make_record(provider=TokenProvider.AWS))
        inventory.register(
            _make_record(
                provider=TokenProvider.GITHUB,
                token_id=_compute_token_id("github", "ghp_test1234"),
            )
        )
        aws_only = inventory.list_tokens(provider=TokenProvider.AWS)
        assert len(aws_only) == 1
        assert aws_only[0].provider == TokenProvider.AWS

    def test_list_tokens_filter_risk(self, inventory):
        r1 = _make_record()
        r1.risk_level = RiskLevel.HIGH
        r1.risk_score = 70
        inventory.register(r1)

        r2 = _make_record(
            provider=TokenProvider.SLACK,
            token_id=_compute_token_id("slack", "xoxb-test1234"),
        )
        r2.risk_level = RiskLevel.LOW
        r2.risk_score = 20
        inventory.register(r2)

        high_only = inventory.list_tokens(risk_level=RiskLevel.HIGH)
        assert len(high_only) == 1

    def test_stale_tokens(self, inventory):
        fresh = _make_record()
        fresh.first_seen = time.time()
        inventory.register(fresh)

        old = _make_record(
            provider=TokenProvider.GITHUB,
            token_id=_compute_token_id("github", "old_token123"),
        )
        old.first_seen = time.time() - (100 * 86400)
        inventory.register(old)

        stale = inventory.stale_tokens(max_age_days=90)
        assert len(stale) == 1
        assert stale[0].provider == TokenProvider.GITHUB

    def test_update_risk(self, inventory):
        record = _make_record()
        inventory.register(record)
        inventory.update_risk(record.token_id, 85, RiskLevel.CRITICAL)
        updated = inventory.get_token(record.token_id)
        assert updated is not None
        assert updated.risk_score == 85
        assert updated.risk_level == RiskLevel.CRITICAL

    def test_mark_status(self, inventory):
        record = _make_record()
        inventory.register(record)
        inventory.mark_status(record.token_id, TokenStatus.REVOKED)
        updated = inventory.get_token(record.token_id)
        assert updated is not None
        assert updated.status == TokenStatus.REVOKED

    def test_summary(self, inventory):
        inventory.register(_make_record(provider=TokenProvider.AWS))
        inventory.register(
            _make_record(
                provider=TokenProvider.GITHUB,
                token_id=_compute_token_id("github", "ghp_summary12"),
            )
        )
        summary = inventory.summary()
        assert summary["total_tokens"] == 2
        assert "aws" in summary["by_provider"]
        assert "github" in summary["by_provider"]
        assert "active" in summary["by_status"]
