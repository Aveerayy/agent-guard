"""Tests for token policy engine — governance rules and compliance checking."""

from __future__ import annotations

import time

from agent_guard.tokens.inventory import (
    RiskLevel,
    TokenProvider,
    TokenRecord,
    TokenSource,
    TokenStatus,
    TokenType,
    _compute_token_id,
)
from agent_guard.tokens.policy import TokenPolicy, TokenViolationType


def _make_record(
    provider=TokenProvider.AWS,
    source=TokenSource.ENV_VAR,
    age_days=30,
    agents=None,
    risk_score=20,
    status=TokenStatus.ACTIVE,
):
    return TokenRecord(
        token_id=_compute_token_id(provider.value, "test12345678"),
        provider=provider,
        token_type=TokenType.API_KEY,
        masked_value="test12...5678",
        source=source,
        source_detail="TEST_KEY",
        first_seen=time.time() - (age_days * 86400),
        agents=agents or [],
        risk_score=risk_score,
        risk_level=(
            RiskLevel.CRITICAL
            if risk_score > 75
            else RiskLevel.HIGH
            if risk_score > 50
            else RiskLevel.MEDIUM
            if risk_score > 25
            else RiskLevel.LOW
        ),
        status=status,
    )


class TestStaleTokenPolicy:
    def test_compliant_fresh_token(self):
        policy = TokenPolicy(max_age_days=90)
        record = _make_record(age_days=30)
        result = policy.evaluate(record)
        assert result.compliant
        assert len(result.violations) == 0

    def test_stale_token_flagged(self):
        policy = TokenPolicy(max_age_days=90)
        record = _make_record(age_days=120)
        result = policy.evaluate(record)
        assert not result.compliant
        assert TokenViolationType.STALE_TOKEN in result.violations
        assert any("120" in m for m in result.messages)

    def test_rotation_disabled(self):
        policy = TokenPolicy(require_rotation=False, max_age_days=90)
        record = _make_record(age_days=120)
        result = policy.evaluate(record)
        assert TokenViolationType.STALE_TOKEN not in result.violations


class TestExcessiveSharing:
    def test_within_limit(self):
        policy = TokenPolicy(max_agents_per_token=5)
        record = _make_record(agents=["a1", "a2"])
        result = policy.evaluate(record)
        assert TokenViolationType.EXCESSIVE_SHARING not in result.violations

    def test_exceeds_limit(self):
        policy = TokenPolicy(max_agents_per_token=3)
        record = _make_record(agents=["a1", "a2", "a3", "a4"])
        result = policy.evaluate(record)
        assert not result.compliant
        assert TokenViolationType.EXCESSIVE_SHARING in result.violations


class TestDeniedProvider:
    def test_allowed_provider(self):
        policy = TokenPolicy(denied_providers=["stripe"])
        record = _make_record(provider=TokenProvider.AWS)
        result = policy.evaluate(record)
        assert TokenViolationType.DENIED_PROVIDER not in result.violations

    def test_denied_provider(self):
        policy = TokenPolicy(denied_providers=["aws"])
        record = _make_record(provider=TokenProvider.AWS)
        result = policy.evaluate(record)
        assert not result.compliant
        assert TokenViolationType.DENIED_PROVIDER in result.violations

    def test_case_insensitive(self):
        policy = TokenPolicy(denied_providers=["AWS"])
        record = _make_record(provider=TokenProvider.AWS)
        result = policy.evaluate(record)
        assert TokenViolationType.DENIED_PROVIDER in result.violations


class TestInlineCredential:
    def test_env_var_ok(self):
        policy = TokenPolicy(alert_on_inline=True)
        record = _make_record(source=TokenSource.ENV_VAR)
        result = policy.evaluate(record)
        assert TokenViolationType.INLINE_CREDENTIAL not in result.violations

    def test_tool_argument_flagged(self):
        policy = TokenPolicy(alert_on_inline=True)
        record = _make_record(source=TokenSource.TOOL_ARGUMENT)
        result = policy.evaluate(record)
        assert not result.compliant
        assert TokenViolationType.INLINE_CREDENTIAL in result.violations

    def test_tool_output_flagged(self):
        policy = TokenPolicy(alert_on_inline=True)
        record = _make_record(source=TokenSource.TOOL_OUTPUT)
        result = policy.evaluate(record)
        assert TokenViolationType.INLINE_CREDENTIAL in result.violations

    def test_inline_alert_disabled(self):
        policy = TokenPolicy(alert_on_inline=False)
        record = _make_record(source=TokenSource.TOOL_ARGUMENT)
        result = policy.evaluate(record)
        assert TokenViolationType.INLINE_CREDENTIAL not in result.violations


class TestHighRisk:
    def test_within_threshold(self):
        policy = TokenPolicy(max_risk_score=75)
        record = _make_record(risk_score=50)
        result = policy.evaluate(record)
        assert TokenViolationType.HIGH_RISK not in result.violations

    def test_exceeds_threshold(self):
        policy = TokenPolicy(max_risk_score=75)
        record = _make_record(risk_score=80)
        result = policy.evaluate(record)
        assert not result.compliant
        assert TokenViolationType.HIGH_RISK in result.violations


class TestExpiredToken:
    def test_expired_flagged(self):
        policy = TokenPolicy()
        record = _make_record(status=TokenStatus.EXPIRED)
        result = policy.evaluate(record)
        assert not result.compliant
        assert TokenViolationType.EXPIRED in result.violations


class TestMultipleViolations:
    def test_multiple_violations_at_once(self):
        policy = TokenPolicy(
            max_age_days=90,
            denied_providers=["aws"],
            max_agents_per_token=2,
            max_risk_score=50,
        )
        record = _make_record(
            age_days=200,
            provider=TokenProvider.AWS,
            agents=["a1", "a2", "a3"],
            risk_score=80,
        )
        result = policy.evaluate(record)
        assert not result.compliant
        assert len(result.violations) >= 3


class TestEvaluateAll:
    def test_sorts_violations_first(self):
        policy = TokenPolicy(max_age_days=90)
        records = [
            _make_record(age_days=30),
            _make_record(age_days=200),
        ]
        results = policy.evaluate_all(records)
        assert not results[0].compliant
        assert results[1].compliant


class TestSummary:
    def test_summary_stats(self):
        policy = TokenPolicy(max_age_days=90)
        records = [
            _make_record(age_days=30),
            _make_record(age_days=200),
        ]
        summary = policy.summary(records)
        assert summary["total_tokens"] == 2
        assert summary["compliant"] == 1
        assert summary["non_compliant"] == 1
        assert summary["compliance_rate"] == 50.0
        assert "stale_token" in summary["violations_by_type"]

    def test_summary_empty(self):
        policy = TokenPolicy()
        summary = policy.summary([])
        assert summary["total_tokens"] == 0
        assert summary["compliance_rate"] == 100.0


class TestPolicyResultToDict:
    def test_to_dict(self):
        policy = TokenPolicy(max_age_days=90)
        record = _make_record(age_days=200)
        result = policy.evaluate(record)
        d = result.to_dict()
        assert d["compliant"] is False
        assert "stale_token" in d["violations"]
        assert len(d["messages"]) > 0
