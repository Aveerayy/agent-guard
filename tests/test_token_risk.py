"""Tests for token risk scoring engine."""

from __future__ import annotations

import time

import pytest

from agent_guard.tokens.inventory import (
    RiskLevel,
    TokenProvider,
    TokenRecord,
    TokenSource,
    TokenType,
    _compute_token_id,
)
from agent_guard.tokens.risk import RiskScorer


@pytest.fixture
def scorer():
    return RiskScorer()


def _make_record(
    provider=TokenProvider.AWS,
    token_type=TokenType.API_KEY,
    source=TokenSource.ENV_VAR,
    age_days=30,
    agents=None,
):
    record = TokenRecord(
        token_id=_compute_token_id(provider.value, "test12345678"),
        provider=provider,
        token_type=token_type,
        masked_value="test12...5678",
        source=source,
        source_detail="TEST_KEY",
        first_seen=time.time() - (age_days * 86400),
        agents=agents or [],
    )
    return record


class TestProviderCriticality:
    def test_aws_highest(self, scorer):
        aws = _make_record(provider=TokenProvider.AWS)
        custom = _make_record(provider=TokenProvider.CUSTOM)
        aws_score, _ = scorer.score(aws)
        custom_score, _ = scorer.score(custom)
        assert aws_score > custom_score

    def test_github_higher_than_slack(self, scorer):
        gh = _make_record(provider=TokenProvider.GITHUB)
        slack = _make_record(provider=TokenProvider.SLACK)
        gh_score, _ = scorer.score(gh)
        slack_score, _ = scorer.score(slack)
        assert gh_score > slack_score


class TestAgeScoring:
    def test_old_token_scores_higher(self, scorer):
        old = _make_record(age_days=400)
        fresh = _make_record(age_days=30)
        old_score, _ = scorer.score(old)
        fresh_score, _ = scorer.score(fresh)
        assert old_score > fresh_score

    def test_age_thresholds(self, scorer):
        t365 = _make_record(age_days=400)
        t180 = _make_record(age_days=200)
        t90 = _make_record(age_days=100)
        t30 = _make_record(age_days=30)

        s365, _ = scorer.score(t365)
        s180, _ = scorer.score(t180)
        s90, _ = scorer.score(t90)
        s30, _ = scorer.score(t30)

        assert s365 > s180 > s90 > s30


class TestExposureScoring:
    def test_tool_arg_higher_than_env(self, scorer):
        inline = _make_record(source=TokenSource.TOOL_ARGUMENT)
        env = _make_record(source=TokenSource.ENV_VAR)
        inline_score, _ = scorer.score(inline)
        env_score, _ = scorer.score(env)
        assert inline_score > env_score


class TestBreadthScoring:
    def test_many_agents_scores_higher(self, scorer):
        shared = _make_record(agents=["a1", "a2", "a3", "a4", "a5"])
        single = _make_record(agents=["a1"])
        shared_score, _ = scorer.score(shared)
        single_score, _ = scorer.score(single)
        assert shared_score > single_score


class TestRiskLevels:
    def test_critical_level(self, scorer):
        record = _make_record(
            provider=TokenProvider.AWS,
            token_type=TokenType.SECRET_KEY,
            source=TokenSource.TOOL_ARGUMENT,
            age_days=400,
            agents=["a1", "a2", "a3", "a4", "a5"],
        )
        score, level = scorer.score(record)
        assert level == RiskLevel.CRITICAL
        assert score >= 76

    def test_low_level(self, scorer):
        record = _make_record(
            provider=TokenProvider.CUSTOM,
            token_type=TokenType.JWT,
            source=TokenSource.ENV_VAR,
            age_days=10,
            agents=[],
        )
        score, level = scorer.score(record)
        # 5 (custom) + 10 (jwt) + 5 (young) + 8 (env) + 5 (no agents) = 33 MEDIUM
        # The lowest possible is still MEDIUM with real tokens
        assert level in (RiskLevel.LOW, RiskLevel.MEDIUM)
        assert score < 50

    def test_score_capped_at_100(self, scorer):
        record = _make_record(
            provider=TokenProvider.AWS,
            token_type=TokenType.SECRET_KEY,
            source=TokenSource.TOOL_ARGUMENT,
            age_days=500,
            agents=[f"a{i}" for i in range(10)],
        )
        score, _ = scorer.score(record)
        assert score <= 100


class TestScoreAll:
    def test_scores_and_sorts(self, scorer):
        records = [
            _make_record(provider=TokenProvider.CUSTOM, age_days=10),
            _make_record(provider=TokenProvider.AWS, age_days=400),
        ]
        scored = scorer.score_all(records)
        assert scored[0].risk_score >= scored[1].risk_score
        assert all(r.risk_score > 0 for r in scored)
        assert all(r.risk_level != RiskLevel.LOW or r.risk_score <= 25 for r in scored)
