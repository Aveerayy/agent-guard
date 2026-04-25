"""Tests for token governance dashboard API endpoints."""

from __future__ import annotations

import json
import time
from http.client import HTTPConnection

import pytest

from agent_guard.core.engine import Guard
from agent_guard.core.policy import Policy
from agent_guard.dashboard.server import DashboardState, run_dashboard
from agent_guard.tokens.inventory import (
    RiskLevel,
    TokenInventory,
    TokenProvider,
    TokenRecord,
    TokenSource,
    TokenType,
    _compute_token_id,
)


def _make_record(provider=TokenProvider.AWS, idx=0):
    return TokenRecord(
        token_id=_compute_token_id(provider.value, f"test{idx:08d}"),
        provider=provider,
        token_type=TokenType.API_KEY,
        masked_value=f"test{idx}...5678",
        source=TokenSource.ENV_VAR,
        source_detail=f"KEY_{idx}",
        risk_score=50,
        risk_level=RiskLevel.MEDIUM,
        first_seen=time.time() - (30 * 86400),
    )


class TestDashboardStateTokens:
    def test_tokens_empty(self):
        state = DashboardState(Guard())
        assert state.tokens() == []
        assert state.tokens_summary() == {"total_tokens": 0}
        assert state.tokens_stale() == []

    def test_tokens_with_inventory(self):
        inv = TokenInventory()
        inv.register(_make_record(idx=1))
        inv.register(_make_record(provider=TokenProvider.GITHUB, idx=2))
        state = DashboardState(Guard(), token_inventory=inv)

        tokens = state.tokens()
        assert len(tokens) == 2
        assert all("provider" in t for t in tokens)
        assert all("risk_score" in t for t in tokens)

    def test_tokens_summary(self):
        inv = TokenInventory()
        inv.register(_make_record(idx=1))
        state = DashboardState(Guard(), token_inventory=inv)
        summary = state.tokens_summary()
        assert summary["total_tokens"] == 1

    def test_tokens_stale(self):
        inv = TokenInventory()
        old_record = _make_record(idx=3)
        old_record.first_seen = time.time() - (100 * 86400)
        inv.register(old_record)
        inv.register(_make_record(idx=4))

        state = DashboardState(Guard(), token_inventory=inv)
        stale = state.tokens_stale(max_age_days=90)
        assert len(stale) == 1


class TestDashboardHTTPTokenEndpoints:
    @pytest.fixture
    def server(self):
        guard = Guard()
        guard.add_policy(Policy.permissive())
        inv = TokenInventory()
        inv.register(_make_record(idx=1))
        inv.register(_make_record(provider=TokenProvider.GITHUB, idx=2))
        srv = run_dashboard(
            guard,
            token_inventory=inv,
            port=7799,
            open_browser=False,
            blocking=False,
        )
        yield srv
        srv.shutdown()

    def _get(self, path: str) -> dict | list:
        conn = HTTPConnection("127.0.0.1", 7799)
        conn.request("GET", path)
        resp = conn.getresponse()
        assert resp.status == 200
        return json.loads(resp.read())

    def test_api_tokens(self, server):
        data = self._get("/api/tokens")
        assert isinstance(data, list)
        assert len(data) == 2

    def test_api_tokens_summary(self, server):
        data = self._get("/api/tokens/summary")
        assert data["total_tokens"] == 2

    def test_api_tokens_stale(self, server):
        data = self._get("/api/tokens/stale")
        assert isinstance(data, list)
