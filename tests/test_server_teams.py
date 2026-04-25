"""Tests for agent_guard.server.teams."""

from __future__ import annotations

from agent_guard.server.config import (
    DefaultsConfig,
    GatewayServerConfig,
    TeamConfig,
    UpstreamConfig,
)
from agent_guard.server.teams import TeamContext, TeamRegistry, _resolve_policy


def _make_config() -> GatewayServerConfig:
    return GatewayServerConfig(
        upstreams={
            "github": UpstreamConfig(command="npx", args=["@mcp/github"]),
            "slack": UpstreamConfig(transport="http", url="https://slack-mcp/mcp"),
        },
        teams={
            "alpha": TeamConfig(
                token="ag_team_aaa",
                policy="standard",
                allowed_upstreams=["github", "slack"],
                max_calls_per_minute=60,
            ),
            "beta": TeamConfig(
                token="ag_team_bbb",
                policy="restrictive",
                allowed_upstreams=["github"],
                max_calls_per_minute=30,
            ),
        },
        defaults=DefaultsConfig(policy="standard", max_calls_per_minute=60),
    )


class TestResolvePolicy:
    def test_standard(self):
        p = _resolve_policy("standard")
        assert p.name == "standard"

    def test_permissive(self):
        p = _resolve_policy("permissive")
        assert p.name == "permissive"

    def test_restrictive(self):
        p = _resolve_policy("restrictive")
        assert p.name == "restrictive"

    def test_unknown_falls_back_to_standard(self):
        p = _resolve_policy("custom-unknown")
        assert p.name == "standard"


class TestTeamRegistry:
    def test_get_or_create(self):
        config = _make_config()
        registry = TeamRegistry(config)
        ctx = registry.get_or_create("alpha")
        assert isinstance(ctx, TeamContext)
        assert ctx.team_id == "alpha"

    def test_same_team_returns_same_context(self):
        config = _make_config()
        registry = TeamRegistry(config)
        ctx1 = registry.get_or_create("alpha")
        ctx2 = registry.get_or_create("alpha")
        assert ctx1 is ctx2

    def test_different_teams_different_contexts(self):
        config = _make_config()
        registry = TeamRegistry(config)
        ctx_a = registry.get_or_create("alpha")
        ctx_b = registry.get_or_create("beta")
        assert ctx_a.team_id != ctx_b.team_id

    def test_dynamic_team_creation(self):
        config = _make_config()
        registry = TeamRegistry(config)
        ctx = registry.get_or_create("new-team")
        assert ctx.team_id == "new-team"
        assert ctx.config.policy == "standard"

    def test_team_gateway_authorize(self):
        config = _make_config()
        registry = TeamRegistry(config)
        ctx = registry.get_or_create("alpha")
        result = ctx.gateway.authorize("test_tool", agent_id="agent-1")
        assert result.allowed is True or result.allowed is False

    def test_kill_switch_per_team(self):
        config = _make_config()
        registry = TeamRegistry(config)
        registry.get_or_create("alpha")
        registry.get_or_create("beta")

        registry.activate_kill_switch("alpha")
        ctx_a = registry.get_or_create("alpha")
        ctx_b = registry.get_or_create("beta")
        assert ctx_a.kill_switch is True
        assert ctx_b.kill_switch is False

    def test_kill_switch_global(self):
        config = _make_config()
        registry = TeamRegistry(config)
        registry.get_or_create("alpha")
        registry.get_or_create("beta")

        registry.activate_kill_switch()
        assert registry.global_kill_switch is True
        ctx_a = registry.get_or_create("alpha")
        assert ctx_a.guard.kill_switch_active is True

    def test_deactivate_kill_switch(self):
        config = _make_config()
        registry = TeamRegistry(config)
        registry.get_or_create("alpha")
        registry.activate_kill_switch("alpha")
        registry.deactivate_kill_switch("alpha")
        ctx_a = registry.get_or_create("alpha")
        assert ctx_a.kill_switch is False

    def test_list_teams(self):
        config = _make_config()
        registry = TeamRegistry(config)
        registry.get_or_create("alpha")
        registry.get_or_create("beta")
        teams = registry.list_teams()
        assert "alpha" in teams
        assert "beta" in teams

    def test_stats(self):
        config = _make_config()
        registry = TeamRegistry(config)
        registry.get_or_create("alpha")
        s = registry.stats()
        assert s["total_teams"] == 1
        assert "alpha" in s["teams"]
        assert s["global_kill_switch"] is False
