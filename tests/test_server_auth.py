"""Tests for agent_guard.server.auth."""

from __future__ import annotations

from agent_guard.server.auth import TeamAuthenticator, _hash_token
from agent_guard.server.config import (
    GatewayServerConfig,
    TeamConfig,
    UpstreamConfig,
)


def _make_config(**team_overrides) -> GatewayServerConfig:
    teams = {
        "alpha": TeamConfig(
            token="ag_team_alpha_secret",
            policy="standard",
            allowed_upstreams=["github"],
        ),
        "beta": TeamConfig(
            token="ag_team_beta_secret",
            policy="restrictive",
        ),
    }
    teams.update(team_overrides)
    return GatewayServerConfig(
        upstreams={"github": UpstreamConfig(command="npx")},
        teams=teams,
    )


class TestTeamAuthenticator:
    def test_valid_bearer_token(self):
        config = _make_config()
        auth = TeamAuthenticator(config)
        result = auth.authenticate("Bearer ag_team_alpha_secret")
        assert result.authenticated
        assert result.team_id == "alpha"
        assert result.team_config is not None

    def test_second_team(self):
        config = _make_config()
        auth = TeamAuthenticator(config)
        result = auth.authenticate("Bearer ag_team_beta_secret")
        assert result.authenticated
        assert result.team_id == "beta"

    def test_invalid_token(self):
        config = _make_config()
        auth = TeamAuthenticator(config)
        result = auth.authenticate("Bearer wrong_token")
        assert not result.authenticated
        assert "Invalid team token" in result.reason

    def test_missing_header(self):
        config = _make_config()
        auth = TeamAuthenticator(config)
        result = auth.authenticate("")
        assert not result.authenticated
        assert "Missing" in result.reason

    def test_bad_format(self):
        config = _make_config()
        auth = TeamAuthenticator(config)
        result = auth.authenticate("Basic dXNlcjpwYXNz")
        assert not result.authenticated
        assert "Invalid" in result.reason

    def test_anonymous_when_no_teams(self):
        config = GatewayServerConfig()
        auth = TeamAuthenticator(config)
        result = auth.authenticate("")
        assert result.authenticated
        assert result.team_id == "default"

    def test_generate_token(self):
        config = _make_config()
        auth = TeamAuthenticator(config)
        new_token = auth.generate_token("gamma")
        assert new_token.startswith("ag_team_")
        result = auth.authenticate(f"Bearer {new_token}")
        assert result.authenticated
        assert result.team_id == "gamma"

    def test_team_ids(self):
        config = _make_config()
        auth = TeamAuthenticator(config)
        ids = auth.team_ids
        assert "alpha" in ids
        assert "beta" in ids

    def test_to_dict(self):
        config = _make_config()
        auth = TeamAuthenticator(config)
        d = auth.to_dict()
        assert d["teams_registered"] == 2
        assert d["allow_anonymous"] is False


class TestHashToken:
    def test_deterministic(self):
        assert _hash_token("abc") == _hash_token("abc")

    def test_different_inputs(self):
        assert _hash_token("a") != _hash_token("b")
