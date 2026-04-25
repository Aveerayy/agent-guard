"""Tests for agent_guard.server.config."""

from __future__ import annotations

import yaml

from agent_guard.server.config import (
    DefaultsConfig,
    GatewayServerConfig,
    TeamConfig,
    UpstreamConfig,
    _expand_env_vars,
    default_config_yaml,
    load_config,
)


class TestUpstreamConfig:
    def test_stdio_defaults(self):
        cfg = UpstreamConfig(command="npx", args=["@mcp/server"])
        assert cfg.transport == "stdio"
        assert cfg.command == "npx"
        assert cfg.url == ""

    def test_http_upstream(self):
        cfg = UpstreamConfig(transport="http", url="https://example.com/mcp")
        assert cfg.transport == "http"
        assert cfg.url == "https://example.com/mcp"


class TestTeamConfig:
    def test_defaults(self):
        cfg = TeamConfig()
        assert cfg.policy == "standard"
        assert cfg.allowed_upstreams == []
        assert cfg.max_calls_per_minute == 0


class TestGatewayServerConfig:
    def test_resolve_team_known(self):
        cfg = GatewayServerConfig(
            upstreams={"github": UpstreamConfig(command="npx")},
            teams={
                "alpha": TeamConfig(
                    token="tok",
                    policy="restrictive",
                    allowed_upstreams=["github"],
                    max_calls_per_minute=30,
                )
            },
        )
        team = cfg.resolve_team("alpha")
        assert team.policy == "restrictive"
        assert team.max_calls_per_minute == 30
        assert team.allowed_upstreams == ["github"]

    def test_resolve_team_unknown_gets_defaults(self):
        cfg = GatewayServerConfig(
            upstreams={"github": UpstreamConfig(), "slack": UpstreamConfig()},
            defaults=DefaultsConfig(policy="permissive", max_calls_per_minute=120),
        )
        team = cfg.resolve_team("new-team")
        assert team.policy == "permissive"
        assert team.max_calls_per_minute == 120
        assert set(team.allowed_upstreams) == {"github", "slack"}


class TestExpandEnvVars:
    def test_simple_expansion(self, monkeypatch):
        monkeypatch.setenv("MY_TOKEN", "secret123")
        result = _expand_env_vars("Bearer ${MY_TOKEN}")
        assert result == "Bearer secret123"

    def test_nested_dict(self, monkeypatch):
        monkeypatch.setenv("DB_HOST", "localhost")
        data = {"db": {"host": "${DB_HOST}", "port": 5432}}
        expanded = _expand_env_vars(data)
        assert expanded["db"]["host"] == "localhost"
        assert expanded["db"]["port"] == 5432

    def test_list_expansion(self, monkeypatch):
        monkeypatch.setenv("VAL", "x")
        result = _expand_env_vars(["${VAL}", "plain"])
        assert result == ["x", "plain"]

    def test_no_expansion_needed(self):
        assert _expand_env_vars("plain text") == "plain text"
        assert _expand_env_vars(42) == 42


class TestLoadConfig:
    def test_load_from_yaml(self, tmp_path):
        config_data = {
            "server": {"host": "127.0.0.1", "port": 9000},
            "database": {"url": "postgresql://db:5432/test"},
            "upstreams": {
                "github": {
                    "transport": "stdio",
                    "command": "npx",
                    "args": ["@mcp/github"],
                }
            },
            "teams": {
                "team-a": {
                    "token": "ag_team_abc",
                    "policy": "standard",
                    "allowed_upstreams": ["github"],
                }
            },
            "defaults": {"policy": "standard", "max_calls_per_minute": 100},
        }
        path = tmp_path / "gateway.yaml"
        path.write_text(yaml.dump(config_data))

        cfg = load_config(path)
        assert cfg.server.host == "127.0.0.1"
        assert cfg.server.port == 9000
        assert "github" in cfg.upstreams
        assert "team-a" in cfg.teams
        assert cfg.defaults.max_calls_per_minute == 100

    def test_load_with_env_expansion(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GH_TOKEN", "ghp_secret")
        config_data = {
            "upstreams": {
                "github": {
                    "command": "npx",
                    "env": {"GITHUB_TOKEN": "${GH_TOKEN}"},
                }
            }
        }
        path = tmp_path / "cfg.yaml"
        path.write_text(yaml.dump(config_data))

        cfg = load_config(path)
        assert cfg.upstreams["github"].env["GITHUB_TOKEN"] == "ghp_secret"


class TestDefaultConfigYaml:
    def test_parseable(self):
        text = default_config_yaml()
        data = yaml.safe_load(text)
        assert "server" in data
        assert data["server"]["port"] == 8443
