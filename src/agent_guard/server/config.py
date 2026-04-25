"""Server configuration — YAML loader for upstreams, teams, policies, and server settings."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class UpstreamConfig(BaseModel):
    """Configuration for a single upstream MCP server."""

    transport: str = "stdio"
    command: str = ""
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    url: str = ""


class TeamConfig(BaseModel):
    """Configuration for a single team."""

    token: str = ""
    policy: str = "standard"
    allowed_upstreams: list[str] = Field(default_factory=list)
    max_calls_per_minute: int = 0


class DefaultsConfig(BaseModel):
    """Default settings applied when team-specific values are absent."""

    policy: str = "standard"
    max_calls_per_minute: int = 60


class ServerSettings(BaseModel):
    """Top-level server binding settings."""

    host: str = "0.0.0.0"
    port: int = 8443


class DatabaseConfig(BaseModel):
    """PostgreSQL connection settings."""

    url: str = "postgresql://localhost:5432/agent_guard"
    min_connections: int = 2
    max_connections: int = 10


class GatewayServerConfig(BaseModel):
    """Complete configuration for the central MCP gateway server."""

    server: ServerSettings = Field(default_factory=ServerSettings)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    upstreams: dict[str, UpstreamConfig] = Field(default_factory=dict)
    teams: dict[str, TeamConfig] = Field(default_factory=dict)
    defaults: DefaultsConfig = Field(default_factory=DefaultsConfig)
    auth_token: str = ""

    def resolve_team(self, team_id: str) -> TeamConfig:
        """Get team config with defaults filled in."""
        registered = self.teams.get(team_id)
        team = registered.model_copy() if registered else TeamConfig(policy=self.defaults.policy)
        if not team.allowed_upstreams:
            team.allowed_upstreams = list(self.upstreams.keys())
        if team.max_calls_per_minute <= 0:
            team.max_calls_per_minute = self.defaults.max_calls_per_minute
        return team


def _expand_env_vars(obj: Any) -> Any:
    """Recursively expand ${VAR} references in string values."""
    if isinstance(obj, str) and "${" in obj:
        for key, val in os.environ.items():
            obj = obj.replace(f"${{{key}}}", val)
        return obj
    if isinstance(obj, dict):
        return {k: _expand_env_vars(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_expand_env_vars(v) for v in obj]
    return obj


def load_config(path: str | Path) -> GatewayServerConfig:
    """Load gateway configuration from a YAML file."""
    raw = yaml.safe_load(Path(path).read_text())
    raw = _expand_env_vars(raw)
    return GatewayServerConfig.model_validate(raw)


def default_config_yaml() -> str:
    """Return a starter YAML config for ``agent-guard server init``."""
    return """\
server:
  host: "0.0.0.0"
  port: 8443

database:
  url: "postgresql://localhost:5432/agent_guard"

upstreams:
  # example-stdio:
  #   transport: stdio
  #   command: "npx"
  #   args: ["@modelcontextprotocol/server-github"]
  #   env:
  #     GITHUB_TOKEN: "${GITHUB_TOKEN}"
  # example-http:
  #   transport: http
  #   url: "https://mcp-server.internal/mcp"

teams:
  # team-alpha:
  #   token: "ag_team_xxxx"
  #   policy: "standard"
  #   allowed_upstreams: ["example-stdio", "example-http"]

defaults:
  policy: "standard"
  max_calls_per_minute: 60
"""
