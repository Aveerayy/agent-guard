"""Team authentication — extract and verify team identity from HTTP requests."""

from __future__ import annotations

import hashlib
import secrets
from typing import Any

from agent_guard.server.config import GatewayServerConfig, TeamConfig


class AuthResult:
    """Outcome of authenticating an incoming request."""

    __slots__ = ("authenticated", "team_id", "team_config", "reason")

    def __init__(
        self,
        *,
        authenticated: bool,
        team_id: str = "",
        team_config: TeamConfig | None = None,
        reason: str = "",
    ):
        self.authenticated = authenticated
        self.team_id = team_id
        self.team_config = team_config
        self.reason = reason


class TeamAuthenticator:
    """Authenticate incoming requests against the team registry.

    Tokens are stored hashed; comparison is constant-time.

    Usage::

        auth = TeamAuthenticator(config)
        result = auth.authenticate("Bearer ag_team_xxxx")
        if result.authenticated:
            print(result.team_id, result.team_config)
    """

    def __init__(self, config: GatewayServerConfig) -> None:
        self._token_map: dict[str, str] = {}
        for team_id, team_cfg in config.teams.items():
            if team_cfg.token:
                hashed = _hash_token(team_cfg.token)
                self._token_map[hashed] = team_id
        self._config = config
        self._allow_anonymous = len(config.teams) == 0

    def authenticate(self, authorization: str) -> AuthResult:
        """Authenticate from an Authorization header value.

        Accepts ``Bearer <token>`` format.
        """
        if self._allow_anonymous:
            return AuthResult(
                authenticated=True,
                team_id="default",
                team_config=self._config.resolve_team("default"),
                reason="No teams configured; anonymous access allowed",
            )

        if not authorization:
            return AuthResult(authenticated=False, reason="Missing Authorization header")

        parts = authorization.split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return AuthResult(authenticated=False, reason="Invalid Authorization format")

        token = parts[1].strip()
        hashed = _hash_token(token)

        team_id = self._token_map.get(hashed)
        if not team_id:
            return AuthResult(authenticated=False, reason="Invalid team token")

        return AuthResult(
            authenticated=True,
            team_id=team_id,
            team_config=self._config.resolve_team(team_id),
        )

    def generate_token(self, team_id: str) -> str:
        """Generate a new team token (for admin use)."""
        raw = f"ag_team_{secrets.token_hex(20)}"
        hashed = _hash_token(raw)
        self._token_map[hashed] = team_id
        return raw

    @property
    def team_ids(self) -> list[str]:
        return list(set(self._token_map.values()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "teams_registered": len(self._token_map),
            "allow_anonymous": self._allow_anonymous,
        }


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
