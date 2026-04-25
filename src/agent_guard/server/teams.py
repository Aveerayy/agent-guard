"""Multi-tenant team registry — per-team Guard, policies, rate limits, and kill switch."""

from __future__ import annotations

import threading
from typing import Any

from agent_guard.core.engine import Guard
from agent_guard.core.policy import Policy
from agent_guard.mcp.gateway import GatewayConfig, MCPGateway
from agent_guard.server.config import GatewayServerConfig, TeamConfig
from agent_guard.server.store import PgAuditLog, PgTokenInventory


class TeamContext:
    """Runtime state for a single team: Guard, MCPGateway, audit, tokens."""

    __slots__ = (
        "team_id",
        "config",
        "guard",
        "gateway",
        "audit_log",
        "token_inventory",
        "kill_switch",
    )

    def __init__(
        self,
        team_id: str,
        config: TeamConfig,
        guard: Guard,
        gateway: MCPGateway,
        audit_log: PgAuditLog,
        token_inventory: PgTokenInventory,
    ):
        self.team_id = team_id
        self.config = config
        self.guard = guard
        self.gateway = gateway
        self.audit_log = audit_log
        self.token_inventory = token_inventory
        self.kill_switch = False


class TeamRegistry:
    """Manage per-team governance contexts.

    Creates a ``Guard`` + ``MCPGateway`` per team, each loaded with the
    policy template referenced in the team's config. Provides a global
    kill switch plus per-team overrides.

    Usage::

        registry = TeamRegistry(config)
        ctx = registry.get_or_create("team-alpha")
        result = ctx.gateway.authorize("web_search", agent_id="agent-1")
    """

    def __init__(
        self,
        config: GatewayServerConfig,
        *,
        db_pool: Any = None,
    ) -> None:
        self._config = config
        self._db_pool = db_pool
        self._teams: dict[str, TeamContext] = {}
        self._lock = threading.Lock()
        self._global_kill_switch = False

    def get_or_create(self, team_id: str) -> TeamContext:
        """Get an existing team context or create one on-demand."""
        with self._lock:
            ctx = self._teams.get(team_id)
            if ctx:
                return ctx

        team_cfg = self._config.resolve_team(team_id)
        ctx = self._build_context(team_id, team_cfg)

        with self._lock:
            existing = self._teams.get(team_id)
            if existing:
                return existing
            self._teams[team_id] = ctx
            return ctx

    def _build_context(self, team_id: str, team_cfg: TeamConfig) -> TeamContext:
        policy = _resolve_policy(team_cfg.policy)
        guard = Guard(policies=[policy])

        audit_log = PgAuditLog(pool=self._db_pool, team_id=team_id)
        token_inv = PgTokenInventory(pool=self._db_pool, team_id=team_id)

        gw_config = GatewayConfig(
            max_calls_per_minute=team_cfg.max_calls_per_minute,
        )
        gateway = MCPGateway(
            guard,
            config=gw_config,
            audit_log=audit_log,
            token_inventory=token_inv,
        )

        return TeamContext(
            team_id=team_id,
            config=team_cfg,
            guard=guard,
            gateway=gateway,
            audit_log=audit_log,
            token_inventory=token_inv,
        )

    def activate_kill_switch(self, team_id: str | None = None) -> None:
        """Activate kill switch globally or for a specific team."""
        if team_id:
            ctx = self._teams.get(team_id)
            if ctx:
                ctx.kill_switch = True
                ctx.guard.activate_kill_switch()
        else:
            self._global_kill_switch = True
            for ctx in self._teams.values():
                ctx.guard.activate_kill_switch()

    def deactivate_kill_switch(self, team_id: str | None = None) -> None:
        if team_id:
            ctx = self._teams.get(team_id)
            if ctx:
                ctx.kill_switch = False
                ctx.guard.deactivate_kill_switch()
        else:
            self._global_kill_switch = False
            for ctx in self._teams.values():
                ctx.guard.deactivate_kill_switch()

    @property
    def global_kill_switch(self) -> bool:
        return self._global_kill_switch

    def list_teams(self) -> list[str]:
        return list(self._teams.keys())

    def stats(self) -> dict[str, Any]:
        team_stats = {}
        for tid, ctx in self._teams.items():
            team_stats[tid] = {
                "policy": ctx.config.policy,
                "kill_switch": ctx.kill_switch,
                "gateway": ctx.gateway.stats(),
            }
        return {
            "total_teams": len(self._teams),
            "global_kill_switch": self._global_kill_switch,
            "teams": team_stats,
        }


def _resolve_policy(name: str) -> Policy:
    """Map a policy template name to a Policy object."""
    name_lower = name.lower()
    if name_lower == "permissive":
        return Policy.permissive()
    if name_lower == "restrictive":
        return Policy.restrictive()
    return Policy.standard()
