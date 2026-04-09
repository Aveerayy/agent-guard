"""CrewAI integration — add governance to CrewAI agents and crews.

Usage:
    from agent_guard import Guard, Policy
    from agent_guard.integrations.crewai import GovernedCrew

    guard = Guard()
    guard.add_policy(Policy.standard())

    governed = GovernedCrew(guard)

    # Wrap a CrewAI tool
    governed_tool = governed.wrap_tool(my_tool, agent_id="researcher")

    # Or govern an entire crew's execution
    governed.before_task("researcher", "web_search", {"query": "AI news"})
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from agent_guard.audit.logger import AuditLog
from agent_guard.core.engine import Guard

logger = logging.getLogger(__name__)


class GovernedCrew:
    """Governance layer for CrewAI agents and tools."""

    def __init__(
        self,
        guard: Guard,
        *,
        audit_log: AuditLog | None = None,
        raise_on_deny: bool = True,
    ):
        self.guard = guard
        self.audit = audit_log or AuditLog()
        self.raise_on_deny = raise_on_deny

    def wrap_tool(
        self,
        tool: Any,
        *,
        agent_id: str = "crewai-agent",
        action_name: str | None = None,
    ) -> Any:
        """Wrap a CrewAI tool with governance checks."""
        name = action_name or getattr(tool, "name", type(tool).__name__)
        original_run = tool._run if hasattr(tool, "_run") else tool.run

        governed_self = self

        def governed_run(*args: Any, **kwargs: Any) -> Any:
            decision = governed_self.guard.evaluate(
                str(name or "unknown"), agent_id=agent_id, parameters=kwargs
            )
            governed_self.audit.log_decision(decision)

            if not decision.allowed:
                logger.warning(f"Blocked '{name}' for {agent_id}: {decision.reason}")
                if governed_self.raise_on_deny:
                    raise PermissionError(f"Agent Guard blocked '{name}': {decision.reason}")
                return None

            return original_run(*args, **kwargs)

        if hasattr(tool, "_run"):
            tool._run = governed_run
        else:
            tool.run = governed_run
        return tool

    def before_task(
        self,
        agent_id: str,
        action: str,
        parameters: dict[str, Any] | None = None,
    ) -> bool:
        """Check governance before a task executes. Returns True if allowed."""
        decision = self.guard.evaluate(action, agent_id=agent_id, parameters=parameters or {})
        self.audit.log_decision(decision)

        if not decision.allowed and self.raise_on_deny:
            raise PermissionError(f"Agent Guard blocked '{action}': {decision.reason}")

        return decision.allowed

    def after_task(self, agent_id: str, action: str, *, success: bool = True) -> None:
        self.audit.log(
            "task_complete" if success else "task_failed",
            agent_id=agent_id,
            action=action,
            allowed=True,
        )


def govern_crewai_tool(
    guard: Guard,
    action_name: str,
    *,
    agent_id: str = "crewai-agent",
) -> Callable:
    """Decorator for CrewAI tool functions.

    Usage:
        @govern_crewai_tool(guard, "web_search", agent_id="researcher")
        def search(query: str) -> str:
            ...
    """

    def decorator(fn: Callable) -> Callable:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            decision = guard.evaluate(action_name, agent_id=agent_id, parameters=kwargs)
            if not decision.allowed:
                raise PermissionError(f"Agent Guard blocked '{action_name}': {decision.reason}")
            return fn(*args, **kwargs)

        wrapper.__name__ = fn.__name__
        wrapper.__doc__ = fn.__doc__
        return wrapper

    return decorator
