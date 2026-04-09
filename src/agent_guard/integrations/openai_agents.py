"""OpenAI Agents SDK integration — governance middleware for OpenAI agents.

Usage:
    from agent_guard import Guard, Policy
    from agent_guard.integrations.openai_agents import govern_openai_tool

    guard = Guard()
    guard.add_policy(Policy.standard())

    # Wrap any tool function
    @govern_openai_tool(guard, "web_search")
    def web_search(query: str) -> str:
        return do_search(query)
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from agent_guard.audit.logger import AuditLog
from agent_guard.core.engine import Guard

logger = logging.getLogger(__name__)


def govern_openai_tool(
    guard: Guard,
    action_name: str,
    *,
    agent_id: str = "openai-agent",
    audit_log: AuditLog | None = None,
) -> Callable:
    """Decorator to wrap an OpenAI Agents SDK tool function with governance.

    Usage:
        @govern_openai_tool(guard, "web_search")
        def search(query: str) -> str:
            ...
    """
    audit = audit_log or AuditLog()

    def decorator(fn: Callable) -> Callable:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            decision = guard.evaluate(
                action_name,
                agent_id=agent_id,
                parameters=kwargs,
            )
            audit.log_decision(decision)

            if not decision.allowed:
                logger.warning(f"Blocked '{action_name}': {decision.reason}")
                raise PermissionError(f"Agent Guard blocked '{action_name}': {decision.reason}")

            return fn(*args, **kwargs)

        wrapper.__name__ = fn.__name__
        wrapper.__doc__ = fn.__doc__
        return wrapper

    return decorator


class OpenAIGovernanceMiddleware:
    """Middleware that intercepts all tool calls in an OpenAI agent.

    Usage:
        middleware = OpenAIGovernanceMiddleware(guard)

        # Before any tool call
        decision = middleware.before_tool_call("web_search", {"query": "AI news"})
        if decision.allowed:
            result = execute_tool(...)
            middleware.after_tool_call("web_search", success=True)
    """

    def __init__(
        self,
        guard: Guard,
        *,
        agent_id: str = "openai-agent",
        audit_log: AuditLog | None = None,
    ):
        self.guard = guard
        self.agent_id = agent_id
        self.audit = audit_log or AuditLog()

    def before_tool_call(self, tool_name: str, parameters: dict[str, Any] | None = None) -> Any:
        decision = self.guard.evaluate(
            tool_name, agent_id=self.agent_id, parameters=parameters or {}
        )
        self.audit.log_decision(decision)
        return decision

    def after_tool_call(self, tool_name: str, *, success: bool = True, error: str = "") -> None:
        event_type = "tool_success" if success else "tool_error"
        self.audit.log(
            event_type,
            agent_id=self.agent_id,
            action=tool_name,
            allowed=True,
            metadata={"error": error} if error else {},
        )
