"""AutoGen integration — governance for Microsoft AutoGen agents.

Usage:
    from agent_guard import Guard, Policy
    from agent_guard.integrations.autogen import GovernedAutoGen

    guard = Guard()
    guard.add_policy(Policy.standard())

    gov = GovernedAutoGen(guard)
    gov.before_execute("assistant", "code_exec", {"code": "print('hello')"})
"""

from __future__ import annotations

import logging
from typing import Any
from collections.abc import Callable

from agent_guard.core.engine import Guard
from agent_guard.audit.logger import AuditLog

logger = logging.getLogger(__name__)


class GovernedAutoGen:
    """Governance wrapper for AutoGen agent interactions."""

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

    def before_execute(
        self,
        agent_name: str,
        action: str,
        parameters: dict[str, Any] | None = None,
    ) -> bool:
        """Check governance before an AutoGen agent executes an action."""
        decision = self.guard.evaluate(
            action, agent_id=agent_name, parameters=parameters or {}
        )
        self.audit.log_decision(decision)

        if not decision.allowed:
            logger.warning(f"Blocked '{action}' for {agent_name}: {decision.reason}")
            if self.raise_on_deny:
                raise PermissionError(
                    f"Agent Guard blocked '{action}': {decision.reason}"
                )
        return decision.allowed

    def wrap_function(
        self,
        fn: Callable,
        action_name: str,
        *,
        agent_id: str = "autogen-agent",
    ) -> Callable:
        """Wrap a function map entry with governance."""
        governed_self = self

        def wrapper(*args: Any, **kwargs: Any) -> Any:
            decision = governed_self.guard.evaluate(
                action_name, agent_id=agent_id, parameters=kwargs
            )
            governed_self.audit.log_decision(decision)
            if not decision.allowed:
                raise PermissionError(
                    f"Agent Guard blocked '{action_name}': {decision.reason}"
                )
            return fn(*args, **kwargs)

        wrapper.__name__ = fn.__name__
        wrapper.__doc__ = fn.__doc__
        return wrapper

    def govern_code_execution(
        self, agent_name: str, code: str
    ) -> bool:
        """Specifically govern code execution — common in AutoGen workflows."""
        return self.before_execute(
            agent_name, "code_exec", parameters={"code": code[:500]}
        )
