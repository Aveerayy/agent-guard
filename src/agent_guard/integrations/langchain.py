"""LangChain integration — add governance to any LangChain agent or chain.

Usage:
    from agent_guard import Guard, Policy
    from agent_guard.integrations.langchain import GovernedCallbackHandler

    guard = Guard()
    guard.add_policy(Policy.standard())

    handler = GovernedCallbackHandler(guard)

    # Use with any LangChain agent
    agent.run("research quantum computing", callbacks=[handler])
"""

from __future__ import annotations

import logging
from typing import Any

from agent_guard.core.engine import Guard
from agent_guard.audit.logger import AuditLog

logger = logging.getLogger(__name__)


class GovernedCallbackHandler:
    """LangChain callback handler that enforces governance on tool calls.

    Works with LangChain's callback system — drop it in with zero code changes.
    """

    def __init__(
        self,
        guard: Guard,
        *,
        agent_id: str = "langchain-agent",
        audit_log: AuditLog | None = None,
        raise_on_deny: bool = True,
    ):
        self.guard = guard
        self.agent_id = agent_id
        self.audit = audit_log or AuditLog()
        self.raise_on_deny = raise_on_deny

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        tool_name = serialized.get("name", "unknown_tool")
        decision = self.guard.evaluate(
            tool_name,
            agent_id=self.agent_id,
            parameters={"input": input_str},
        )
        self.audit.log_decision(decision)

        if not decision.allowed:
            logger.warning(f"Blocked tool '{tool_name}': {decision.reason}")
            if self.raise_on_deny:
                raise PermissionError(
                    f"Agent Guard blocked '{tool_name}': {decision.reason}"
                )

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        pass

    def on_tool_error(self, error: BaseException, **kwargs: Any) -> None:
        logger.error(f"Tool error: {error}")


def govern_tool(guard: Guard, tool: Any, *, agent_id: str = "langchain-agent") -> Any:
    """Wrap a LangChain tool with governance.

    Usage:
        from langchain.tools import DuckDuckGoSearchRun
        search = govern_tool(guard, DuckDuckGoSearchRun(), agent_id="researcher")
    """
    original_run = tool._run if hasattr(tool, "_run") else tool.run

    def governed_run(*args: Any, **kwargs: Any) -> Any:
        tool_name = getattr(tool, "name", type(tool).__name__)
        decision = guard.evaluate(tool_name, agent_id=agent_id, parameters=kwargs)
        if not decision.allowed:
            raise PermissionError(f"Agent Guard blocked '{tool_name}': {decision.reason}")
        return original_run(*args, **kwargs)

    if hasattr(tool, "_run"):
        tool._run = governed_run
    else:
        tool.run = governed_run
    return tool
