"""Action types and request models for governance evaluation."""

from __future__ import annotations

import time
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ActionType(str, Enum):
    """Categories of agent actions that can be governed."""

    TOOL_CALL = "tool_call"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    NETWORK = "network"
    SHELL_EXEC = "shell_exec"
    DATABASE = "database"
    API_CALL = "api_call"
    AGENT_MESSAGE = "agent_message"
    MEMORY_WRITE = "memory_write"
    CODE_EXEC = "code_exec"
    CUSTOM = "custom"


class Action(BaseModel):
    """An action an agent wants to perform, submitted to the Guard for evaluation."""

    name: str = Field(description="Action identifier, e.g. 'web_search' or 'file_write'")
    action_type: ActionType = ActionType.TOOL_CALL
    agent_id: str = Field(default="anonymous")
    parameters: dict[str, Any] = Field(default_factory=dict)
    resource: str | None = Field(default=None, description="Target resource path or identifier")
    timestamp: float = Field(default_factory=time.time)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def matches(self, pattern: str) -> bool:
        """Check if this action matches a glob-style pattern (supports '*' wildcard)."""
        if pattern == "*":
            return True
        if pattern.endswith(".*"):
            prefix = pattern[:-2]
            return self.name.startswith(prefix + ".") or self.name == prefix
        if pattern.startswith("*."):
            suffix = pattern[2:]
            return self.name.endswith("." + suffix) or self.name == suffix
        return self.name == pattern
