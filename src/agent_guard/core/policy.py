"""Policy definitions, loading, and evaluation primitives."""

from __future__ import annotations

import fnmatch
from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from agent_guard.core.actions import Action, ActionType


class Effect(str, Enum):
    """The result of a policy rule evaluation."""

    ALLOW = "allow"
    DENY = "deny"
    AUDIT = "audit"  # allow but log for review


class Condition(BaseModel):
    """A condition that must be true for a rule to apply."""

    field: str = Field(description="Dot-path into the action, e.g. 'parameters.query'")
    operator: str = Field(
        default="equals",
        description="One of: equals, not_equals, contains, "
        "not_contains, matches, gt, lt, gte, lte, in, not_in, exists",
    )
    value: Any = None

    def evaluate(self, action: Action) -> bool:
        actual = self._resolve(action)
        op = self.operator
        if op == "equals":
            return bool(actual == self.value)
        if op == "not_equals":
            return bool(actual != self.value)
        if op == "contains":
            return self.value in actual if actual else False
        if op == "not_contains":
            return self.value not in actual if actual else True
        if op == "matches":
            return fnmatch.fnmatch(str(actual), str(self.value)) if actual else False
        if op == "gt":
            return actual > self.value if actual is not None else False
        if op == "lt":
            return actual < self.value if actual is not None else False
        if op == "gte":
            return actual >= self.value if actual is not None else False
        if op == "lte":
            return actual <= self.value if actual is not None else False
        if op == "in":
            return actual in self.value if self.value else False
        if op == "not_in":
            return actual not in self.value if self.value else True
        if op == "exists":
            return actual is not None
        return False

    def _resolve(self, action: Action) -> Any:
        """Walk a dot-path to extract a value from the action."""
        obj: Any = action
        for part in self.field.split("."):
            if isinstance(obj, dict):
                obj = obj.get(part)
            elif isinstance(obj, BaseModel):
                obj = getattr(obj, part, None)
            else:
                return None
        return obj


class PolicyRule(BaseModel):
    """A single governance rule within a policy."""

    name: str = ""
    action: str = Field(description="Action pattern to match, e.g. 'web_search', 'file.*', '*'")
    effect: Effect = Effect.DENY
    action_types: list[ActionType] | None = None
    agents: list[str] | None = Field(
        default=None, description="Agent IDs this rule applies to (None = all)"
    )
    conditions: list[Condition] = Field(default_factory=list)
    priority: int = Field(default=0, description="Higher priority rules are evaluated first")
    reason: str = ""

    def matches_action(self, action: Action) -> bool:
        if not action.matches(self.action):
            return False
        if self.action_types and action.action_type not in self.action_types:
            return False
        if self.agents and action.agent_id not in self.agents:
            return False
        return all(c.evaluate(action) for c in self.conditions)


class PolicyDecision(BaseModel):
    """The outcome of evaluating an action against a policy set."""

    allowed: bool
    effect: Effect
    matched_rule: str = ""
    reason: str = ""
    action_name: str = ""
    agent_id: str = ""
    evaluation_time_ms: float = 0.0

    def __bool__(self) -> bool:
        return self.allowed


class Policy(BaseModel):
    """A named collection of governance rules."""

    name: str = "default"
    description: str = ""
    version: str = "1.0"
    default_effect: Effect = Effect.DENY
    rules: list[PolicyRule] = Field(default_factory=list)

    def add_rule(
        self,
        action: str,
        effect: Effect = Effect.ALLOW,
        *,
        agents: list[str] | None = None,
        conditions: list[Condition] | None = None,
        priority: int = 0,
        name: str = "",
        reason: str = "",
    ) -> Policy:
        """Fluent API: add a rule and return self for chaining."""
        self.rules.append(
            PolicyRule(
                name=name or f"{effect.value}_{action}",
                action=action,
                effect=effect,
                agents=agents,
                conditions=conditions or [],
                priority=priority,
                reason=reason,
            )
        )
        return self

    def allow(self, action: str, **kwargs: Any) -> Policy:
        """Shorthand to add an allow rule."""
        return self.add_rule(action, Effect.ALLOW, **kwargs)

    def deny(self, action: str, **kwargs: Any) -> Policy:
        """Shorthand to add a deny rule."""
        return self.add_rule(action, Effect.DENY, **kwargs)

    def audit(self, action: str, **kwargs: Any) -> Policy:
        """Shorthand to add an audit rule (allow + log)."""
        return self.add_rule(action, Effect.AUDIT, **kwargs)

    @classmethod
    def from_yaml(cls, path: str | Path) -> Policy:
        """Load a policy from a YAML file."""
        data = yaml.safe_load(Path(path).read_text())
        return cls._from_dict(data)

    @classmethod
    def from_yaml_string(cls, content: str) -> Policy:
        """Load a policy from a YAML string."""
        data = yaml.safe_load(content)
        return cls._from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        return cls._from_dict(data)

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> Policy:
        rules = []
        for r in data.get("rules", []):
            conditions = [Condition(**c) for c in r.get("conditions", [])]
            rules.append(
                PolicyRule(
                    name=r.get("name", ""),
                    action=r.get("action", "*"),
                    effect=Effect(r.get("effect", "deny")),
                    action_types=[ActionType(t) for t in r.get("action_types", [])] or None,
                    agents=r.get("agents"),
                    conditions=conditions,
                    priority=r.get("priority", 0),
                    reason=r.get("reason", ""),
                )
            )
        return cls(
            name=data.get("name", "default"),
            description=data.get("description", ""),
            version=str(data.get("version", "1.0")),
            default_effect=Effect(data.get("default_effect", "deny")),
            rules=rules,
        )

    @classmethod
    def permissive(cls) -> Policy:
        """A starter policy that allows everything but audits shell and file writes."""
        return (
            cls(
                name="permissive",
                description="Allow everything, audit dangerous actions",
                default_effect=Effect.ALLOW,
            )
            .audit("shell_exec", reason="Shell execution audited")
            .audit("file_write", reason="File writes audited")
        )

    @classmethod
    def restrictive(cls) -> Policy:
        """A locked-down policy that only allows explicitly listed actions."""
        return cls(
            name="restrictive",
            description="Deny by default — only explicitly allowed actions proceed",
            default_effect=Effect.DENY,
        )

    @classmethod
    def standard(cls) -> Policy:
        """A balanced policy suitable for most use cases."""
        return (
            cls(
                name="standard",
                description="Balanced governance: common tools allowed, dangerous actions denied",
                default_effect=Effect.DENY,
            )
            .allow("web_search", reason="Search is safe")
            .allow("file_read", reason="Reading files is safe")
            .allow("api_call", reason="API calls allowed by default")
            .deny("shell_exec", reason="Shell execution requires explicit approval")
            .deny("file_write", reason="File writes require explicit approval")
            .deny("code_exec", reason="Code execution requires explicit approval")
            .audit("database", reason="Database operations are audited")
        )
