"""The Guard — central governance engine that evaluates every agent action."""

from __future__ import annotations

import time
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from agent_guard.core.actions import Action, ActionType
from agent_guard.core.policy import Effect, Policy, PolicyDecision, PolicyRule


class Guard:
    """Central governance engine. Create one, add policies, and check every action.

    Usage:
        guard = Guard()
        guard.add_policy(Policy.standard())

        # Simple check
        if guard.check("web_search"):
            do_search()

        # Full check with context
        result = guard.evaluate("shell_exec", agent_id="my-agent", parameters={"cmd": "ls"})
        if result.allowed:
            run_command()

        # Decorator
        @guard.govern("web_search")
        def search(query: str):
            ...

        # Context manager
        with guard.session("my-agent") as session:
            session.check("web_search")
            session.check("file_read")
    """

    def __init__(
        self,
        policies: list[Policy] | None = None,
        *,
        on_deny: Callable[[PolicyDecision], None] | None = None,
        on_audit: Callable[[PolicyDecision], None] | None = None,
        default_agent_id: str = "default",
    ):
        self._policies: list[Policy] = policies or []
        self._deny_hook = on_deny
        self._audit_hook = on_audit
        self._default_agent_id = default_agent_id
        self._history: list[PolicyDecision] = []
        self._lock = threading.Lock()
        self._kill_switch = False

    def add_policy(self, policy: Policy) -> Guard:
        """Add a policy to the evaluation stack. Returns self for chaining."""
        with self._lock:
            self._policies.append(policy)
        return self

    def load_policy(self, path: str | Path) -> Guard:
        """Load and add a policy from a YAML file."""
        return self.add_policy(Policy.from_yaml(path))

    def remove_policy(self, name: str) -> Guard:
        """Remove a policy by name."""
        with self._lock:
            self._policies = [p for p in self._policies if p.name != name]
        return self

    def check(
        self,
        action_name: str,
        *,
        agent_id: str | None = None,
        action_type: ActionType = ActionType.TOOL_CALL,
        parameters: dict[str, Any] | None = None,
        resource: str | None = None,
    ) -> bool:
        """Quick boolean check — is this action allowed?"""
        return self.evaluate(
            action_name,
            agent_id=agent_id,
            action_type=action_type,
            parameters=parameters,
            resource=resource,
        ).allowed

    def evaluate(
        self,
        action_name: str,
        *,
        agent_id: str | None = None,
        action_type: ActionType = ActionType.TOOL_CALL,
        parameters: dict[str, Any] | None = None,
        resource: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        """Full policy evaluation with detailed decision."""
        start = time.perf_counter()

        if self._kill_switch:
            return PolicyDecision(
                allowed=False,
                effect=Effect.DENY,
                matched_rule="KILL_SWITCH",
                reason="Kill switch activated — all actions blocked",
                action_name=action_name,
                agent_id=agent_id or self._default_agent_id,
            )

        action = Action(
            name=action_name,
            action_type=action_type,
            agent_id=agent_id or self._default_agent_id,
            parameters=parameters or {},
            resource=resource,
            metadata=metadata or {},
        )

        decision = self._evaluate_action(action)
        decision.evaluation_time_ms = (time.perf_counter() - start) * 1000

        with self._lock:
            self._history.append(decision)

        if decision.effect == Effect.DENY and self._deny_hook:
            self._deny_hook(decision)
        elif decision.effect == Effect.AUDIT and self._audit_hook:
            self._audit_hook(decision)

        return decision

    def evaluate_action(self, action: Action) -> PolicyDecision:
        """Evaluate a pre-built Action object."""
        start = time.perf_counter()
        if self._kill_switch:
            return PolicyDecision(
                allowed=False,
                effect=Effect.DENY,
                matched_rule="KILL_SWITCH",
                reason="Kill switch activated",
                action_name=action.name,
                agent_id=action.agent_id,
            )
        decision = self._evaluate_action(action)
        decision.evaluation_time_ms = (time.perf_counter() - start) * 1000
        with self._lock:
            self._history.append(decision)
        return decision

    def _evaluate_action(self, action: Action) -> PolicyDecision:
        all_rules: list[tuple[PolicyRule, Policy]] = []
        for policy in self._policies:
            for rule in policy.rules:
                all_rules.append((rule, policy))

        all_rules.sort(key=lambda x: x[0].priority, reverse=True)

        for rule, _policy in all_rules:
            if rule.matches_action(action):
                allowed = rule.effect in (Effect.ALLOW, Effect.AUDIT)
                return PolicyDecision(
                    allowed=allowed,
                    effect=rule.effect,
                    matched_rule=rule.name,
                    reason=rule.reason,
                    action_name=action.name,
                    agent_id=action.agent_id,
                )

        default = self._resolve_default_effect()
        allowed = default in (Effect.ALLOW, Effect.AUDIT)
        return PolicyDecision(
            allowed=allowed,
            effect=default,
            matched_rule="default",
            reason=f"No rule matched — default effect is {default.value}",
            action_name=action.name,
            agent_id=action.agent_id,
        )

    def _resolve_default_effect(self) -> Effect:
        if self._policies:
            return self._policies[-1].default_effect
        return Effect.DENY

    # --- Kill switch ---

    def activate_kill_switch(self) -> None:
        """Emergency stop: block ALL actions for ALL agents immediately."""
        self._kill_switch = True

    def deactivate_kill_switch(self) -> None:
        self._kill_switch = False

    @property
    def kill_switch_active(self) -> bool:
        return self._kill_switch

    # --- Decorator ---

    def govern(
        self,
        action_name: str,
        *,
        agent_id: str | None = None,
        action_type: ActionType = ActionType.TOOL_CALL,
        raise_on_deny: bool = True,
    ) -> Callable:
        """Decorator that enforces governance before function execution.

            @guard.govern("web_search")
            def search(query: str):
                ...
        """
        def decorator(fn: Callable) -> Callable:
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                decision = self.evaluate(
                    action_name,
                    agent_id=agent_id,
                    action_type=action_type,
                    parameters=kwargs,
                )
                if not decision.allowed:
                    if raise_on_deny:
                        raise PermissionError(
                            f"Action '{action_name}' denied: {decision.reason}"
                        )
                    return None
                return fn(*args, **kwargs)
            wrapper.__name__ = fn.__name__
            wrapper.__doc__ = fn.__doc__
            return wrapper
        return decorator

    # --- Session context ---

    def session(self, agent_id: str) -> GuardSession:
        """Create a session scoped to a specific agent."""
        return GuardSession(self, agent_id)

    # --- Introspection ---

    @property
    def history(self) -> list[PolicyDecision]:
        return list(self._history)

    @property
    def policies(self) -> list[Policy]:
        return list(self._policies)

    def stats(self) -> dict[str, Any]:
        total = len(self._history)
        allowed = sum(1 for d in self._history if d.allowed)
        denied = total - allowed
        avg_ms = (
            sum(d.evaluation_time_ms for d in self._history) / total if total else 0
        )
        return {
            "total_evaluations": total,
            "allowed": allowed,
            "denied": denied,
            "allow_rate": allowed / total if total else 0,
            "avg_evaluation_ms": round(avg_ms, 4),
            "policies_loaded": len(self._policies),
            "total_rules": sum(len(p.rules) for p in self._policies),
            "kill_switch": self._kill_switch,
        }

    def clear_history(self) -> None:
        with self._lock:
            self._history.clear()


class GuardSession:
    """A governance session scoped to a single agent — avoids repeating agent_id."""

    def __init__(self, guard: Guard, agent_id: str):
        self._guard = guard
        self._agent_id = agent_id
        self._decisions: list[PolicyDecision] = []

    def check(self, action_name: str, **kwargs: Any) -> bool:
        decision = self._guard.evaluate(action_name, agent_id=self._agent_id, **kwargs)
        self._decisions.append(decision)
        return decision.allowed

    def evaluate(self, action_name: str, **kwargs: Any) -> PolicyDecision:
        decision = self._guard.evaluate(action_name, agent_id=self._agent_id, **kwargs)
        self._decisions.append(decision)
        return decision

    @property
    def history(self) -> list[PolicyDecision]:
        return list(self._decisions)

    def __enter__(self) -> GuardSession:
        return self

    def __exit__(self, *args: Any) -> None:
        pass
