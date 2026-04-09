"""Tests for the core policy engine."""

import pytest

from agent_guard import Action, Effect, Guard, Policy, PolicyDecision


class TestPolicy:
    def test_standard_policy_allows_search(self):
        policy = Policy.standard()
        guard = Guard(policies=[policy])
        assert guard.check("web_search")

    def test_standard_policy_denies_shell(self):
        policy = Policy.standard()
        guard = Guard(policies=[policy])
        assert not guard.check("shell_exec")

    def test_permissive_policy_allows_all(self):
        policy = Policy.permissive()
        guard = Guard(policies=[policy])
        assert guard.check("anything_goes")

    def test_restrictive_policy_denies_all(self):
        policy = Policy.restrictive()
        guard = Guard(policies=[policy])
        assert not guard.check("web_search")

    def test_fluent_api(self):
        policy = Policy(default_effect=Effect.DENY).allow("read").deny("write")
        guard = Guard(policies=[policy])
        assert guard.check("read")
        assert not guard.check("write")

    def test_yaml_string(self):
        policy = Policy.from_yaml_string("""
name: test
default_effect: deny
rules:
  - action: web_search
    effect: allow
  - action: shell_exec
    effect: deny
""")
        guard = Guard(policies=[policy])
        assert guard.check("web_search")
        assert not guard.check("shell_exec")

    def test_wildcard_pattern(self):
        policy = Policy(default_effect=Effect.DENY).allow("file.*")
        guard = Guard(policies=[policy])
        assert guard.check("file.read")
        assert guard.check("file.write")
        assert not guard.check("shell_exec")

    def test_agent_specific_rules(self):
        policy = Policy(default_effect=Effect.DENY).allow("web_search", agents=["researcher"])
        guard = Guard(policies=[policy])
        assert guard.check("web_search", agent_id="researcher")
        assert not guard.check("web_search", agent_id="writer")

    def test_priority_ordering(self):
        policy = Policy(default_effect=Effect.DENY)
        policy.deny("web_search", priority=1, name="low")
        policy.allow("web_search", priority=10, name="high")
        guard = Guard(policies=[policy])
        assert guard.check("web_search")

    def test_conditions(self):
        from agent_guard.core.policy import Condition

        policy = Policy(default_effect=Effect.DENY).allow(
            "api_call",
            conditions=[Condition(field="parameters.safe", operator="equals", value=True)],
        )
        guard = Guard(policies=[policy])
        assert guard.check("api_call", parameters={"safe": True})
        assert not guard.check("api_call", parameters={"safe": False})


class TestGuard:
    def test_evaluate_returns_decision(self):
        guard = Guard(policies=[Policy.standard()])
        decision = guard.evaluate("web_search")
        assert isinstance(decision, PolicyDecision)
        assert decision.allowed
        assert decision.evaluation_time_ms > 0

    def test_kill_switch(self):
        guard = Guard(policies=[Policy.permissive()])
        assert guard.check("anything")
        guard.activate_kill_switch()
        assert not guard.check("anything")
        guard.deactivate_kill_switch()
        assert guard.check("anything")

    def test_decorator(self):
        guard = Guard(policies=[Policy.standard()])

        @guard.govern("web_search")
        def search(query: str) -> str:
            return f"results for {query}"

        assert search(query="test") == "results for test"

    def test_decorator_denies(self):
        guard = Guard(policies=[Policy.standard()])

        @guard.govern("shell_exec")
        def run_shell(cmd: str) -> str:
            return cmd

        with pytest.raises(PermissionError):
            run_shell(cmd="rm -rf /")

    def test_session(self):
        guard = Guard(policies=[Policy.standard()])
        with guard.session("test-agent") as session:
            assert session.check("web_search")
            assert not session.check("shell_exec")
            assert len(session.history) == 2

    def test_history_tracking(self):
        guard = Guard(policies=[Policy.standard()])
        guard.check("web_search")
        guard.check("shell_exec")
        assert len(guard.history) == 2

    def test_stats(self):
        guard = Guard(policies=[Policy.standard()])
        guard.check("web_search")
        guard.check("shell_exec")
        stats = guard.stats()
        assert stats["total_evaluations"] == 2
        assert stats["allowed"] == 1
        assert stats["denied"] == 1

    def test_deny_hook(self):
        denied_actions = []
        guard = Guard(
            policies=[Policy.standard()],
            on_deny=lambda d: denied_actions.append(d.action_name),
        )
        guard.check("shell_exec")
        assert "shell_exec" in denied_actions

    def test_multiple_policies(self):
        base = Policy(name="base", default_effect=Effect.DENY).allow("read")
        overlay = Policy(name="overlay", default_effect=Effect.DENY).allow("write")
        guard = Guard(policies=[base, overlay])
        assert guard.check("read")
        assert guard.check("write")

    def test_remove_policy(self):
        guard = Guard(policies=[Policy.standard()])
        assert guard.check("web_search")
        guard.remove_policy("standard")
        assert not guard.check("web_search")


class TestAction:
    def test_wildcard_match(self):
        action = Action(name="web_search")
        assert action.matches("*")
        assert action.matches("web_search")
        assert not action.matches("file_read")

    def test_prefix_match(self):
        action = Action(name="file.read")
        assert action.matches("file.*")
        assert not action.matches("web.*")
