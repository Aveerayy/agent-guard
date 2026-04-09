"""Tests for the dashboard server."""

import json
import time
import urllib.request

import pytest
from agent_guard import Guard, Policy
from agent_guard.audit.logger import AuditLog
from agent_guard.dashboard.server import DashboardState, run_dashboard


class TestDashboardState:
    def test_overview(self):
        guard = Guard(policies=[Policy.standard()])
        audit = AuditLog()
        state = DashboardState(guard, audit_log=audit)
        overview = state.overview()
        assert "uptime_seconds" in overview
        assert "guard" in overview
        assert "audit" in overview

    def test_recent_events(self):
        guard = Guard(policies=[Policy.standard()])
        audit = AuditLog()
        audit.log("test", agent_id="a", action="search", allowed=True)
        state = DashboardState(guard, audit_log=audit)
        events = state.recent_events()
        assert len(events) == 1
        assert events[0]["agent_id"] == "a"

    def test_violations(self):
        guard = Guard(policies=[Policy.standard()])
        audit = AuditLog()
        audit.log("deny", agent_id="a", action="shell", allowed=False)
        state = DashboardState(guard, audit_log=audit)
        violations = state.violations()
        assert len(violations) == 1

    def test_policies(self):
        guard = Guard(policies=[Policy.standard()])
        state = DashboardState(guard)
        policies = state.policies()
        assert len(policies) == 1
        assert policies[0]["name"] == "standard"


class TestDashboardServer:
    def test_server_starts_and_serves(self):
        guard = Guard(policies=[Policy.standard()])
        audit = AuditLog()
        guard.evaluate("web_search", agent_id="test")
        audit.log("test_event", agent_id="test", action="web_search", allowed=True)

        server = run_dashboard(
            guard, audit_log=audit,
            port=17701, open_browser=False, blocking=False,
        )

        try:
            time.sleep(0.3)

            resp = urllib.request.urlopen("http://127.0.0.1:17701/")
            html = resp.read().decode()
            assert "Agent Guard" in html

            resp = urllib.request.urlopen("http://127.0.0.1:17701/api/overview")
            data = json.loads(resp.read().decode())
            assert "guard" in data
            assert data["guard"]["total_evaluations"] == 1

            resp = urllib.request.urlopen("http://127.0.0.1:17701/api/events")
            events = json.loads(resp.read().decode())
            assert isinstance(events, list)

            resp = urllib.request.urlopen("http://127.0.0.1:17701/api/policies")
            policies = json.loads(resp.read().decode())
            assert len(policies) >= 1

        finally:
            server.shutdown()
