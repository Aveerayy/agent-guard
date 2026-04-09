"""Agent Guard Dashboard — lightweight HTTP server for real-time governance monitoring.

Zero external dependencies — uses only Python stdlib (http.server + json).
Provides a JSON API consumed by the embedded single-page dashboard.
"""

from __future__ import annotations

import json
import threading
import time
import webbrowser
from functools import partial
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any

from agent_guard.core.engine import Guard
from agent_guard.audit.logger import AuditLog
from agent_guard.mcp.gateway import MCPGateway


_DASHBOARD_HTML = (Path(__file__).parent / "index.html").read_bytes


class DashboardState:
    """Shared state accessible by the dashboard API endpoints."""

    def __init__(
        self,
        guard: Guard,
        audit_log: AuditLog | None = None,
        gateway: MCPGateway | None = None,
    ):
        self.guard = guard
        self.audit_log = audit_log or AuditLog()
        self.gateway = gateway
        self._start_time = time.time()

    def overview(self) -> dict[str, Any]:
        guard_stats = self.guard.stats()
        audit_summary = self.audit_log.summary()
        gateway_stats = self.gateway.stats() if self.gateway else {}
        uptime = time.time() - self._start_time

        return {
            "uptime_seconds": round(uptime, 1),
            "kill_switch": guard_stats.get("kill_switch", False),
            "guard": guard_stats,
            "audit": audit_summary,
            "gateway": gateway_stats,
        }

    def recent_events(self, limit: int = 50) -> list[dict[str, Any]]:
        events = self.audit_log.query(limit=limit)
        return [e.model_dump() for e in events]

    def violations(self, limit: int = 50) -> list[dict[str, Any]]:
        events = self.audit_log.violations(limit=limit)
        return [e.model_dump() for e in events]

    def policies(self) -> list[dict[str, Any]]:
        return [
            {
                "name": p.name,
                "description": p.description,
                "default_effect": p.default_effect.value,
                "rules_count": len(p.rules),
                "rules": [
                    {
                        "name": r.name,
                        "action": r.action,
                        "effect": r.effect.value,
                        "reason": r.reason,
                    }
                    for r in p.rules
                ],
            }
            for p in self.guard.policies
        ]

    def gateway_calls(self, limit: int = 50) -> list[dict[str, Any]]:
        if not self.gateway:
            return []
        calls = self.gateway.call_log[-limit:]
        return [c.model_dump() for c in calls]


class _Handler(BaseHTTPRequestHandler):
    """HTTP request handler for the dashboard."""

    state: DashboardState
    auth_token: str

    def do_GET(self) -> None:
        path = self.path.split("?")[0]

        if path == "/" or path == "/index.html":
            self._serve_html()
        elif path == "/api/overview":
            self._json_response(self.state.overview())
        elif path == "/api/events":
            self._json_response(self.state.recent_events())
        elif path == "/api/violations":
            self._json_response(self.state.violations())
        elif path == "/api/policies":
            self._json_response(self.state.policies())
        elif path == "/api/gateway":
            self._json_response(self.state.gateway_calls())
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        path = self.path.split("?")[0]

        if self.auth_token:
            provided = self.headers.get("Authorization", "")
            if provided != f"Bearer {self.auth_token}":
                self.send_error(403, "Forbidden — valid Bearer token required for write operations")
                return

        if path == "/api/kill-switch/activate":
            self.state.guard.activate_kill_switch()
            self._json_response({"status": "activated"})
        elif path == "/api/kill-switch/deactivate":
            self.state.guard.deactivate_kill_switch()
            self._json_response({"status": "deactivated"})
        else:
            self.send_error(404)

    def _serve_html(self) -> None:
        html = _DASHBOARD_HTML()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)

    def _json_response(self, data: Any) -> None:
        body = json.dumps(data, default=str).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        pass


def run_dashboard(
    guard: Guard,
    *,
    audit_log: AuditLog | None = None,
    gateway: MCPGateway | None = None,
    host: str = "127.0.0.1",
    port: int = 7700,
    open_browser: bool = True,
    blocking: bool = True,
    auth_token: str = "",
) -> HTTPServer:
    """Start the Agent Guard dashboard server.

    Usage:
        from agent_guard import Guard
        from agent_guard.dashboard.server import run_dashboard

        guard = Guard()
        guard.add_policy(Policy.standard())
        run_dashboard(guard)  # opens http://127.0.0.1:7700

        # Non-blocking (returns server, runs in background thread)
        server = run_dashboard(guard, blocking=False)
        # ... do other work ...
        server.shutdown()

        # With auth token (required for POST /api/kill-switch/*)
        run_dashboard(guard, auth_token="my-secret-token")
    """
    state = DashboardState(guard, audit_log=audit_log, gateway=gateway)

    handler_class = type("Handler", (_Handler,), {"state": state, "auth_token": auth_token})
    server = HTTPServer((host, port), handler_class)

    if open_browser:
        webbrowser.open(f"http://{host}:{port}")

    if blocking:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()
    else:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

    return server
