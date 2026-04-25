"""Tests for agent_guard.server.app — GatewayApp request handling."""

from __future__ import annotations

import pytest

from agent_guard.server.app import GatewayApp, _jsonrpc_error, _jsonrpc_result
from agent_guard.server.config import (
    GatewayServerConfig,
    TeamConfig,
    UpstreamConfig,
)


def _make_config() -> GatewayServerConfig:
    return GatewayServerConfig(
        upstreams={
            "mock": UpstreamConfig(transport="http", url="http://localhost:19999/mcp"),
        },
        teams={
            "alpha": TeamConfig(
                token="ag_team_alpha",
                policy="standard",
                allowed_upstreams=["mock"],
            ),
        },
    )


def _make_anonymous_config() -> GatewayServerConfig:
    return GatewayServerConfig(
        upstreams={
            "mock": UpstreamConfig(transport="http", url="http://localhost:19999/mcp"),
        },
    )


class TestJsonRpcHelpers:
    def test_jsonrpc_result(self):
        resp = _jsonrpc_result(1, {"tools": []})
        assert resp["jsonrpc"] == "2.0"
        assert resp["id"] == 1
        assert resp["result"] == {"tools": []}

    def test_jsonrpc_error(self):
        resp = _jsonrpc_error(2, -32601, "Method not found")
        assert resp["error"]["code"] == -32601
        assert resp["error"]["message"] == "Method not found"


class TestGatewayAppMCPRequests:
    @pytest.mark.asyncio
    async def test_initialize(self):
        config = _make_config()
        gw = GatewayApp(config)
        await gw.start()

        body = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        result, sid, status = await gw.handle_mcp_request(body, "Bearer ag_team_alpha")
        assert status == 200
        assert result["result"]["serverInfo"]["name"] == "agent-guard-gateway"
        assert sid != ""

        await gw.shutdown()

    @pytest.mark.asyncio
    async def test_tools_list(self):
        config = _make_config()
        gw = GatewayApp(config)
        await gw.start()

        gw.proxy.register_upstream_tools(
            "mock",
            [
                {"name": "search", "description": "Search the web"},
            ],
        )

        body = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        result, sid, status = await gw.handle_mcp_request(body, "Bearer ag_team_alpha")
        assert status == 200
        tools = result["result"]["tools"]
        assert len(tools) == 1
        assert tools[0]["name"] == "mock/search"

        await gw.shutdown()

    @pytest.mark.asyncio
    async def test_unauthenticated_request(self):
        config = _make_config()
        gw = GatewayApp(config)
        await gw.start()

        body = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        result, sid, status = await gw.handle_mcp_request(body, "")
        assert status == 401
        assert "error" in result

        await gw.shutdown()

    @pytest.mark.asyncio
    async def test_unknown_method(self):
        config = _make_config()
        gw = GatewayApp(config)
        await gw.start()

        body = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "resources/list",
            "params": {},
        }
        result, sid, status = await gw.handle_mcp_request(body, "Bearer ag_team_alpha")
        assert status == 200
        assert "error" in result
        assert result["error"]["code"] == -32601

        await gw.shutdown()

    @pytest.mark.asyncio
    async def test_notifications_initialized(self):
        config = _make_config()
        gw = GatewayApp(config)
        await gw.start()

        body = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        }
        result, sid, status = await gw.handle_mcp_request(body, "Bearer ag_team_alpha")
        assert status == 204

        await gw.shutdown()

    @pytest.mark.asyncio
    async def test_anonymous_access(self):
        config = _make_anonymous_config()
        gw = GatewayApp(config)
        await gw.start()

        body = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        result, sid, status = await gw.handle_mcp_request(body, "")
        assert status == 200

        await gw.shutdown()

    @pytest.mark.asyncio
    async def test_session_persistence(self):
        config = _make_config()
        gw = GatewayApp(config)
        await gw.start()

        body = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        _, sid1, _ = await gw.handle_mcp_request(body, "Bearer ag_team_alpha")
        _, sid2, _ = await gw.handle_mcp_request(body, "Bearer ag_team_alpha", sid1)
        assert sid1 == sid2

        await gw.shutdown()


class TestGatewayAppDashboardAPIs:
    @pytest.mark.asyncio
    async def test_get_overview(self):
        config = _make_config()
        gw = GatewayApp(config)
        await gw.start()

        overview = await gw.get_overview()
        assert "proxy" in overview
        assert "teams" in overview

        await gw.shutdown()

    @pytest.mark.asyncio
    async def test_get_team_events_in_memory(self):
        config = _make_config()
        gw = GatewayApp(config)
        await gw.start()

        events = await gw.get_team_events("alpha")
        assert isinstance(events, list)

        await gw.shutdown()

    @pytest.mark.asyncio
    async def test_get_tokens_no_db(self):
        config = _make_config()
        gw = GatewayApp(config)
        await gw.start()

        tokens = await gw.get_tokens()
        assert tokens == []

        await gw.shutdown()

    @pytest.mark.asyncio
    async def test_get_tokens_summary_no_db(self):
        config = _make_config()
        gw = GatewayApp(config)
        await gw.start()

        summary = await gw.get_tokens_summary()
        assert summary["total_tokens"] == 0

        await gw.shutdown()

    @pytest.mark.asyncio
    async def test_kill_switch_activate_deactivate(self):
        config = _make_config()
        gw = GatewayApp(config)
        await gw.start()

        result = gw.toggle_kill_switch("activate")
        assert result["status"] == "activated"
        assert gw.registry.global_kill_switch is True

        result = gw.toggle_kill_switch("deactivate")
        assert result["status"] == "deactivated"
        assert gw.registry.global_kill_switch is False

        await gw.shutdown()

    @pytest.mark.asyncio
    async def test_kill_switch_per_team(self):
        config = _make_config()
        gw = GatewayApp(config)
        await gw.start()

        gw.registry.get_or_create("alpha")
        result = gw.toggle_kill_switch("activate", "alpha")
        assert result["status"] == "activated"
        assert result["target"] == "alpha"

        await gw.shutdown()

    @pytest.mark.asyncio
    async def test_kill_switch_unknown_action(self):
        config = _make_config()
        gw = GatewayApp(config)
        await gw.start()

        result = gw.toggle_kill_switch("unknown")
        assert result["status"] == "error"

        await gw.shutdown()
