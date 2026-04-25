"""Tests for agent_guard.server.proxy."""

from __future__ import annotations

import pytest

from agent_guard.server.config import (
    GatewayServerConfig,
    TeamConfig,
    UpstreamConfig,
)
from agent_guard.server.proxy import MCPProxy, UpstreamConnection
from agent_guard.server.teams import TeamRegistry


def _make_config() -> GatewayServerConfig:
    return GatewayServerConfig(
        upstreams={
            "mock-http": UpstreamConfig(
                transport="http",
                url="http://localhost:19999/mcp",
            ),
        },
        teams={
            "alpha": TeamConfig(
                token="tok",
                policy="standard",
                allowed_upstreams=["mock-http"],
            ),
        },
    )


class TestUpstreamConnection:
    def test_init(self):
        cfg = UpstreamConfig(transport="http", url="https://example.com/mcp")
        conn = UpstreamConnection("test", cfg)
        assert conn.name == "test"
        assert not conn.healthy
        assert conn.tools == []

    @pytest.mark.asyncio
    async def test_connect_http(self):
        cfg = UpstreamConfig(transport="http", url="https://example.com/mcp")
        conn = UpstreamConnection("test", cfg)
        await conn.connect()
        assert conn.healthy

    @pytest.mark.asyncio
    async def test_connect_unknown_transport(self):
        cfg = UpstreamConfig(transport="grpc", url="grpc://example.com")
        conn = UpstreamConnection("test", cfg)
        await conn.connect()
        assert not conn.healthy

    @pytest.mark.asyncio
    async def test_shutdown(self):
        cfg = UpstreamConfig(transport="http", url="https://example.com/mcp")
        conn = UpstreamConnection("test", cfg)
        await conn.connect()
        await conn.shutdown()
        assert not conn.healthy


class TestMCPProxy:
    @pytest.mark.asyncio
    async def test_start_and_shutdown(self):
        config = _make_config()
        proxy = MCPProxy(config)
        await proxy.start()
        assert "mock-http" in proxy.upstream_names
        health = proxy.upstream_health()
        assert health["mock-http"] is True
        await proxy.shutdown()
        assert len(proxy.upstream_names) == 0

    @pytest.mark.asyncio
    async def test_list_tools_filters_by_team(self):
        config = GatewayServerConfig(
            upstreams={
                "github": UpstreamConfig(transport="http", url="http://gh/mcp"),
                "slack": UpstreamConfig(transport="http", url="http://sl/mcp"),
            },
            teams={
                "alpha": TeamConfig(
                    token="tok",
                    policy="standard",
                    allowed_upstreams=["github"],
                ),
            },
        )
        proxy = MCPProxy(config)
        await proxy.start()

        proxy.register_upstream_tools(
            "github",
            [
                {"name": "create_issue", "description": "Create a GitHub issue"},
            ],
        )
        proxy.register_upstream_tools(
            "slack",
            [
                {"name": "send_message", "description": "Send a Slack message"},
            ],
        )

        registry = TeamRegistry(config)
        ctx = registry.get_or_create("alpha")

        tools = proxy.list_tools(ctx)
        names = [t["name"] for t in tools]
        assert "github/create_issue" in names
        assert "slack/send_message" not in names

        await proxy.shutdown()

    @pytest.mark.asyncio
    async def test_call_tool_unknown_upstream(self):
        config = _make_config()
        proxy = MCPProxy(config)
        await proxy.start()

        registry = TeamRegistry(config)
        ctx = registry.get_or_create("alpha")

        result = await proxy.call_tool(ctx, "nonexistent/tool", {})
        assert "error" in result

        await proxy.shutdown()

    @pytest.mark.asyncio
    async def test_call_tool_unauthorized_upstream(self):
        config = GatewayServerConfig(
            upstreams={
                "github": UpstreamConfig(transport="http", url="http://gh/mcp"),
                "secret": UpstreamConfig(transport="http", url="http://sec/mcp"),
            },
            teams={
                "alpha": TeamConfig(
                    token="tok",
                    policy="standard",
                    allowed_upstreams=["github"],
                ),
            },
        )
        proxy = MCPProxy(config)
        await proxy.start()

        registry = TeamRegistry(config)
        ctx = registry.get_or_create("alpha")

        result = await proxy.call_tool(ctx, "secret/admin_tool", {})
        assert "error" in result
        assert "not authorized" in result["error"]

        await proxy.shutdown()

    @pytest.mark.asyncio
    async def test_call_tool_kill_switch(self):
        config = _make_config()
        proxy = MCPProxy(config)
        await proxy.start()

        registry = TeamRegistry(config)
        ctx = registry.get_or_create("alpha")
        ctx.kill_switch = True

        result = await proxy.call_tool(ctx, "mock-http/some_tool", {})
        assert "error" in result
        assert "Kill switch" in result["error"]

        await proxy.shutdown()

    @pytest.mark.asyncio
    async def test_register_upstream_tools(self):
        config = _make_config()
        proxy = MCPProxy(config)
        await proxy.start()

        proxy.register_upstream_tools(
            "mock-http",
            [
                {"name": "tool_a"},
                {"name": "tool_b"},
            ],
        )

        registry = TeamRegistry(config)
        ctx = registry.get_or_create("alpha")
        tools = proxy.list_tools(ctx)
        assert len(tools) == 2

        await proxy.shutdown()

    def test_stats(self):
        config = _make_config()
        proxy = MCPProxy(config)
        s = proxy.stats()
        assert s["upstreams"] == 0
        assert s["healthy"] == 0
