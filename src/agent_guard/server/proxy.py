"""MCP Proxy — upstream connection pool, tool aggregation, governance-gated forwarding.

Manages connections to upstream MCP servers (stdio subprocesses and HTTP
remotes), aggregates their tool lists, and routes ``tools/call`` requests
through the team's governance stack before forwarding.
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
from typing import Any

from agent_guard.server.config import GatewayServerConfig, UpstreamConfig
from agent_guard.server.store import insert_gateway_call
from agent_guard.server.teams import TeamContext

logger = logging.getLogger(__name__)

SEPARATOR = "/"


class UpstreamConnection:
    """Represents a live connection to one upstream MCP server."""

    __slots__ = ("name", "config", "tools", "_process", "_healthy")

    def __init__(self, name: str, config: UpstreamConfig) -> None:
        self.name = name
        self.config = config
        self.tools: list[dict[str, Any]] = []
        self._process: subprocess.Popen[bytes] | None = None
        self._healthy = False

    @property
    def healthy(self) -> bool:
        return self._healthy

    async def connect(self) -> None:
        """Establish the connection to the upstream."""
        if self.config.transport == "stdio":
            await self._connect_stdio()
        elif self.config.transport == "http":
            self._healthy = True
            logger.info("HTTP upstream '%s' registered: %s", self.name, self.config.url)
        else:
            logger.warning(
                "Unknown transport '%s' for upstream '%s'",
                self.config.transport,
                self.name,
            )

    async def _connect_stdio(self) -> None:
        """Spawn the stdio subprocess and discover tools via initialization."""
        try:
            cmd = [self.config.command, *self.config.args]
            env = {**dict(__import__("os").environ), **self.config.env}
            self._process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
            self._healthy = True
            logger.info("Stdio upstream '%s' started: %s", self.name, " ".join(cmd))
        except FileNotFoundError:
            logger.error("Command not found for upstream '%s': %s", self.name, self.config.command)
            self._healthy = False
        except Exception:
            logger.error("Failed to start upstream '%s'", self.name, exc_info=True)
            self._healthy = False

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Forward a tool call to the upstream and return the result.

        For the initial implementation, this uses a simple JSON-RPC
        message exchange.  A full MCP ClientSession integration
        (via the ``mcp`` SDK) can replace this once the server extras
        are installed.
        """
        if self.config.transport == "http":
            return await self._call_http(tool_name, arguments)
        if self.config.transport == "stdio":
            return await self._call_stdio(tool_name, arguments)
        return {"error": f"Unsupported transport: {self.config.transport}"}

    async def _call_http(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Forward via HTTP POST to the upstream's MCP endpoint."""
        try:
            import httpx

            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": arguments},
            }
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(self.config.url, json=payload)
                data = resp.json()
                return data.get("result", data)
        except Exception as exc:
            logger.error("HTTP call to '%s' failed: %s", self.name, exc)
            return {"error": str(exc)}

    async def _call_stdio(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Forward via stdin/stdout JSON-RPC to the stdio subprocess."""
        if not self._process or not self._process.stdin or not self._process.stdout:
            return {"error": f"Upstream '{self.name}' not connected"}

        import json

        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }
        try:
            msg = json.dumps(payload) + "\n"
            self._process.stdin.write(msg.encode())
            self._process.stdin.flush()

            line = await asyncio.get_event_loop().run_in_executor(
                None, self._process.stdout.readline
            )
            if line:
                data = json.loads(line)
                return data.get("result", data)
            return {"error": "No response from upstream"}
        except Exception as exc:
            logger.error("Stdio call to '%s' failed: %s", self.name, exc)
            return {"error": str(exc)}

    async def shutdown(self) -> None:
        if self._process:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None
        self._healthy = False


class MCPProxy:
    """Central proxy that manages upstream connections and routes governed tool calls.

    Usage::

        proxy = MCPProxy(config)
        await proxy.start()

        # List all tools available to a team
        tools = proxy.list_tools(team_ctx)

        # Execute a governed tool call
        result = await proxy.call_tool(team_ctx, "github/create_issue", {...}, "agent-1")

        await proxy.shutdown()
    """

    def __init__(self, config: GatewayServerConfig, *, db_pool: Any = None) -> None:
        self._config = config
        self._db_pool = db_pool
        self._upstreams: dict[str, UpstreamConnection] = {}

    async def start(self) -> None:
        """Connect to all configured upstream MCP servers."""
        for name, upstream_cfg in self._config.upstreams.items():
            conn = UpstreamConnection(name, upstream_cfg)
            await conn.connect()
            self._upstreams[name] = conn
        logger.info("MCP Proxy started with %d upstreams", len(self._upstreams))

    async def shutdown(self) -> None:
        """Gracefully disconnect from all upstreams."""
        for conn in self._upstreams.values():
            await conn.shutdown()
        self._upstreams.clear()

    def list_tools(self, team_ctx: TeamContext) -> list[dict[str, Any]]:
        """Return aggregated tool list for a team, filtered by allowed upstreams.

        Tool names are prefixed with ``upstream_name/`` to avoid collisions.
        """
        allowed = set(team_ctx.config.allowed_upstreams)
        tools: list[dict[str, Any]] = []

        for name, conn in self._upstreams.items():
            if name not in allowed:
                continue
            if not conn.healthy:
                continue
            for tool in conn.tools:
                prefixed = dict(tool)
                prefixed["name"] = f"{name}{SEPARATOR}{tool.get('name', '')}"
                prefixed["_upstream"] = name
                tools.append(prefixed)

        return tools

    def register_upstream_tools(self, upstream_name: str, tools: list[dict[str, Any]]) -> None:
        """Register discovered tools for an upstream (called after initialization)."""
        conn = self._upstreams.get(upstream_name)
        if conn:
            conn.tools = tools
            logger.info("Registered %d tools for upstream '%s'", len(tools), upstream_name)

    async def call_tool(
        self,
        team_ctx: TeamContext,
        tool_name: str,
        arguments: dict[str, Any],
        agent_id: str = "default",
    ) -> dict[str, Any]:
        """Execute a governed tool call.

        1. Parse upstream from prefixed tool name
        2. Authorize through the team's MCPGateway
        3. Forward to upstream if allowed
        4. Filter output
        5. Persist to database
        """
        upstream_name, _, real_tool = tool_name.partition(SEPARATOR)
        if not real_tool:
            real_tool = upstream_name
            upstream_name = ""

        conn = self._upstreams.get(upstream_name)
        if not conn:
            return {"error": f"Unknown upstream: {upstream_name}"}

        if upstream_name not in team_ctx.config.allowed_upstreams:
            return {"error": f"Team not authorized for upstream: {upstream_name}"}

        if team_ctx.kill_switch:
            return {"error": "Kill switch active for team"}

        auth_result = team_ctx.gateway.authorize(real_tool, agent_id=agent_id, params=arguments)

        if self._db_pool:
            await insert_gateway_call(
                self._db_pool,
                team_id=team_ctx.team_id,
                tool_name=tool_name,
                agent_id=agent_id,
                allowed=auth_result.allowed,
                reason=auth_result.reason,
            )

        if not auth_result.allowed:
            return {
                "error": f"Denied: {auth_result.reason}",
                "allowed": False,
                "tool": tool_name,
            }

        result = await conn.call_tool(real_tool, arguments)

        result_text = str(result)
        filter_result = team_ctx.gateway.filter_output(result_text)
        if filter_result.has_findings:
            result["_filtered"] = True
            result["_findings_count"] = len(filter_result.findings)

        return result

    @property
    def upstream_names(self) -> list[str]:
        return list(self._upstreams.keys())

    def upstream_health(self) -> dict[str, bool]:
        return {name: conn.healthy for name, conn in self._upstreams.items()}

    def stats(self) -> dict[str, Any]:
        return {
            "upstreams": len(self._upstreams),
            "healthy": sum(1 for c in self._upstreams.values() if c.healthy),
            "health": self.upstream_health(),
        }
