"""FastAPI application — Streamable HTTP MCP endpoint, dashboard API, and session management.

This is the main entry point for the Central MCP Gateway Server. It:
- Accepts MCP JSON-RPC 2.0 requests at ``POST /mcp``
- Serves an SSE stream at ``GET /mcp`` for server-initiated messages
- Exposes org-wide dashboard and admin APIs under ``/api/``
- Manages sessions via ``Mcp-Session-Id`` headers
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from agent_guard.server.auth import TeamAuthenticator
from agent_guard.server.config import GatewayServerConfig, load_config
from agent_guard.server.proxy import MCPProxy
from agent_guard.server.store import (
    init_db,
    query_audit_events,
    query_gateway_stats,
    query_token_records,
)
from agent_guard.server.teams import TeamRegistry

logger = logging.getLogger(__name__)


class GatewayApp:
    """Encapsulates the gateway state and request handling.

    Can be used standalone or mounted into a FastAPI app via
    :func:`create_app`.
    """

    def __init__(self, config: GatewayServerConfig, *, db_pool: Any = None) -> None:
        self.config = config
        self.db_pool = db_pool
        self.authenticator = TeamAuthenticator(config)
        self.registry = TeamRegistry(config, db_pool=db_pool)
        self.proxy = MCPProxy(config, db_pool=db_pool)
        self._sessions: dict[str, dict[str, Any]] = {}

    async def start(self) -> None:
        """Initialize connections and database."""
        if self.db_pool:
            await init_db(self.db_pool)
        await self.proxy.start()

    async def shutdown(self) -> None:
        await self.proxy.shutdown()

    def _get_or_create_session(self, session_id: str | None, team_id: str) -> str:
        if session_id and session_id in self._sessions:
            return session_id
        new_id = session_id or str(uuid.uuid4())
        self._sessions[new_id] = {"team_id": team_id, "created": True}
        return new_id

    async def handle_mcp_request(
        self,
        body: dict[str, Any],
        authorization: str = "",
        session_id: str | None = None,
    ) -> tuple[dict[str, Any], str, int]:
        """Process a single MCP JSON-RPC 2.0 request.

        Returns ``(response_body, session_id, http_status)``.
        """
        auth = self.authenticator.authenticate(authorization)
        if not auth.authenticated:
            return (
                _jsonrpc_error(body.get("id"), -32000, auth.reason),
                "",
                401,
            )

        team_ctx = self.registry.get_or_create(auth.team_id)
        sid = self._get_or_create_session(session_id, auth.team_id)

        method = body.get("method", "")
        params = body.get("params", {})
        req_id = body.get("id")

        if method == "initialize":
            result = {
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {
                    "name": "agent-guard-gateway",
                    "version": "0.3.0",
                },
            }
            return _jsonrpc_result(req_id, result), sid, 200

        if method == "tools/list":
            tools = self.proxy.list_tools(team_ctx)
            result = {"tools": tools}
            return _jsonrpc_result(req_id, result), sid, 200

        if method == "tools/call":
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})
            agent_id = params.get("_meta", {}).get("agent_id", "default")

            call_result = await self.proxy.call_tool(team_ctx, tool_name, arguments, agent_id)

            if "error" in call_result and not call_result.get("allowed", True):
                result = {
                    "content": [{"type": "text", "text": call_result["error"]}],
                    "isError": True,
                }
            else:
                result = {
                    "content": [{"type": "text", "text": json.dumps(call_result, default=str)}],
                }
            return _jsonrpc_result(req_id, result), sid, 200

        if method == "notifications/initialized":
            return {}, sid, 204

        return (
            _jsonrpc_error(req_id, -32601, f"Method not found: {method}"),
            sid,
            200,
        )

    async def get_overview(self) -> dict[str, Any]:
        """Org-wide dashboard data."""
        data: dict[str, Any] = {
            "proxy": self.proxy.stats(),
            "teams": self.registry.stats(),
        }
        if self.db_pool:
            data["gateway_calls"] = await query_gateway_stats(self.db_pool)
        return data

    async def get_team_events(self, team_id: str, limit: int = 100) -> list[dict[str, Any]]:
        if self.db_pool:
            return await query_audit_events(self.db_pool, team_id=team_id, limit=limit)
        ctx = self.registry.get_or_create(team_id)
        return ctx.audit_log.export_dict()

    async def get_tokens(self, team_id: str | None = None) -> list[dict[str, Any]]:
        if self.db_pool:
            return await query_token_records(self.db_pool, team_id=team_id)
        return []

    async def get_tokens_summary(self) -> dict[str, Any]:
        if self.db_pool:
            records = await query_token_records(self.db_pool)
            return {
                "total_tokens": len(records),
                "teams_with_tokens": len({r.get("team_id", "") for r in records}),
            }
        return {"total_tokens": 0}

    def toggle_kill_switch(self, action: str, team_id: str | None = None) -> dict[str, str]:
        if action == "activate":
            self.registry.activate_kill_switch(team_id)
            target = team_id or "global"
            return {"status": "activated", "target": target}
        elif action == "deactivate":
            self.registry.deactivate_kill_switch(team_id)
            target = team_id or "global"
            return {"status": "deactivated", "target": target}
        return {"status": "error", "message": f"Unknown action: {action}"}


def create_app(config: GatewayServerConfig, *, db_pool: Any = None) -> Any:
    """Create and return a FastAPI application for the gateway.

    Requires ``fastapi`` to be installed (part of the ``server`` extras).
    """
    from fastapi import FastAPI, Header, Query, Request
    from fastapi.responses import JSONResponse

    gateway = GatewayApp(config, db_pool=db_pool)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
        await gateway.start()
        yield
        await gateway.shutdown()

    app = FastAPI(
        title="Agent Guard Central Gateway",
        version="0.2.0",
        lifespan=lifespan,
    )

    @app.post("/mcp")
    async def mcp_endpoint(
        request: Request,
        authorization: str = Header(default=""),
        mcp_session_id: str | None = Header(default=None, alias="Mcp-Session-Id"),
    ) -> JSONResponse:
        body = await request.json()
        result, sid, status = await gateway.handle_mcp_request(body, authorization, mcp_session_id)
        if status == 204:
            return JSONResponse(content={}, status_code=204)
        headers = {"Mcp-Session-Id": sid} if sid else {}
        return JSONResponse(content=result, status_code=status, headers=headers)

    @app.get("/api/overview")
    async def api_overview() -> JSONResponse:
        data = await gateway.get_overview()
        return JSONResponse(content=data)

    @app.get("/api/teams")
    async def api_teams() -> JSONResponse:
        return JSONResponse(content=gateway.registry.stats())

    @app.get("/api/teams/{team_id}/events")
    async def api_team_events(team_id: str, limit: int = Query(default=100)) -> JSONResponse:
        events = await gateway.get_team_events(team_id, limit)
        return JSONResponse(content=events)

    @app.get("/api/tokens")
    async def api_tokens(
        team_id: str | None = Query(default=None),
    ) -> JSONResponse:
        tokens = await gateway.get_tokens(team_id)
        return JSONResponse(content=tokens)

    @app.get("/api/tokens/summary")
    async def api_tokens_summary() -> JSONResponse:
        data = await gateway.get_tokens_summary()
        return JSONResponse(content=data)

    @app.post("/api/kill-switch/{action}")
    async def api_kill_switch(
        action: str,
        team_id: str | None = Query(default=None),
    ) -> JSONResponse:
        result = gateway.toggle_kill_switch(action, team_id)
        return JSONResponse(content=result)

    @app.get("/health")
    async def health() -> JSONResponse:
        return JSONResponse(
            content={
                "status": "ok",
                "upstreams": gateway.proxy.upstream_health(),
                "global_kill_switch": gateway.registry.global_kill_switch,
            }
        )

    return app


def _jsonrpc_result(req_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _jsonrpc_error(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def run_server(config_path: str, host: str | None = None, port: int | None = None) -> None:
    """Start the gateway server (blocking). Called from CLI."""
    import asyncio

    config = load_config(config_path)
    if host:
        config.server.host = host
    if port:
        config.server.port = port

    async def _run() -> None:
        db_pool = None
        if config.database.url:
            try:
                import asyncpg

                db_pool = await asyncpg.create_pool(
                    config.database.url,
                    min_size=config.database.min_connections,
                    max_size=config.database.max_connections,
                )
            except Exception:
                logger.warning(
                    "Could not connect to PostgreSQL at %s; running without persistence",
                    config.database.url,
                    exc_info=True,
                )

        app = create_app(config, db_pool=db_pool)

        import uvicorn

        uv_config = uvicorn.Config(
            app,
            host=config.server.host,
            port=config.server.port,
            log_level="info",
        )
        server = uvicorn.Server(uv_config)
        await server.serve()

    asyncio.run(_run())
