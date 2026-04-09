"""MCP Gateway — runtime governance proxy for MCP tool calls.

Sits between agents and MCP servers, enforcing policy on every tool call.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from pydantic import BaseModel, Field

from agent_guard.audit.logger import AuditLog
from agent_guard.core.actions import ActionType
from agent_guard.core.engine import Guard
from agent_guard.filters.output_filter import FilterAction, FilterResult, OutputFilter
from agent_guard.mcp.injection_detector import InjectionDetector, InjectionResult
from agent_guard.mcp.scanner import MCPScanner, ScanResult


class GatewayConfig(BaseModel):
    """Configuration for the MCP gateway."""

    allowed_tools: list[str] = Field(
        default_factory=list, description="Empty = all allowed (subject to policy)"
    )
    denied_tools: list[str] = Field(default_factory=list)
    require_approval_for: list[str] = Field(
        default_factory=list,
        description="Tools requiring human approval before execution",
    )
    max_calls_per_minute: int = 60
    scan_on_register: bool = True
    detect_injection: bool = True
    filter_outputs: bool = True
    output_filter_action: FilterAction = FilterAction.REDACT


class ToolCallRecord(BaseModel):
    tool_name: str
    agent_id: str
    allowed: bool
    timestamp: float = Field(default_factory=time.time)
    parameters: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""
    injection_result: InjectionResult | None = None
    output_filter_result: FilterResult | None = None


class MCPGateway:
    """Runtime governance proxy for MCP tool calls.

    Usage:
        gateway = MCPGateway(guard)

        # Register tools (auto-scans for threats)
        gateway.register_tools([tool1, tool2])

        # Gate every tool call
        result = gateway.authorize("web_search", agent_id="agent-1", params={"query": "AI"})
        if result.allowed:
            execute_tool(...)
    """

    def __init__(
        self,
        guard: Guard,
        *,
        config: GatewayConfig | None = None,
        audit_log: AuditLog | None = None,
        scanner: MCPScanner | None = None,
        injection_detector: InjectionDetector | None = None,
        output_filter: OutputFilter | None = None,
    ):
        self._guard = guard
        self._config = config or GatewayConfig()
        self._audit = audit_log or AuditLog()
        self._scanner = scanner or MCPScanner()
        self._injection_detector = injection_detector or InjectionDetector()
        self._output_filter = output_filter or OutputFilter(
            action=self._config.output_filter_action
        )
        self._registered_tools: dict[str, dict[str, Any]] = {}
        self._scan_results: dict[str, ScanResult] = {}
        self._call_log: list[ToolCallRecord] = []
        self._rate_counters: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def register_tools(self, tools: list[dict[str, Any]]) -> ScanResult | None:
        """Register MCP tools with the gateway. Scans for threats if enabled."""
        scan_result = None
        if self._config.scan_on_register:
            scan_result = self._scanner.scan_tools(tools)

        with self._lock:
            for tool in tools:
                name = tool.get("name", "")
                self._registered_tools[name] = tool
            if scan_result:
                for tool in tools:
                    self._scan_results[tool.get("name", "")] = scan_result

        return scan_result

    def authorize(
        self,
        tool_name: str,
        *,
        agent_id: str = "default",
        params: dict[str, Any] | None = None,
    ) -> ToolCallRecord:
        """Authorize an MCP tool call through the full governance stack."""
        params = params or {}

        if self._config.denied_tools and tool_name in self._config.denied_tools:
            return self._record(tool_name, agent_id, False, params, "Tool is explicitly denied")

        if self._config.allowed_tools and tool_name not in self._config.allowed_tools:
            return self._record(tool_name, agent_id, False, params, "Tool not in allowed list")

        if self._config.require_approval_for and tool_name in self._config.require_approval_for:
            return self._record(
                tool_name,
                agent_id,
                False,
                params,
                "Tool requires human approval (not yet approved)",
            )

        if not self._check_rate_limit(agent_id):
            return self._record(
                tool_name,
                agent_id,
                False,
                params,
                f"Rate limit exceeded ({self._config.max_calls_per_minute}/min)",
            )

        if self._config.detect_injection and params:
            injection = self._injection_detector.scan(tool_name, params, agent_id=agent_id)
            if injection.blocked:
                record = self._record(
                    tool_name,
                    agent_id,
                    False,
                    params,
                    f"Injection detected (score={injection.risk_score:.0f}): "
                    + "; ".join(f.description for f in injection.findings[:3]),
                )
                record.injection_result = injection
                return record

        decision = self._guard.evaluate(
            tool_name, agent_id=agent_id, action_type=ActionType.TOOL_CALL, parameters=params
        )
        self._audit.log_decision(decision)

        return self._record(tool_name, agent_id, decision.allowed, params, decision.reason)

    def filter_output(self, text: str) -> FilterResult:
        """Filter tool output for PII and secrets. Call after tool execution."""
        return self._output_filter.scan(text)

    def filter_output_dict(self, data: dict[str, Any]) -> FilterResult:
        """Filter structured tool output for PII and secrets."""
        return self._output_filter.scan_dict(data)

    def _check_rate_limit(self, agent_id: str) -> bool:
        now = time.time()
        with self._lock:
            calls = self._rate_counters.get(agent_id, [])
            calls = [t for t in calls if now - t < 60]
            if len(calls) >= self._config.max_calls_per_minute:
                self._rate_counters[agent_id] = calls
                return False
            calls.append(now)
            self._rate_counters[agent_id] = calls
            return True

    def _record(
        self,
        tool_name: str,
        agent_id: str,
        allowed: bool,
        params: dict[str, Any],
        reason: str,
    ) -> ToolCallRecord:
        record = ToolCallRecord(
            tool_name=tool_name,
            agent_id=agent_id,
            allowed=allowed,
            parameters=params,
            reason=reason,
        )
        with self._lock:
            self._call_log.append(record)
        return record

    @property
    def registered_tools(self) -> list[str]:
        return list(self._registered_tools.keys())

    @property
    def call_log(self) -> list[ToolCallRecord]:
        return list(self._call_log)

    def stats(self) -> dict[str, Any]:
        total = len(self._call_log)
        allowed = sum(1 for r in self._call_log if r.allowed)
        injections_blocked = sum(
            1 for r in self._call_log if r.injection_result and r.injection_result.blocked
        )
        return {
            "registered_tools": len(self._registered_tools),
            "total_calls": total,
            "allowed": allowed,
            "denied": total - allowed,
            "injections_blocked": injections_blocked,
            "scan_findings": sum(
                r.critical_count + r.high_count for r in self._scan_results.values()
            ),
        }
