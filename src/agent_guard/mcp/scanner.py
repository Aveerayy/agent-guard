"""MCP Security Scanner — detect tool poisoning, typosquatting, and hidden instructions.

Scans MCP (Model Context Protocol) tool definitions for common attack patterns
that can compromise agent security.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ThreatType(str, Enum):
    """Categories of MCP tool threats."""

    TOOL_POISONING = "tool_poisoning"
    TYPOSQUATTING = "typosquatting"
    HIDDEN_INSTRUCTIONS = "hidden_instructions"
    SCHEMA_ABUSE = "schema_abuse"
    INJECTION = "injection"
    RUG_PULL = "rug_pull"
    CROSS_SERVER = "cross_server"
    PRIVILEGE_ESCALATION = "privilege_escalation"


class ThreatSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThreatFinding(BaseModel):
    """A single security finding from the MCP scanner."""

    threat_type: ThreatType
    severity: ThreatSeverity
    tool_name: str = ""
    description: str
    evidence: str = ""
    recommendation: str = ""


class ScanResult(BaseModel):
    """Aggregate result of scanning MCP tool definitions."""

    tools_scanned: int = 0
    findings: list[ThreatFinding] = Field(default_factory=list)
    risk_score: float = 0.0  # 0-100
    safe: bool = True

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == ThreatSeverity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == ThreatSeverity.HIGH)

    def summary(self) -> dict[str, Any]:
        return {
            "tools_scanned": self.tools_scanned,
            "total_findings": len(self.findings),
            "critical": self.critical_count,
            "high": self.high_count,
            "risk_score": self.risk_score,
            "safe": self.safe,
        }


SUSPICIOUS_PATTERNS = [
    (
        r"ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions",
        ThreatType.INJECTION,
        ThreatSeverity.CRITICAL,
        "Prompt injection attempt — tool description tries to override prior instructions",
    ),
    (
        r"you\s+(?:are|must|should|will)\s+now",
        ThreatType.INJECTION,
        ThreatSeverity.HIGH,
        "Role hijacking — tool description attempts to redefine agent behavior",
    ),
    (
        r"<\s*(?:script|img|iframe|object|embed|svg)\b",
        ThreatType.HIDDEN_INSTRUCTIONS,
        ThreatSeverity.HIGH,
        "HTML/script injection in tool definition",
    ),
    (
        r"[\u200b-\u200f\u2028-\u202f\u2060-\u206f\ufeff]",
        ThreatType.HIDDEN_INSTRUCTIONS,
        ThreatSeverity.HIGH,
        "Unicode zero-width or invisible characters hiding instructions",
    ),
    (
        r"(?:system|admin|root|sudo)\s*(?:access|privilege|permission|mode)",
        ThreatType.PRIVILEGE_ESCALATION,
        ThreatSeverity.HIGH,
        "Tool description references privilege escalation",
    ),
    (
        r"(?:exec|eval|compile|subprocess|os\.system|popen)\s*\(",
        ThreatType.TOOL_POISONING,
        ThreatSeverity.CRITICAL,
        "Code execution pattern in tool definition",
    ),
    (
        r"(?:rm\s+-rf|del\s+/[sq]|format\s+[a-z]:|mkfs)",
        ThreatType.TOOL_POISONING,
        ThreatSeverity.CRITICAL,
        "Destructive command pattern in tool definition",
    ),
    (
        r"(?:password|secret|token|api[_-]?key|credential)s?\s*[:=]",
        ThreatType.TOOL_POISONING,
        ThreatSeverity.HIGH,
        "Hardcoded secret or credential in tool definition",
    ),
    (
        r"(?:curl|wget|fetch)\s+https?://",
        ThreatType.TOOL_POISONING,
        ThreatSeverity.MEDIUM,
        "External URL fetch in tool definition",
    ),
    (
        r"(?:base64|atob|btoa)\s*(?:\(|\.decode)",
        ThreatType.HIDDEN_INSTRUCTIONS,
        ThreatSeverity.MEDIUM,
        "Base64 encoding/decoding — may hide malicious payloads",
    ),
]

KNOWN_TOOL_NAMES: set[str] = {
    "web_search",
    "file_read",
    "file_write",
    "code_exec",
    "shell_exec",
    "database_query",
    "http_request",
    "send_email",
    "browser",
    "calculator",
    "python_repl",
    "retrieval",
    "dalle",
}

TYPOSQUAT_PAIRS = [
    ("l", "1"),
    ("o", "0"),
    ("i", "1"),
    ("s", "5"),
    ("e", "3"),
    ("rn", "m"),
    ("vv", "w"),
    ("cl", "d"),
    ("nn", "m"),
]


class MCPScanner:
    """Scan MCP tool definitions for security threats.

    Usage:
        scanner = MCPScanner()

        # Scan a single tool
        result = scanner.scan_tool({
            "name": "web_search",
            "description": "Search the web for information",
            "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}
        })

        # Scan multiple tools
        result = scanner.scan_tools([tool1, tool2, tool3])

        if not result.safe:
            for finding in result.findings:
                print(f"[{finding.severity}] {finding.description}")
    """

    def __init__(
        self,
        *,
        custom_patterns: list[tuple[str, ThreatType, ThreatSeverity, str]] | None = None,
        known_tools: set[str] | None = None,
    ):
        self._patterns = list(SUSPICIOUS_PATTERNS)
        if custom_patterns:
            self._patterns.extend(custom_patterns)
        self._known_tools = known_tools or KNOWN_TOOL_NAMES
        self._compiled = [(re.compile(p, re.IGNORECASE), t, s, d) for p, t, s, d in self._patterns]

    def scan_tool(self, tool: dict[str, Any]) -> ScanResult:
        """Scan a single MCP tool definition."""
        return self.scan_tools([tool])

    def scan_tools(self, tools: list[dict[str, Any]]) -> ScanResult:
        """Scan a list of MCP tool definitions for security threats."""
        findings: list[ThreatFinding] = []

        for tool in tools:
            name = tool.get("name", "")
            description = tool.get("description", "")
            schema = tool.get("inputSchema", {})
            text_blob = f"{name} {description} {_flatten_schema(schema)}"

            findings.extend(self._check_patterns(name, text_blob))
            findings.extend(self._check_typosquatting(name))
            findings.extend(self._check_schema(name, schema))
            findings.extend(self._check_description_length(name, description))
            findings.extend(self._check_name_collision(name, tools))

        severity_weights = {
            ThreatSeverity.CRITICAL: 25,
            ThreatSeverity.HIGH: 15,
            ThreatSeverity.MEDIUM: 8,
            ThreatSeverity.LOW: 3,
            ThreatSeverity.INFO: 1,
        }
        risk_score = min(100.0, sum(severity_weights.get(f.severity, 0) for f in findings))

        return ScanResult(
            tools_scanned=len(tools),
            findings=findings,
            risk_score=risk_score,
            safe=len(findings) == 0,
        )

    def _check_patterns(self, tool_name: str, text: str) -> list[ThreatFinding]:
        findings = []
        for regex, threat_type, severity, description in self._compiled:
            match = regex.search(text)
            if match:
                findings.append(
                    ThreatFinding(
                        threat_type=threat_type,
                        severity=severity,
                        tool_name=tool_name,
                        description=description,
                        evidence=match.group(0)[:200],
                        recommendation=_recommendation_for(threat_type),
                    )
                )
        return findings

    def _check_typosquatting(self, name: str) -> list[ThreatFinding]:
        findings = []
        name_lower = name.lower().replace("-", "_")
        for known in self._known_tools:
            if name_lower == known:
                continue
            dist = _edit_distance(name_lower, known)
            if 0 < dist <= 2:
                findings.append(
                    ThreatFinding(
                        threat_type=ThreatType.TYPOSQUATTING,
                        severity=ThreatSeverity.HIGH,
                        tool_name=name,
                        description=(
                            f"Tool name '{name}' is suspiciously similar to known tool '{known}' "
                            f"(edit distance: {dist})"
                        ),
                        evidence=f"{name} ≈ {known}",
                        recommendation=(
                            "Verify this is the intended tool and not a malicious impersonator"
                        ),
                    )
                )
        return findings

    def _check_schema(self, tool_name: str, schema: dict[str, Any]) -> list[ThreatFinding]:
        findings = []
        props = schema.get("properties", {})

        for prop_name, prop_def in props.items():
            if isinstance(prop_def, dict):
                desc = prop_def.get("description", "")
                if len(desc) > 500:
                    findings.append(
                        ThreatFinding(
                            threat_type=ThreatType.SCHEMA_ABUSE,
                            severity=ThreatSeverity.MEDIUM,
                            tool_name=tool_name,
                            description=f"Unusually long property description for '{prop_name}' "
                            f"({len(desc)} chars) — may contain hidden instructions",
                            evidence=desc[:100] + "...",
                            recommendation="Review property descriptions for embedded instructions",
                        )
                    )

        if len(props) > 20:
            findings.append(
                ThreatFinding(
                    threat_type=ThreatType.SCHEMA_ABUSE,
                    severity=ThreatSeverity.MEDIUM,
                    tool_name=tool_name,
                    description=(
                        f"Excessive parameter count ({len(props)}) — may indicate schema abuse"
                    ),
                    recommendation="Reduce parameter count or split into multiple tools",
                )
            )

        return findings

    def _check_description_length(self, tool_name: str, desc: str) -> list[ThreatFinding]:
        if len(desc) > 2000:
            return [
                ThreatFinding(
                    threat_type=ThreatType.HIDDEN_INSTRUCTIONS,
                    severity=ThreatSeverity.MEDIUM,
                    tool_name=tool_name,
                    description=f"Unusually long tool description ({len(desc)} chars) — "
                    "may contain hidden instructions",
                    evidence=desc[:100] + "...",
                    recommendation="Review description for embedded instructions or payloads",
                )
            ]
        return []

    def _check_name_collision(
        self, name: str, all_tools: list[dict[str, Any]]
    ) -> list[ThreatFinding]:
        names = [t.get("name", "") for t in all_tools]
        count = sum(1 for n in names if n == name)
        if count > 1:
            return [
                ThreatFinding(
                    threat_type=ThreatType.CROSS_SERVER,
                    severity=ThreatSeverity.HIGH,
                    tool_name=name,
                    description=f"Duplicate tool name '{name}' found {count} times — "
                    "possible cross-server name collision attack",
                    recommendation="Ensure each tool has a unique name; namespace by server",
                )
            ]
        return []


def _flatten_schema(schema: dict[str, Any], depth: int = 0) -> str:
    if depth > 5:
        return ""
    parts = []
    for _key, val in schema.items():
        if isinstance(val, str):
            parts.append(val)
        elif isinstance(val, dict):
            parts.append(_flatten_schema(val, depth + 1))
    return " ".join(parts)


def _edit_distance(a: str, b: str) -> int:
    if len(a) < len(b):
        return _edit_distance(b, a)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(
                min(
                    prev[j + 1] + 1,
                    curr[j] + 1,
                    prev[j] + (0 if ca == cb else 1),
                )
            )
        prev = curr
    return prev[len(b)]


def _recommendation_for(threat_type: ThreatType) -> str:
    recs = {
        ThreatType.TOOL_POISONING: "Remove or quarantine this tool; audit its source",
        ThreatType.TYPOSQUATTING: (
            "Verify this is the intended tool and not a malicious impersonator"
        ),
        ThreatType.HIDDEN_INSTRUCTIONS: "Strip hidden characters and review full description",
        ThreatType.SCHEMA_ABUSE: "Review and simplify the tool schema",
        ThreatType.INJECTION: "Block this tool — it contains injection attempts",
        ThreatType.RUG_PULL: "Pin tool versions and verify hashes on update",
        ThreatType.CROSS_SERVER: "Namespace tool names by server to prevent collisions",
        ThreatType.PRIVILEGE_ESCALATION: "Restrict tool permissions to least-privilege",
    }
    return recs.get(threat_type, "Review and remediate this finding")
