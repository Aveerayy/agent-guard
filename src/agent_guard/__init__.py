"""
Agent Guard — Simple, powerful governance for AI agents.

    from agent_guard import Guard, Policy, AgentIdentity

    guard = Guard()
    guard.add_policy(Policy.from_yaml("policy.yaml"))

    result = guard.check("web_search", agent_id="researcher-1")
    if result.allowed:
        # proceed
        ...
"""

from agent_guard.audit.logger import AuditEvent, AuditLog
from agent_guard.compliance.attestation import GovernanceAttestation, GovernanceVerifier
from agent_guard.compliance.integrity import IntegrityVerifier
from agent_guard.core.actions import Action, ActionType
from agent_guard.core.engine import Guard
from agent_guard.core.policy import Effect, Policy, PolicyDecision
from agent_guard.filters.output_filter import FilterAction, FilterResult, OutputFilter
from agent_guard.identity.agent_id import AgentIdentity
from agent_guard.identity.trust import TrustEngine, TrustScore
from agent_guard.mcp.gateway import MCPGateway
from agent_guard.mcp.injection_detector import InjectionDetector, InjectionResult
from agent_guard.mcp.scanner import MCPScanner, ScanResult, ThreatFinding
from agent_guard.mesh.network import AgentMesh
from agent_guard.observability.hooks import GuardEvent, ObservabilityBus
from agent_guard.policies.rate_limit import RateLimiter
from agent_guard.reliability.circuit_breaker import CircuitBreaker
from agent_guard.reliability.slo import SLO
from agent_guard.sandbox.executor import PermissionLevel, Sandbox
from agent_guard.tokens.inventory import (
    RiskLevel,
    TokenInventory,
    TokenRecord,
    TokenStatus,
)
from agent_guard.tokens.policy import TokenPolicy
from agent_guard.tokens.risk import RiskScorer
from agent_guard.tokens.scanner import TokenScanner

__version__ = "0.2.0"

__all__ = [
    "Guard",
    "Policy",
    "PolicyDecision",
    "Effect",
    "Action",
    "ActionType",
    "AgentIdentity",
    "TrustScore",
    "TrustEngine",
    "Sandbox",
    "PermissionLevel",
    "AuditLog",
    "AuditEvent",
    "AgentMesh",
    "CircuitBreaker",
    "SLO",
    "MCPScanner",
    "MCPGateway",
    "ScanResult",
    "ThreatFinding",
    "InjectionDetector",
    "InjectionResult",
    "OutputFilter",
    "FilterResult",
    "FilterAction",
    "GovernanceVerifier",
    "GovernanceAttestation",
    "IntegrityVerifier",
    "ObservabilityBus",
    "GuardEvent",
    "RateLimiter",
    "TokenInventory",
    "TokenRecord",
    "TokenScanner",
    "TokenPolicy",
    "RiskScorer",
    "RiskLevel",
    "TokenStatus",
]
