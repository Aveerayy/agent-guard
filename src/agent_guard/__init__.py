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

from agent_guard.core.engine import Guard
from agent_guard.core.policy import Policy, PolicyDecision, Effect
from agent_guard.core.actions import Action, ActionType
from agent_guard.identity.agent_id import AgentIdentity
from agent_guard.identity.trust import TrustScore, TrustEngine
from agent_guard.sandbox.executor import Sandbox, PermissionLevel
from agent_guard.audit.logger import AuditLog, AuditEvent
from agent_guard.mesh.network import AgentMesh
from agent_guard.reliability.circuit_breaker import CircuitBreaker
from agent_guard.reliability.slo import SLO
from agent_guard.mcp.scanner import MCPScanner, ScanResult, ThreatFinding
from agent_guard.mcp.gateway import MCPGateway
from agent_guard.mcp.injection_detector import InjectionDetector, InjectionResult
from agent_guard.filters.output_filter import OutputFilter, FilterResult, FilterAction
from agent_guard.compliance.attestation import GovernanceVerifier, GovernanceAttestation
from agent_guard.compliance.integrity import IntegrityVerifier
from agent_guard.observability.hooks import ObservabilityBus, GuardEvent
from agent_guard.policies.rate_limit import RateLimiter

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
]
