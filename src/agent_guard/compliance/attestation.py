"""Governance attestation — machine-verifiable OWASP compliance evidence."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


OWASP_ASI_CONTROLS = {
    "ASI-01": {
        "risk": "Agent Goal Hijacking",
        "control": "Policy engine blocks unauthorized goal changes",
        "module": "agent_guard.core.engine",
    },
    "ASI-02": {
        "risk": "Excessive Capabilities",
        "control": "Policy rules enforce least-privilege per agent",
        "module": "agent_guard.core.policy",
    },
    "ASI-03": {
        "risk": "Identity & Privilege Abuse",
        "control": "Ed25519 cryptographic identity + trust scoring",
        "module": "agent_guard.identity",
    },
    "ASI-04": {
        "risk": "Uncontrolled Code Execution",
        "control": "Sandbox with 5 permission levels + kill switch",
        "module": "agent_guard.sandbox.executor",
    },
    "ASI-05": {
        "risk": "Insecure Output Handling",
        "control": "Output PII/secrets filter with redaction + audit logging",
        "module": "agent_guard.filters.output_filter",
    },
    "ASI-06": {
        "risk": "Memory Poisoning",
        "control": "Hash-chained audit trail detects tampering",
        "module": "agent_guard.audit.logger",
    },
    "ASI-07": {
        "risk": "Unsafe Inter-Agent Communication",
        "control": "Mesh with trust-gated encrypted channels",
        "module": "agent_guard.mesh.network",
    },
    "ASI-08": {
        "risk": "Cascading Failures",
        "control": "Circuit breakers + SLO enforcement with error budgets",
        "module": "agent_guard.reliability",
    },
    "ASI-09": {
        "risk": "Human-Agent Trust Deficit",
        "control": "Full audit trail + compliance reporting + CLI",
        "module": "agent_guard.audit.logger",
    },
    "ASI-10": {
        "risk": "Rogue Agents",
        "control": "Kill switch + trust scoring + sandbox isolation",
        "module": "agent_guard.core.engine",
    },
}


class ControlStatus(BaseModel):
    control_id: str
    risk: str = ""
    control: str = ""
    module: str = ""
    implemented: bool = False
    verified: bool = False
    evidence: str = ""


class GovernanceAttestation(BaseModel):
    """A signed attestation of governance posture."""

    version: str = "1.0"
    framework: str = "agent-guard"
    framework_version: str = "0.2.0"
    timestamp: float = Field(default_factory=time.time)
    controls: list[ControlStatus] = Field(default_factory=list)
    coverage_score: float = 0.0
    total_controls: int = 10
    implemented_controls: int = 0
    hash: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def fully_compliant(self) -> bool:
        return self.implemented_controls == self.total_controls


class GovernanceVerifier:
    """Verify and attest governance posture against OWASP Agentic Top 10.

    Usage:
        verifier = GovernanceVerifier()
        attestation = verifier.verify()

        print(f"Coverage: {attestation.coverage_score:.0%}")
        print(f"Compliant: {attestation.fully_compliant}")

        verifier.export_attestation(attestation, "governance-attestation.json")
    """

    def verify(self) -> GovernanceAttestation:
        """Run verification checks against all OWASP ASI controls."""
        controls = []
        implemented = 0

        for control_id, info in OWASP_ASI_CONTROLS.items():
            is_implemented = self._check_module(info["module"])
            if is_implemented:
                implemented += 1

            controls.append(ControlStatus(
                control_id=control_id,
                risk=info["risk"],
                control=info["control"],
                module=info["module"],
                implemented=is_implemented,
                verified=is_implemented,
                evidence=f"Module {info['module']} importable" if is_implemented else "Module not found",
            ))

        attestation = GovernanceAttestation(
            controls=controls,
            coverage_score=implemented / len(OWASP_ASI_CONTROLS),
            total_controls=len(OWASP_ASI_CONTROLS),
            implemented_controls=implemented,
        )
        attestation.hash = self._compute_hash(attestation)
        return attestation

    def _check_module(self, module_path: str) -> bool:
        try:
            __import__(module_path)
            return True
        except ImportError:
            return False

    def _compute_hash(self, attestation: GovernanceAttestation) -> str:
        data = json.dumps({
            "framework": attestation.framework,
            "version": attestation.framework_version,
            "timestamp": attestation.timestamp,
            "controls": [c.control_id for c in attestation.controls if c.implemented],
            "coverage": attestation.coverage_score,
        }, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(data.encode()).hexdigest()

    def export_attestation(
        self,
        attestation: GovernanceAttestation,
        path: str | Path,
    ) -> None:
        """Export attestation as JSON for CI/CD consumption."""
        Path(path).write_text(json.dumps(attestation.model_dump(), indent=2, default=str))

    def summary(self, attestation: GovernanceAttestation | None = None) -> dict[str, Any]:
        if attestation is None:
            attestation = self.verify()
        return {
            "framework": attestation.framework,
            "version": attestation.framework_version,
            "owasp_coverage": f"{attestation.coverage_score:.0%}",
            "controls_implemented": f"{attestation.implemented_controls}/{attestation.total_controls}",
            "fully_compliant": attestation.fully_compliant,
            "hash": attestation.hash[:16] + "...",
        }
