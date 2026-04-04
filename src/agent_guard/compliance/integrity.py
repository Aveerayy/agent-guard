"""Integrity verification — detect tampering of governance modules at startup."""

from __future__ import annotations

import hashlib
import importlib
import inspect
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class ModuleHash(BaseModel):
    module: str
    file_path: str = ""
    sha256: str = ""
    verified: bool = False


class IntegrityReport(BaseModel):
    """Report on the integrity of Agent Guard's own governance modules."""

    modules_checked: int = 0
    all_valid: bool = True
    hashes: list[ModuleHash] = Field(default_factory=list)
    baseline_hash: str = ""


GOVERNANCE_MODULES = [
    "agent_guard.core.engine",
    "agent_guard.core.policy",
    "agent_guard.core.actions",
    "agent_guard.identity.agent_id",
    "agent_guard.identity.trust",
    "agent_guard.sandbox.executor",
    "agent_guard.audit.logger",
    "agent_guard.mesh.network",
    "agent_guard.mcp.scanner",
    "agent_guard.mcp.gateway",
]


class IntegrityVerifier:
    """Verify the integrity of Agent Guard's own modules.

    Usage:
        verifier = IntegrityVerifier()

        # Generate a baseline
        baseline = verifier.generate_baseline()

        # Later, verify against it
        report = verifier.verify(baseline)
        assert report.all_valid
    """

    def generate_baseline(self) -> dict[str, str]:
        """Generate SHA-256 hashes of all governance modules."""
        baseline = {}
        for module_name in GOVERNANCE_MODULES:
            try:
                mod = importlib.import_module(module_name)
                source_file = inspect.getfile(mod)
                content = Path(source_file).read_bytes()
                baseline[module_name] = hashlib.sha256(content).hexdigest()
            except (ImportError, TypeError, OSError):
                pass
        return baseline

    def verify(self, baseline: dict[str, str]) -> IntegrityReport:
        """Verify current module hashes against a stored baseline."""
        hashes = []
        all_valid = True

        for module_name, expected_hash in baseline.items():
            try:
                mod = importlib.import_module(module_name)
                source_file = inspect.getfile(mod)
                content = Path(source_file).read_bytes()
                actual_hash = hashlib.sha256(content).hexdigest()
                verified = actual_hash == expected_hash
                if not verified:
                    all_valid = False
                hashes.append(ModuleHash(
                    module=module_name,
                    file_path=source_file,
                    sha256=actual_hash,
                    verified=verified,
                ))
            except (ImportError, TypeError, OSError):
                all_valid = False
                hashes.append(ModuleHash(module=module_name, verified=False))

        combined = "".join(h.sha256 for h in hashes)
        baseline_hash = hashlib.sha256(combined.encode()).hexdigest()

        return IntegrityReport(
            modules_checked=len(hashes),
            all_valid=all_valid,
            hashes=hashes,
            baseline_hash=baseline_hash,
        )

    def quick_check(self) -> bool:
        """Fast check: can all governance modules be imported?"""
        for module_name in GOVERNANCE_MODULES:
            try:
                importlib.import_module(module_name)
            except ImportError:
                return False
        return True
