"""Built-in policy templates for common governance scenarios."""

from __future__ import annotations

from agent_guard.core.policy import Condition, Effect, Policy


def hipaa_policy() -> Policy:
    """HIPAA-aligned policy: strict data access, audit everything."""
    return (
        Policy(
            name="hipaa",
            description="HIPAA-aligned governance: restrict PII access, audit all data operations",
            default_effect=Effect.DENY,
        )
        .allow(
            "file_read",
            name="read_non_phi",
            reason="Allow reads with audit",
        )
        .deny(
            "file_write",
            name="block_writes",
            reason="File writes require approval",
        )
        .deny(
            "shell_exec",
            name="block_shell",
            reason="Shell execution not permitted",
        )
        .deny(
            "network",
            name="block_network",
            reason="External network calls not permitted without approval",
        )
        .audit(
            "database",
            name="audit_db",
            reason="All database operations audited for PHI access",
        )
        .audit(
            "api_call",
            name="audit_api",
            reason="All API calls audited",
        )
    )


def financial_policy() -> Policy:
    """Financial services policy: strict execution, transaction limits."""
    return (
        Policy(
            name="financial",
            description="Financial services governance: transaction controls and audit",
            default_effect=Effect.DENY,
        )
        .allow(
            "api_call",
            name="allow_api",
            reason="API calls allowed with audit",
        )
        .allow(
            "database",
            name="allow_db_read",
            reason="Database reads allowed",
            conditions=[Condition(field="parameters.operation", operator="equals", value="read")],
        )
        .deny(
            "database",
            name="block_db_write",
            reason="Database writes require approval",
            conditions=[Condition(field="parameters.operation", operator="equals", value="write")],
        )
        .deny(
            "shell_exec",
            name="block_shell",
            reason="Shell execution prohibited",
        )
        .deny(
            "code_exec",
            name="block_code",
            reason="Arbitrary code execution prohibited",
        )
        .audit(
            "file_read",
            name="audit_reads",
            reason="File reads audited",
        )
    )


def research_policy() -> Policy:
    """Research agent policy: broad read access, limited write."""
    return (
        Policy(
            name="research",
            description="Research agent: broad search and read, limited writes",
            default_effect=Effect.DENY,
        )
        .allow(
            "web_search",
            reason="Searching is core to research",
        )
        .allow(
            "api_call",
            reason="API calls allowed for data gathering",
        )
        .allow(
            "file_read",
            reason="Reading files and documents is allowed",
        )
        .audit(
            "file_write",
            reason="File writes are audited",
        )
        .deny(
            "shell_exec",
            reason="Shell execution not needed for research",
        )
        .deny(
            "code_exec",
            reason="Code execution not needed for research",
        )
    )


def development_policy() -> Policy:
    """Software development agent policy: code access, sandboxed execution."""
    return (
        Policy(
            name="development",
            description="Development agent: code access with sandboxed execution",
            default_effect=Effect.DENY,
        )
        .allow(
            "file_read",
            reason="Reading source code is allowed",
        )
        .allow(
            "file_write",
            reason="Writing code files is allowed",
        )
        .allow(
            "web_search",
            reason="Documentation lookup allowed",
        )
        .allow(
            "api_call",
            reason="API testing allowed",
        )
        .audit(
            "shell_exec",
            reason="Shell execution audited",
        )
        .audit(
            "code_exec",
            reason="Code execution audited",
        )
        .deny(
            "database",
            reason="Direct database access requires approval",
        )
    )


BUILTIN_POLICIES = {
    "permissive": Policy.permissive,
    "restrictive": Policy.restrictive,
    "standard": Policy.standard,
    "hipaa": hipaa_policy,
    "financial": financial_policy,
    "research": research_policy,
    "development": development_policy,
}


def get_builtin(name: str) -> Policy:
    """Get a built-in policy by name."""
    factory = BUILTIN_POLICIES.get(name)
    if not factory:
        available = ", ".join(sorted(BUILTIN_POLICIES.keys()))
        raise ValueError(f"Unknown built-in policy '{name}'. Available: {available}")
    return factory()


def list_builtins() -> list[str]:
    """List available built-in policy names."""
    return sorted(BUILTIN_POLICIES.keys())
