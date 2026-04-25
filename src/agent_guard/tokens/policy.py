"""Token Policy — governance rules for credential lifecycle and usage."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from agent_guard.tokens.inventory import (
    TokenRecord,
    TokenSource,
    TokenStatus,
)


class TokenViolationType(str, Enum):
    """Types of token policy violations."""

    STALE_TOKEN = "stale_token"
    EXCESSIVE_SHARING = "excessive_sharing"
    DENIED_PROVIDER = "denied_provider"
    INLINE_CREDENTIAL = "inline_credential"
    HIGH_RISK = "high_risk"
    EXPIRED = "expired"


class TokenPolicyResult(BaseModel):
    """Outcome of evaluating a token against the policy."""

    token_id: str
    compliant: bool = True
    violations: list[TokenViolationType] = Field(default_factory=list)
    messages: list[str] = Field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "token_id": self.token_id,
            "compliant": self.compliant,
            "violations": [v.value for v in self.violations],
            "messages": self.messages,
        }


class TokenPolicy:
    """Evaluate tokens against governance rules.

    Usage::

        policy = TokenPolicy(max_age_days=90, max_agents_per_token=3)
        result = policy.evaluate(token_record)
        if not result.compliant:
            for msg in result.messages:
                print(f"  VIOLATION: {msg}")
    """

    def __init__(
        self,
        *,
        max_age_days: int = 90,
        require_rotation: bool = True,
        denied_providers: list[str] | None = None,
        max_agents_per_token: int = 5,
        alert_on_inline: bool = True,
        max_risk_score: int = 75,
    ):
        self.max_age_days = max_age_days
        self.require_rotation = require_rotation
        self.denied_providers = [p.lower() for p in (denied_providers or [])]
        self.max_agents_per_token = max_agents_per_token
        self.alert_on_inline = alert_on_inline
        self.max_risk_score = max_risk_score

    def evaluate(self, record: TokenRecord) -> TokenPolicyResult:
        """Check a token record against all policy rules."""
        result = TokenPolicyResult(token_id=record.token_id)

        if record.status == TokenStatus.EXPIRED:
            result.compliant = False
            result.violations.append(TokenViolationType.EXPIRED)
            result.messages.append(f"Token {record.masked_value} has expired")

        if self.require_rotation and record.age_days > self.max_age_days:
            result.compliant = False
            result.violations.append(TokenViolationType.STALE_TOKEN)
            result.messages.append(
                f"Token {record.masked_value} is {record.age_days:.0f} days old "
                f"(limit: {self.max_age_days} days)"
            )

        if len(record.agents) > self.max_agents_per_token:
            result.compliant = False
            result.violations.append(TokenViolationType.EXCESSIVE_SHARING)
            result.messages.append(
                f"Token {record.masked_value} shared across "
                f"{len(record.agents)} agents (limit: {self.max_agents_per_token})"
            )

        if record.provider.value.lower() in self.denied_providers:
            result.compliant = False
            result.violations.append(TokenViolationType.DENIED_PROVIDER)
            result.messages.append(f"Provider '{record.provider.value}' is denied by policy")

        if self.alert_on_inline and record.source in (
            TokenSource.TOOL_ARGUMENT,
            TokenSource.TOOL_OUTPUT,
        ):
            result.compliant = False
            result.violations.append(TokenViolationType.INLINE_CREDENTIAL)
            result.messages.append(
                f"Token {record.masked_value} found inline in "
                f"{record.source.value} (should be in env/vault)"
            )

        if record.risk_score > self.max_risk_score:
            result.compliant = False
            result.violations.append(TokenViolationType.HIGH_RISK)
            result.messages.append(
                f"Token risk score {record.risk_score} exceeds threshold {self.max_risk_score}"
            )

        return result

    def evaluate_all(self, records: list[TokenRecord]) -> list[TokenPolicyResult]:
        """Evaluate all records and return results (violations first)."""
        results = [self.evaluate(r) for r in records]
        return sorted(results, key=lambda r: (r.compliant, -len(r.violations)))

    def summary(self, records: list[TokenRecord]) -> dict[str, Any]:
        """Return aggregate policy compliance stats."""
        results = self.evaluate_all(records)
        violations_by_type: dict[str, int] = {}
        for r in results:
            for v in r.violations:
                violations_by_type[v.value] = violations_by_type.get(v.value, 0) + 1

        compliant = sum(1 for r in results if r.compliant)
        return {
            "total_tokens": len(results),
            "compliant": compliant,
            "non_compliant": len(results) - compliant,
            "compliance_rate": (round(compliant / len(results) * 100, 1) if results else 100.0),
            "violations_by_type": violations_by_type,
        }
