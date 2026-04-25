"""Risk Scoring — assess the criticality of discovered access tokens."""

from __future__ import annotations

from agent_guard.tokens.inventory import (
    RiskLevel,
    TokenProvider,
    TokenRecord,
    TokenSource,
    TokenType,
)

_PROVIDER_CRITICALITY: dict[TokenProvider, int] = {
    TokenProvider.AWS: 25,
    TokenProvider.AZURE: 25,
    TokenProvider.GOOGLE: 20,
    TokenProvider.GITHUB: 20,
    TokenProvider.OPENAI: 15,
    TokenProvider.ANTHROPIC: 15,
    TokenProvider.DATABASE: 20,
    TokenProvider.STRIPE: 20,
    TokenProvider.SLACK: 10,
    TokenProvider.CUSTOM: 5,
    TokenProvider.UNKNOWN: 5,
}

_TYPE_PRIVILEGE: dict[TokenType, int] = {
    TokenType.SECRET_KEY: 25,
    TokenType.SERVICE_ACCOUNT: 25,
    TokenType.SSH_KEY: 25,
    TokenType.CONNECTION_STRING: 20,
    TokenType.API_KEY: 15,
    TokenType.PERSONAL_ACCESS_TOKEN: 15,
    TokenType.OAUTH_TOKEN: 10,
    TokenType.JWT: 10,
    TokenType.UNKNOWN: 5,
}

_SOURCE_EXPOSURE: dict[TokenSource, int] = {
    TokenSource.TOOL_ARGUMENT: 15,
    TokenSource.TOOL_OUTPUT: 15,
    TokenSource.RUNTIME_SCAN: 12,
    TokenSource.CONFIG_FILE: 10,
    TokenSource.MCP_CONFIG: 10,
    TokenSource.ENV_VAR: 8,
}


def _age_score(age_days: float) -> int:
    if age_days > 365:
        return 20
    if age_days > 180:
        return 15
    if age_days > 90:
        return 10
    return 5


def _breadth_score(record: TokenRecord) -> int:
    agents = len(record.agents)
    if agents >= 5:
        return 15
    if agents >= 3:
        return 10
    return 5


class RiskScorer:
    """Score tokens on a 0-100 scale across five weighted factors.

    Factors (weights):
        1. Provider criticality (25) — AWS/Azure highest, custom lowest
        2. Scope / privilege (25) — secret keys > API keys > JWTs
        3. Token age (20) — older tokens score higher
        4. Exposure surface (15) — inline in tool args > env var > vault
        5. Usage breadth (15) — shared across many agents scores higher

    Risk levels: LOW (0-25), MEDIUM (26-50), HIGH (51-75), CRITICAL (76-100).
    """

    def score(self, record: TokenRecord) -> tuple[int, RiskLevel]:
        """Compute risk score and level for a token record."""
        provider_score = _PROVIDER_CRITICALITY.get(record.provider, 5)
        privilege_score = _TYPE_PRIVILEGE.get(record.token_type, 5)
        age = _age_score(record.age_days)
        exposure = _SOURCE_EXPOSURE.get(record.source, 8)
        breadth = _breadth_score(record)

        total = provider_score + privilege_score + age + exposure + breadth
        total = min(total, 100)

        if total >= 76:
            level = RiskLevel.CRITICAL
        elif total >= 51:
            level = RiskLevel.HIGH
        elif total >= 26:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW

        return total, level

    def score_all(self, records: list[TokenRecord]) -> list[TokenRecord]:
        """Score all records in-place and return them sorted by risk (desc)."""
        for record in records:
            score, level = self.score(record)
            record.risk_score = score
            record.risk_level = level
        return sorted(records, key=lambda r: r.risk_score, reverse=True)
