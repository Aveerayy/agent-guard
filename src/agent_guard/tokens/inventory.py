"""Token Inventory — central registry of discovered access tokens and credentials."""

from __future__ import annotations

import hashlib
import threading
import time
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class TokenProvider(str, Enum):
    """Known credential providers."""

    AWS = "aws"
    GITHUB = "github"
    GOOGLE = "google"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    SLACK = "slack"
    STRIPE = "stripe"
    AZURE = "azure"
    DATABASE = "database"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


class TokenType(str, Enum):
    """Classification of credential type."""

    API_KEY = "api_key"
    OAUTH_TOKEN = "oauth_token"
    SERVICE_ACCOUNT = "service_account"
    JWT = "jwt"
    SSH_KEY = "ssh_key"
    CONNECTION_STRING = "connection_string"
    PERSONAL_ACCESS_TOKEN = "personal_access_token"
    SECRET_KEY = "secret_key"
    UNKNOWN = "unknown"


class TokenSource(str, Enum):
    """Where the token was discovered."""

    ENV_VAR = "env_var"
    CONFIG_FILE = "config_file"
    TOOL_ARGUMENT = "tool_argument"
    TOOL_OUTPUT = "tool_output"
    MCP_CONFIG = "mcp_config"
    RUNTIME_SCAN = "runtime_scan"


class TokenStatus(str, Enum):
    """Current lifecycle status."""

    ACTIVE = "active"
    STALE = "stale"
    EXPIRED = "expired"
    REVOKED = "revoked"


class RiskLevel(str, Enum):
    """Risk classification."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TokenRecord(BaseModel):
    """A single tracked access token / credential."""

    token_id: str
    provider: TokenProvider = TokenProvider.UNKNOWN
    token_type: TokenType = TokenType.UNKNOWN
    masked_value: str = ""
    source: TokenSource = TokenSource.ENV_VAR
    source_detail: str = ""
    first_seen: float = Field(default_factory=time.time)
    last_used: float = Field(default_factory=time.time)
    use_count: int = 1
    agents: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    risk_score: int = 0
    risk_level: RiskLevel = RiskLevel.LOW
    status: TokenStatus = TokenStatus.ACTIVE
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def age_days(self) -> float:
        return (time.time() - self.first_seen) / 86400

    def to_summary(self) -> dict[str, Any]:
        return {
            "token_id": self.token_id,
            "provider": self.provider.value,
            "token_type": self.token_type.value,
            "masked_value": self.masked_value,
            "source": self.source.value,
            "source_detail": self.source_detail,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "status": self.status.value,
            "age_days": round(self.age_days, 1),
            "use_count": self.use_count,
            "agents": self.agents,
            "tools": self.tools,
        }


def _compute_token_id(provider: str, value_prefix: str) -> str:
    raw = f"{provider}:{value_prefix}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _mask_value(value: str) -> str:
    if len(value) <= 10:
        return value[:2] + "***" + value[-2:]
    return value[:6] + "..." + value[-4:]


class TokenInventory:
    """Central registry that tracks all discovered tokens.

    Thread-safe. Deduplicates by ``token_id`` so the same credential
    seen from multiple sources is stored once with merged metadata.

    Usage::

        inventory = TokenInventory()
        inventory.scan_environment()

        for token in inventory.list_tokens():
            print(token.provider, token.masked_value, token.risk_level)
    """

    def __init__(self) -> None:
        self._tokens: dict[str, TokenRecord] = {}
        self._lock = threading.Lock()

    def register(self, record: TokenRecord) -> TokenRecord:
        """Add or merge a token record into the inventory."""
        with self._lock:
            existing = self._tokens.get(record.token_id)
            if existing:
                existing.last_used = max(existing.last_used, record.last_used)
                existing.use_count += record.use_count
                for agent in record.agents:
                    if agent not in existing.agents:
                        existing.agents.append(agent)
                for tool in record.tools:
                    if tool not in existing.tools:
                        existing.tools.append(tool)
                if record.source != existing.source:
                    existing.metadata["also_found_in"] = record.source.value
                return existing
            self._tokens[record.token_id] = record
            return record

    def record_usage(
        self,
        token_id: str,
        agent_id: str = "",
        tool_name: str = "",
    ) -> TokenRecord | None:
        """Record a usage event for an existing token."""
        with self._lock:
            record = self._tokens.get(token_id)
            if not record:
                return None
            record.last_used = time.time()
            record.use_count += 1
            if agent_id and agent_id not in record.agents:
                record.agents.append(agent_id)
            if tool_name and tool_name not in record.tools:
                record.tools.append(tool_name)
            return record

    def get_token(self, token_id: str) -> TokenRecord | None:
        return self._tokens.get(token_id)

    def list_tokens(
        self,
        *,
        provider: TokenProvider | None = None,
        risk_level: RiskLevel | None = None,
        status: TokenStatus | None = None,
        source: TokenSource | None = None,
    ) -> list[TokenRecord]:
        """Query tokens with optional filters."""
        result = list(self._tokens.values())
        if provider:
            result = [t for t in result if t.provider == provider]
        if risk_level:
            result = [t for t in result if t.risk_level == risk_level]
        if status:
            result = [t for t in result if t.status == status]
        if source:
            result = [t for t in result if t.source == source]
        return sorted(result, key=lambda t: t.risk_score, reverse=True)

    def stale_tokens(self, max_age_days: int = 90) -> list[TokenRecord]:
        """Return tokens older than *max_age_days*."""
        threshold = time.time() - (max_age_days * 86400)
        return [t for t in self._tokens.values() if t.first_seen < threshold]

    def update_risk(self, token_id: str, score: int, level: RiskLevel) -> None:
        """Set risk score and level for a token."""
        with self._lock:
            record = self._tokens.get(token_id)
            if record:
                record.risk_score = score
                record.risk_level = level

    def mark_status(self, token_id: str, status: TokenStatus) -> None:
        with self._lock:
            record = self._tokens.get(token_id)
            if record:
                record.status = status

    @property
    def count(self) -> int:
        return len(self._tokens)

    def summary(self) -> dict[str, Any]:
        tokens = list(self._tokens.values())
        by_provider: dict[str, int] = {}
        by_risk: dict[str, int] = {}
        by_status: dict[str, int] = {}
        for t in tokens:
            by_provider[t.provider.value] = by_provider.get(t.provider.value, 0) + 1
            by_risk[t.risk_level.value] = by_risk.get(t.risk_level.value, 0) + 1
            by_status[t.status.value] = by_status.get(t.status.value, 0) + 1

        return {
            "total_tokens": len(tokens),
            "by_provider": by_provider,
            "by_risk_level": by_risk,
            "by_status": by_status,
            "active": by_status.get("active", 0),
            "stale": by_status.get("stale", 0),
        }
