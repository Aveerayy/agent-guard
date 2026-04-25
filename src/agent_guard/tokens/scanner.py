"""Token Scanner — discover credentials in environment, configs, and runtime data."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from agent_guard.filters.output_filter import _SECRET_PATTERNS as SECRET_PATTERN_DEFS
from agent_guard.filters.output_filter import SensitiveDataType
from agent_guard.tokens.inventory import (
    TokenInventory,
    TokenProvider,
    TokenRecord,
    TokenSource,
    TokenType,
    _compute_token_id,
    _mask_value,
)

_DTYPE_TO_PROVIDER: dict[SensitiveDataType, TokenProvider] = {
    SensitiveDataType.AWS_KEY: TokenProvider.AWS,
    SensitiveDataType.GITHUB_TOKEN: TokenProvider.GITHUB,
    SensitiveDataType.GOOGLE_API_KEY: TokenProvider.GOOGLE,
    SensitiveDataType.SLACK_TOKEN: TokenProvider.SLACK,
    SensitiveDataType.STRIPE_KEY: TokenProvider.STRIPE,
    SensitiveDataType.JWT: TokenProvider.UNKNOWN,
    SensitiveDataType.PRIVATE_KEY: TokenProvider.UNKNOWN,
    SensitiveDataType.DB_CONNECTION_STRING: TokenProvider.DATABASE,
    SensitiveDataType.GENERIC_SECRET: TokenProvider.UNKNOWN,
}

_DTYPE_TO_TOKEN_TYPE: dict[SensitiveDataType, TokenType] = {
    SensitiveDataType.AWS_KEY: TokenType.API_KEY,
    SensitiveDataType.GITHUB_TOKEN: TokenType.PERSONAL_ACCESS_TOKEN,
    SensitiveDataType.GOOGLE_API_KEY: TokenType.API_KEY,
    SensitiveDataType.SLACK_TOKEN: TokenType.OAUTH_TOKEN,
    SensitiveDataType.STRIPE_KEY: TokenType.SECRET_KEY,
    SensitiveDataType.JWT: TokenType.JWT,
    SensitiveDataType.PRIVATE_KEY: TokenType.SSH_KEY,
    SensitiveDataType.DB_CONNECTION_STRING: TokenType.CONNECTION_STRING,
    SensitiveDataType.GENERIC_SECRET: TokenType.API_KEY,
}

_ENV_HINTS: list[tuple[str, TokenProvider, TokenType]] = [
    ("OPENAI_API_KEY", TokenProvider.OPENAI, TokenType.API_KEY),
    ("ANTHROPIC_API_KEY", TokenProvider.ANTHROPIC, TokenType.API_KEY),
    ("AZURE_OPENAI", TokenProvider.AZURE, TokenType.API_KEY),
    ("AWS_ACCESS_KEY", TokenProvider.AWS, TokenType.API_KEY),
    ("AWS_SECRET_ACCESS", TokenProvider.AWS, TokenType.SECRET_KEY),
    ("GITHUB_TOKEN", TokenProvider.GITHUB, TokenType.PERSONAL_ACCESS_TOKEN),
    ("GH_TOKEN", TokenProvider.GITHUB, TokenType.PERSONAL_ACCESS_TOKEN),
    ("GOOGLE_API_KEY", TokenProvider.GOOGLE, TokenType.API_KEY),
    ("GOOGLE_APPLICATION_CREDENTIALS", TokenProvider.GOOGLE, TokenType.SERVICE_ACCOUNT),
    ("SLACK_TOKEN", TokenProvider.SLACK, TokenType.OAUTH_TOKEN),
    ("SLACK_BOT_TOKEN", TokenProvider.SLACK, TokenType.OAUTH_TOKEN),
    ("STRIPE_SECRET_KEY", TokenProvider.STRIPE, TokenType.SECRET_KEY),
    ("STRIPE_API_KEY", TokenProvider.STRIPE, TokenType.SECRET_KEY),
    ("DATABASE_URL", TokenProvider.DATABASE, TokenType.CONNECTION_STRING),
    ("DB_URL", TokenProvider.DATABASE, TokenType.CONNECTION_STRING),
    ("REDIS_URL", TokenProvider.DATABASE, TokenType.CONNECTION_STRING),
    ("MONGO_URI", TokenProvider.DATABASE, TokenType.CONNECTION_STRING),
]

_COMPILED_SECRETS = [
    (re.compile(pattern), dtype, conf) for pattern, dtype, conf in SECRET_PATTERN_DEFS
]


class TokenScanner:
    """Discover access tokens in the environment, config files, and runtime data.

    Reuses the same regex patterns as :class:`OutputFilter` to classify
    credential types, then enriches with provider and lifecycle metadata.

    Usage::

        scanner = TokenScanner()
        tokens = scanner.scan_environment()
        tokens += scanner.scan_config("~/.cursor/mcp.json")
    """

    def __init__(self, *, inventory: TokenInventory | None = None) -> None:
        self._inventory = inventory or TokenInventory()

    @property
    def inventory(self) -> TokenInventory:
        return self._inventory

    def scan_environment(
        self,
        *,
        env: dict[str, str] | None = None,
        dotenv_path: str | Path | None = None,
    ) -> list[TokenRecord]:
        """Scan ``os.environ`` (or provided dict) for credentials.

        Optionally reads a ``.env`` file and merges its values.
        """
        env_vars = dict(env or os.environ)

        if dotenv_path:
            env_vars.update(_parse_dotenv(Path(dotenv_path)))

        records: list[TokenRecord] = []
        for key, value in env_vars.items():
            if not value or len(value) < 8:
                continue

            provider, token_type = _classify_env_var(key, value)
            if provider == TokenProvider.UNKNOWN and not _matches_secret_pattern(value):
                continue

            if provider == TokenProvider.UNKNOWN:
                provider, token_type = _classify_by_pattern(value)

            token_id = _compute_token_id(provider.value, value[:12])
            record = TokenRecord(
                token_id=token_id,
                provider=provider,
                token_type=token_type,
                masked_value=_mask_value(value),
                source=TokenSource.ENV_VAR,
                source_detail=key,
            )
            self._inventory.register(record)
            records.append(record)

        return records

    def scan_config(self, config_path: str | Path) -> list[TokenRecord]:
        """Scan an MCP or agent config JSON file for embedded credentials."""
        path = Path(config_path).expanduser()
        if not path.exists():
            return []

        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return []

        records: list[TokenRecord] = []
        self._walk_config(data, str(path.name), records)
        return records

    def scan_text(
        self,
        text: str,
        *,
        source: TokenSource = TokenSource.RUNTIME_SCAN,
        source_detail: str = "",
        agent_id: str = "",
        tool_name: str = "",
    ) -> list[TokenRecord]:
        """Scan arbitrary text for credentials (tool args, outputs, etc.)."""
        records: list[TokenRecord] = []
        for regex, dtype, _conf in _COMPILED_SECRETS:
            for match in regex.finditer(text):
                value = match.group(0)
                provider = _DTYPE_TO_PROVIDER.get(dtype, TokenProvider.UNKNOWN)
                token_type = _DTYPE_TO_TOKEN_TYPE.get(dtype, TokenType.UNKNOWN)
                token_id = _compute_token_id(provider.value, value[:12])
                record = TokenRecord(
                    token_id=token_id,
                    provider=provider,
                    token_type=token_type,
                    masked_value=_mask_value(value),
                    source=source,
                    source_detail=source_detail,
                    agents=[agent_id] if agent_id else [],
                    tools=[tool_name] if tool_name else [],
                )
                self._inventory.register(record)
                records.append(record)
        return records

    def scan_dict(
        self,
        data: dict[str, Any],
        *,
        source: TokenSource = TokenSource.TOOL_ARGUMENT,
        source_detail: str = "",
        agent_id: str = "",
        tool_name: str = "",
    ) -> list[TokenRecord]:
        """Recursively scan structured data (e.g. tool call params) for tokens."""
        text = _flatten_dict(data)
        return self.scan_text(
            text,
            source=source,
            source_detail=source_detail,
            agent_id=agent_id,
            tool_name=tool_name,
        )

    def _walk_config(
        self,
        obj: Any,
        context: str,
        records: list[TokenRecord],
    ) -> None:
        if isinstance(obj, str):
            if len(obj) >= 8 and _matches_secret_pattern(obj):
                provider, token_type = _classify_by_pattern(obj)
                token_id = _compute_token_id(provider.value, obj[:12])
                record = TokenRecord(
                    token_id=token_id,
                    provider=provider,
                    token_type=token_type,
                    masked_value=_mask_value(obj),
                    source=TokenSource.MCP_CONFIG,
                    source_detail=context,
                )
                self._inventory.register(record)
                records.append(record)
        elif isinstance(obj, dict):
            for key, val in obj.items():
                child_ctx = f"{context}.{key}" if context else key
                if isinstance(val, str) and len(val) >= 8:
                    env_provider, env_type = _classify_env_var(key, val)
                    if env_provider != TokenProvider.UNKNOWN:
                        token_id = _compute_token_id(env_provider.value, val[:12])
                        record = TokenRecord(
                            token_id=token_id,
                            provider=env_provider,
                            token_type=env_type,
                            masked_value=_mask_value(val),
                            source=TokenSource.MCP_CONFIG,
                            source_detail=child_ctx,
                        )
                        self._inventory.register(record)
                        records.append(record)
                        continue
                self._walk_config(val, child_ctx, records)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                self._walk_config(item, f"{context}[{i}]", records)


def _classify_env_var(key: str, value: str) -> tuple[TokenProvider, TokenType]:
    key_upper = key.upper()
    for hint_key, provider, token_type in _ENV_HINTS:
        if hint_key in key_upper:
            return provider, token_type

    if any(
        kw in key_upper for kw in ("API_KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL", "AUTH")
    ):
        provider, token_type = _classify_by_pattern(value)
        if provider != TokenProvider.UNKNOWN:
            return provider, token_type
        return TokenProvider.CUSTOM, TokenType.API_KEY

    return TokenProvider.UNKNOWN, TokenType.UNKNOWN


def _classify_by_pattern(value: str) -> tuple[TokenProvider, TokenType]:
    for regex, dtype, _conf in _COMPILED_SECRETS:
        if regex.search(value):
            return (
                _DTYPE_TO_PROVIDER.get(dtype, TokenProvider.UNKNOWN),
                _DTYPE_TO_TOKEN_TYPE.get(dtype, TokenType.UNKNOWN),
            )
    return TokenProvider.UNKNOWN, TokenType.UNKNOWN


def _matches_secret_pattern(value: str) -> bool:
    return any(regex.search(value) for regex, _, _ in _COMPILED_SECRETS)


def _parse_dotenv(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    result: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, val = line.partition("=")
            val = val.strip().strip("'\"")
            result[key.strip()] = val
    return result


def _flatten_dict(obj: Any, depth: int = 0) -> str:
    if depth > 8:
        return ""
    if isinstance(obj, str):
        return obj + " "
    if isinstance(obj, dict):
        return " ".join(_flatten_dict(v, depth + 1) for v in obj.values())
    if isinstance(obj, list):
        return " ".join(_flatten_dict(v, depth + 1) for v in obj)
    return str(obj) + " " if obj is not None else ""
