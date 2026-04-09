"""Output PII/Secrets Filter — detect and redact sensitive data in tool responses.

Scans any text blob (tool output, agent response, inter-agent message) for
PII and secrets, then redacts, blocks, or logs based on configuration.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class SensitiveDataType(str, Enum):
    """Categories of sensitive data."""

    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    IP_ADDRESS = "ip_address"
    AWS_KEY = "aws_key"
    GITHUB_TOKEN = "github_token"
    GOOGLE_API_KEY = "google_api_key"
    SLACK_TOKEN = "slack_token"
    STRIPE_KEY = "stripe_key"
    JWT = "jwt"
    PRIVATE_KEY = "private_key"
    DB_CONNECTION_STRING = "db_connection_string"
    GENERIC_SECRET = "generic_secret"
    CUSTOM = "custom"


class FilterAction(str, Enum):
    """What to do when sensitive data is found."""

    REDACT = "redact"
    BLOCK = "block"
    WARN = "warn"
    LOG = "log"


class FilterFinding(BaseModel):
    """A single sensitive data finding."""

    data_type: SensitiveDataType
    matched_text: str = ""
    redacted_text: str = ""
    start: int = 0
    end: int = 0
    confidence: float = 1.0


class FilterResult(BaseModel):
    """Result of scanning text for sensitive data."""

    original_length: int = 0
    filtered_text: str = ""
    findings: list[FilterFinding] = Field(default_factory=list)
    blocked: bool = False
    action_taken: FilterAction = FilterAction.LOG

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    @property
    def pii_count(self) -> int:
        pii_types = {
            SensitiveDataType.EMAIL,
            SensitiveDataType.PHONE,
            SensitiveDataType.SSN,
            SensitiveDataType.CREDIT_CARD,
            SensitiveDataType.IP_ADDRESS,
        }
        return sum(1 for f in self.findings if f.data_type in pii_types)

    @property
    def secret_count(self) -> int:
        return len(self.findings) - self.pii_count

    def summary(self) -> dict[str, Any]:
        return {
            "has_findings": self.has_findings,
            "total_findings": len(self.findings),
            "pii_found": self.pii_count,
            "secrets_found": self.secret_count,
            "blocked": self.blocked,
            "action": self.action_taken.value,
            "types_found": list({f.data_type.value for f in self.findings}),
        }


_REDACT_PLACEHOLDER = "***REDACTED***"

_PII_PATTERNS: list[tuple[str, SensitiveDataType, float]] = [
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", SensitiveDataType.EMAIL, 0.95),
    (
        r"(?<!\d)(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)",
        SensitiveDataType.PHONE,
        0.75,
    ),
    (r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b", SensitiveDataType.SSN, 0.85),
    (r"\b(?:\d[ -]*?){13,19}\b", SensitiveDataType.CREDIT_CARD, 0.7),
    (
        r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
        SensitiveDataType.IP_ADDRESS,
        0.9,
    ),
]

_SECRET_PATTERNS: list[tuple[str, SensitiveDataType, float]] = [
    (r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}", SensitiveDataType.AWS_KEY, 1.0),
    (r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}", SensitiveDataType.GITHUB_TOKEN, 1.0),
    (r"AIza[0-9A-Za-z_-]{35}", SensitiveDataType.GOOGLE_API_KEY, 1.0),
    (r"xox[boaprs]-[0-9a-zA-Z-]{10,250}", SensitiveDataType.SLACK_TOKEN, 1.0),
    (r"(?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{20,250}", SensitiveDataType.STRIPE_KEY, 1.0),
    (
        r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_.+/=-]{10,}",
        SensitiveDataType.JWT,
        0.95,
    ),
    (
        r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----",
        SensitiveDataType.PRIVATE_KEY,
        1.0,
    ),
    (
        r"(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://[^\s\"'`<>]{10,}",
        SensitiveDataType.DB_CONNECTION_STRING,
        0.95,
    ),
    (
        r"(?i)(?:api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token)"
        r"\s*[:=]\s*['\"]?[A-Za-z0-9_/+=.-]{16,}['\"]?",
        SensitiveDataType.GENERIC_SECRET,
        0.8,
    ),
]


def _luhn_check(number: str) -> bool:
    """Validate a credit card number with the Luhn algorithm."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


class OutputFilter:
    """Scan and redact PII and secrets from text.

    Usage:
        filt = OutputFilter()

        result = filt.scan("Call me at 555-123-4567 or email me@example.com")
        if result.has_findings:
            print(result.filtered_text)  # "Call me at ***REDACTED*** or ***REDACTED***"

        # Block mode — reject the entire output
        filt = OutputFilter(action=FilterAction.BLOCK)
        result = filt.scan(tool_output)
        if result.blocked:
            raise ValueError("Tool output contains sensitive data")

        # Custom patterns
        filt = OutputFilter(custom_patterns=[
            (r"INTERNAL-\\d{6}", SensitiveDataType.CUSTOM, 1.0)
        ])
    """

    def __init__(
        self,
        *,
        action: FilterAction = FilterAction.REDACT,
        placeholder: str = _REDACT_PLACEHOLDER,
        detect_pii: bool = True,
        detect_secrets: bool = True,
        custom_patterns: list[tuple[str, SensitiveDataType, float]] | None = None,
        min_confidence: float = 0.5,
    ):
        self._action = action
        self._placeholder = placeholder
        self._min_confidence = min_confidence

        patterns: list[tuple[str, SensitiveDataType, float]] = []
        if detect_pii:
            patterns.extend(_PII_PATTERNS)
        if detect_secrets:
            patterns.extend(_SECRET_PATTERNS)
        if custom_patterns:
            patterns.extend(custom_patterns)

        self._compiled = [(re.compile(p), dtype, conf) for p, dtype, conf in patterns]

    def scan(self, text: str) -> FilterResult:
        """Scan text for PII and secrets, returning findings and optionally redacted text."""
        if not text:
            return FilterResult(original_length=0, filtered_text="", action_taken=self._action)

        findings: list[FilterFinding] = []
        for regex, data_type, confidence in self._compiled:
            if confidence < self._min_confidence:
                continue
            for match in regex.finditer(text):
                matched = match.group(0)

                if data_type == SensitiveDataType.CREDIT_CARD and not _luhn_check(matched):
                    continue

                findings.append(
                    FilterFinding(
                        data_type=data_type,
                        matched_text=matched[:8] + "..." if len(matched) > 8 else matched,
                        redacted_text=self._placeholder,
                        start=match.start(),
                        end=match.end(),
                        confidence=confidence,
                    )
                )

        findings.sort(key=lambda f: f.start, reverse=True)
        _deduplicate(findings)

        blocked = self._action == FilterAction.BLOCK and len(findings) > 0

        filtered_text = text
        if self._action == FilterAction.REDACT and findings:
            for f in findings:
                filtered_text = (
                    filtered_text[: f.start] + self._placeholder + filtered_text[f.end :]
                )
        elif blocked:
            filtered_text = "[BLOCKED — output contained sensitive data]"

        return FilterResult(
            original_length=len(text),
            filtered_text=filtered_text,
            findings=findings,
            blocked=blocked,
            action_taken=self._action,
        )

    def scan_dict(self, data: dict[str, Any], *, max_depth: int = 5) -> FilterResult:
        """Recursively scan all string values in a dict."""
        all_findings: list[FilterFinding] = []
        filtered = _scan_recursive(data, self, all_findings, 0, max_depth)
        blocked = self._action == FilterAction.BLOCK and len(all_findings) > 0
        return FilterResult(
            original_length=len(str(data)),
            filtered_text=str(filtered),
            findings=all_findings,
            blocked=blocked,
            action_taken=self._action,
        )


def _scan_recursive(
    obj: Any,
    filt: OutputFilter,
    findings: list[FilterFinding],
    depth: int,
    max_depth: int,
) -> Any:
    if depth > max_depth:
        return obj
    if isinstance(obj, str):
        result = filt.scan(obj)
        findings.extend(result.findings)
        return result.filtered_text
    if isinstance(obj, dict):
        return {k: _scan_recursive(v, filt, findings, depth + 1, max_depth) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_scan_recursive(v, filt, findings, depth + 1, max_depth) for v in obj]
    return obj


def _deduplicate(findings: list[FilterFinding]) -> None:
    """Remove overlapping findings, keeping higher-confidence ones."""
    if len(findings) < 2:
        return
    i = 0
    while i < len(findings) - 1:
        current = findings[i]
        next_f = findings[i + 1]
        if current.start < next_f.end and current.end > next_f.start:
            if current.confidence >= next_f.confidence:
                findings.pop(i + 1)
            else:
                findings.pop(i)
        else:
            i += 1
