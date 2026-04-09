"""Tests for output PII/secrets filter."""

import pytest
from agent_guard.filters.output_filter import (
    OutputFilter,
    FilterAction,
    SensitiveDataType,
)


class TestPIIDetection:
    def test_detects_email(self):
        filt = OutputFilter()
        result = filt.scan("Contact us at admin@example.com for help")
        assert result.has_findings
        assert any(f.data_type == SensitiveDataType.EMAIL for f in result.findings)
        assert "***REDACTED***" in result.filtered_text
        assert "admin@example.com" not in result.filtered_text

    def test_detects_phone(self):
        filt = OutputFilter()
        result = filt.scan("Call me at 555-123-4567 please")
        assert result.has_findings
        assert any(f.data_type == SensitiveDataType.PHONE for f in result.findings)

    def test_detects_ssn(self):
        filt = OutputFilter()
        result = filt.scan("SSN: 123-45-6789")
        assert result.has_findings
        assert any(f.data_type == SensitiveDataType.SSN for f in result.findings)

    def test_detects_credit_card_with_luhn(self):
        filt = OutputFilter()
        result = filt.scan("Card: 4111 1111 1111 1111")
        assert result.has_findings
        assert any(f.data_type == SensitiveDataType.CREDIT_CARD for f in result.findings)

    def test_rejects_invalid_credit_card(self):
        filt = OutputFilter()
        result = filt.scan("Number: 1234 5678 9012 3456")
        cc_findings = [f for f in result.findings if f.data_type == SensitiveDataType.CREDIT_CARD]
        assert len(cc_findings) == 0

    def test_detects_internal_ip(self):
        filt = OutputFilter()
        result = filt.scan("Server at 192.168.1.100")
        assert result.has_findings
        assert any(f.data_type == SensitiveDataType.IP_ADDRESS for f in result.findings)


class TestSecretDetection:
    def test_detects_aws_key(self):
        filt = OutputFilter()
        result = filt.scan("Key: AKIAIOSFODNN7EXAMPLE")
        assert result.has_findings
        assert any(f.data_type == SensitiveDataType.AWS_KEY for f in result.findings)

    def test_detects_github_token(self):
        filt = OutputFilter()
        result = filt.scan("Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
        assert result.has_findings
        assert any(f.data_type == SensitiveDataType.GITHUB_TOKEN for f in result.findings)

    def test_detects_jwt(self):
        filt = OutputFilter()
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        result = filt.scan(f"Auth: {jwt}")
        assert result.has_findings
        assert any(f.data_type == SensitiveDataType.JWT for f in result.findings)

    def test_detects_private_key(self):
        filt = OutputFilter()
        result = filt.scan("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")
        assert result.has_findings
        assert any(f.data_type == SensitiveDataType.PRIVATE_KEY for f in result.findings)

    def test_detects_db_connection_string(self):
        filt = OutputFilter()
        result = filt.scan("DB: postgres://user:pass@host:5432/db")
        assert result.has_findings
        assert any(f.data_type == SensitiveDataType.DB_CONNECTION_STRING for f in result.findings)

    def test_detects_stripe_key(self):
        filt = OutputFilter()
        fake_key = "sk_test_" + "a1b2c3d4e5f6g7h8i9j0k1l2"
        result = filt.scan(f"key: {fake_key}")
        assert result.has_findings
        assert any(f.data_type == SensitiveDataType.STRIPE_KEY for f in result.findings)

    def test_detects_generic_api_key(self):
        filt = OutputFilter()
        result = filt.scan("api_key = 'ABCDEFghijklMNOP1234567890abcdef'")
        assert result.has_findings
        assert any(f.data_type == SensitiveDataType.GENERIC_SECRET for f in result.findings)


class TestFilterActions:
    def test_redact_mode(self):
        filt = OutputFilter(action=FilterAction.REDACT)
        result = filt.scan("Email: test@example.com")
        assert not result.blocked
        assert "***REDACTED***" in result.filtered_text

    def test_block_mode(self):
        filt = OutputFilter(action=FilterAction.BLOCK)
        result = filt.scan("Email: test@example.com")
        assert result.blocked
        assert "BLOCKED" in result.filtered_text

    def test_log_mode(self):
        filt = OutputFilter(action=FilterAction.LOG)
        result = filt.scan("Email: test@example.com")
        assert not result.blocked
        assert "test@example.com" in result.filtered_text

    def test_clean_text_passes(self):
        filt = OutputFilter()
        result = filt.scan("The weather today is sunny and 72F.")
        assert not result.has_findings
        assert result.filtered_text == "The weather today is sunny and 72F."

    def test_empty_text(self):
        filt = OutputFilter()
        result = filt.scan("")
        assert not result.has_findings

    def test_multiple_findings(self):
        filt = OutputFilter()
        result = filt.scan("Email: a@b.com, phone: 555-123-4567, key: AKIAIOSFODNN7EXAMPLE")
        assert len(result.findings) >= 3

    def test_scan_dict(self):
        filt = OutputFilter()
        result = filt.scan_dict({
            "response": "Contact admin@example.com",
            "nested": {"data": "Key: AKIAIOSFODNN7EXAMPLE"},
        })
        assert result.has_findings
        assert result.pii_count >= 1
        assert result.secret_count >= 1


class TestCustomPatterns:
    def test_custom_pattern(self):
        filt = OutputFilter(custom_patterns=[
            (r"INTERNAL-\d{6}", SensitiveDataType.CUSTOM, 1.0),
        ])
        result = filt.scan("Ref: INTERNAL-123456")
        assert result.has_findings
        assert any(f.data_type == SensitiveDataType.CUSTOM for f in result.findings)

    def test_pii_only_mode(self):
        filt = OutputFilter(detect_pii=True, detect_secrets=False)
        result = filt.scan("Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
        assert not result.has_findings

    def test_secrets_only_mode(self):
        filt = OutputFilter(detect_pii=False, detect_secrets=True)
        result = filt.scan("Email: test@example.com")
        assert not result.has_findings


class TestSummary:
    def test_summary_structure(self):
        filt = OutputFilter()
        result = filt.scan("Email: a@b.com and key AKIAIOSFODNN7EXAMPLE")
        s = result.summary()
        assert "has_findings" in s
        assert "total_findings" in s
        assert "pii_found" in s
        assert "secrets_found" in s
        assert "types_found" in s
        assert s["has_findings"] is True
