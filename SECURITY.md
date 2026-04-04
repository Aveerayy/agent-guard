# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in Agent Guard, please report it responsibly.

**Do NOT open a public issue for security vulnerabilities.**

Instead, please email: **security@agent-guard.dev**

Or use GitHub's private vulnerability reporting feature on this repository.

## What We Consider a Vulnerability

- Bypass of policy enforcement (an action passes when it should be denied)
- Bypass of sandbox isolation
- Tampering with audit log chain without detection
- Identity/key material exposure
- MCP scanner evasion techniques
- Privilege escalation in permission levels

## Security Model

Agent Guard provides **application-level Python middleware governance**, not OS kernel-level isolation. The policy engine and agents run in the same Python process.

| Layer | Provides | Does NOT Provide |
|-------|----------|------------------|
| Policy Engine | Deterministic action interception | Hardware-level memory isolation |
| Identity | Ed25519 cryptographic credentials | OS-level process separation |
| Sandbox | Permission levels + subprocess isolation | CPU ring-level enforcement |
| Audit | SHA-256 tamper detection chain | Hardware root-of-trust |
| Integrity | SHA-256 module verification at startup | TPM/Secure Boot |

## Production Recommendations

- Run each agent in a **separate container** for OS-level isolation
- Review and customize policy rules for your environment
- Enable audit log persistence for compliance
- Rotate agent identity keys periodically
- Monitor the observability bus for anomalies

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Current |

## Disclosure Timeline

- **Day 0**: Report received
- **Day 1-3**: Acknowledgment sent
- **Day 7-14**: Fix developed and tested
- **Day 14-30**: Coordinated disclosure
