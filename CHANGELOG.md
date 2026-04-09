# Changelog

All notable changes to Agent Guard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-04

### Added

- **Policy Engine** — YAML and Python-based rule definitions with conditions, wildcards, priority ordering, and deny-by-default enforcement. Sub-millisecond evaluation (<0.1ms per check).
- **Guard API** — Simple `Guard.check()` interface and `@guard.enforce` decorator for wrapping tool calls.
- **Session-scoped policies** — Context manager for temporary policy overrides within a session.
- **Built-in policy templates** — HIPAA, financial services, and research policy presets.
- **Agent Identity** — Ed25519 cryptographic keypairs with digital signatures for messages and JSON payloads. Agent roles and trust scoring (0-1000 scale).
- **Trust Engine** — Behavioral trust scoring that updates based on agent action outcomes. Configurable thresholds for trust levels.
- **Execution Sandbox** — 5 permission levels (MINIMAL, RESTRICTED, STANDARD, ELEVATED, ADMIN) for controlled execution of Python code, shell commands, and functions.
- **Audit Logger** — SHA-256 hash-chained, tamper-proof audit trail for all governance decisions.
- **MCP Security Scanner** — Detects 8 threat categories in MCP tool definitions: prompt injection, tool poisoning, typosquatting, hidden zero-width unicode, schema abuse, cross-server collisions, privilege escalation, and hardcoded secrets.
- **MCP Gateway** — Runtime authorization layer for MCP tool calls with per-agent rate limiting and configurable allow/deny rules.
- **Agent Mesh** — Secure, trust-gated communication channels for multi-agent systems.
- **Circuit Breakers** — Automatic failure isolation for external service calls with configurable thresholds.
- **SLO Tracking** — Service Level Objective monitoring with error budget calculations.
- **Kill Switch** — Global emergency shutdown for all agent operations.
- **Rate Limiter** — Token bucket algorithm for controlling agent action throughput.
- **Observability Bus** — Pluggable event system for structured telemetry with built-in logging.
- **Compliance Attestation** — Machine-verifiable OWASP Agentic Top 10 attestation (JSON export).
- **Integrity Verification** — SHA-256 hash verification of governance module source files.
- **Framework Integrations** — Drop-in adapters for LangChain (callback handler), OpenAI Agents SDK (decorator), CrewAI (wrapper), and AutoGen (middleware).
- **CLI** — Command-line interface for policy management, testing, and MCP scanning.
- **Output PII/Secrets Filter** — Detects and redacts emails, phone numbers, SSNs, credit cards (Luhn-validated), AWS keys, GitHub tokens, JWTs, Stripe keys, private keys, DB connection strings, and generic API key patterns. Configurable actions: redact, block, warn, log. Recursive dict scanning. Custom pattern support.
- **Runtime Injection Detector** — Scans tool call arguments at runtime for prompt injection attacks: instruction overrides, delimiter injection (OpenAI/Llama/Gemma formats), role hijacking, data exfiltration, encoded payloads (base64, unicode tag smuggling), jailbreak attempts, and destructive commands. Compound scoring escalates risk when multiple attack types appear.
- **Web Dashboard** — Real-time dark-mode monitoring UI served from a zero-dependency embedded HTTP server. Shows live stats, event stream, violation tracker, policy viewer, and kill switch toggle. Bearer token auth on write operations.
- **169 tests** covering all modules.
- **CI/CD** — GitHub Actions workflows for testing, linting, type checking, and automated releases.
- **Pre-commit hook** — Policy YAML validation.
- **Full OWASP Agentic Top 10 coverage** (ASI-01 through ASI-10).

[0.1.0]: https://github.com/Aveerayy/agent-guard/releases/tag/v0.1.0
