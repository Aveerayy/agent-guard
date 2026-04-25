# Changelog

All notable changes to Agent Guard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-04-25

### Added

- **Central MCP Gateway Server** (`agent_guard.server`) — Enterprise-grade, centrally-deployed MCP proxy server. Teams point their MCP clients (Cursor, Claude Desktop, custom agents) at the gateway URL; every tool call flows through the full governance stack automatically. Zero code changes per team — just a config change.
  - `server/config.py` — YAML-based configuration for upstream MCP servers, team definitions, policies, and database settings. Supports `${VAR}` environment variable expansion.
  - `server/auth.py` — Team authentication via Bearer tokens with SHA-256 hashed storage. Supports anonymous fallback when no teams are configured.
  - `server/store.py` — PostgreSQL persistence layer (`PgAuditLog`, `PgTokenInventory`) extending in-memory classes with async database writes via `asyncpg`. Falls back gracefully to in-memory when no database is available.
  - `server/teams.py` — Multi-tenant team registry with per-team `Guard` + `MCPGateway` instances, policy template resolution (`standard`, `permissive`, `restrictive`), per-team and global kill switch.
  - `server/proxy.py` — MCP proxy core managing upstream connections (stdio subprocesses and HTTP), tool aggregation with `upstream/tool_name` prefixing, and governance-gated forwarding.
  - `server/app.py` — FastAPI application exposing Streamable HTTP MCP endpoint (`POST /mcp`), org-wide dashboard APIs (`/api/overview`, `/api/teams`, `/api/tokens`, etc.), kill switch endpoints, and health checks.
- **`agent-guard server` CLI** — New command group: `agent-guard server run -c gateway.yaml` (start the gateway), `agent-guard server init` (generate starter config).
- **Server optional dependencies** — `pip install agent-guard[server]` installs `fastapi`, `uvicorn`, `asyncpg`, `httpx`.
- **`team_id` field** added to `AuditEvent` and `TokenRecord` for multi-tenant support (backward-compatible, defaults to `""`).
- **Token Governance** (`agent_guard.tokens`) — Discover, inventory, risk-score, and enforce policy on every access token in your AI agent environment. Includes `TokenScanner` (env vars, `.env` files, MCP configs, runtime tool args/outputs), `TokenInventory` (dedup registry with usage tracking), `RiskScorer` (5-factor weighted scoring: provider criticality, privilege scope, age, exposure, breadth), and `TokenPolicy` (max age, rotation, sharing limits, provider deny-lists, inline credential alerts).
- **MCPGateway token tracking** — `MCPGateway` accepts optional `token_inventory` parameter; `authorize()` now automatically scans tool arguments for credentials and tracks which agents/tools use which tokens at runtime.
- **Dashboard token endpoints** — New `/api/tokens`, `/api/tokens/summary`, `/api/tokens/stale` API endpoints and `token_inventory` parameter for `run_dashboard()`.
- **`agent-guard tokens` CLI** — New command group: `agent-guard tokens scan` (discover tokens), `agent-guard tokens list` (with `--risk`, `--provider`, `--stale` filters).
- **73 new server tests** + 72 token governance tests (314 total).

### Changed

- **Integrity verifier** expanded from 20 to 26 governance modules (added 6 server modules).
- **`__init__.py`** now exports `TokenInventory`, `TokenRecord`, `TokenScanner`, `TokenPolicy`, `RiskScorer`, `RiskLevel`, `TokenStatus`.

## [0.2.0] - 2026-04-09

### Added

- **Output PII/Secrets Filter** (`agent_guard.filters.output_filter`) — Detects and redacts emails, phone numbers, SSNs, credit cards (Luhn-validated), internal IPs, AWS keys, GitHub tokens, Google API keys, Slack tokens, Stripe keys, JWTs, private keys, DB connection strings, and generic API key patterns. Configurable actions: redact, block, warn, log. Recursive dict scanning. Custom pattern support.
- **Runtime Injection Detector** (`agent_guard.mcp.injection_detector`) — Scans tool call arguments at runtime for prompt injection attacks: instruction overrides, delimiter injection (OpenAI/Llama/Gemma chat template tokens), role hijacking, data exfiltration, encoded payloads (base64, unicode tag smuggling), jailbreak attempts (DAN, filter bypass), urgency manipulation, and destructive commands. Compound scoring escalates risk when multiple attack types appear in one call.
- **Web Dashboard** (`agent_guard.dashboard`) — Real-time dark-mode monitoring UI served from a zero-dependency embedded HTTP server. Live stats, event stream, violation tracker, policy viewer, and kill switch toggle. Auto-refreshes every 2 seconds. Bearer token auth on write operations.
- **`agent-guard dashboard` CLI command** — Launch the dashboard from the command line.
- **`python -m agent_guard`** — Root `__main__.py` for direct module invocation.
- **Gateway output filtering** — `MCPGateway.filter_output()` and `filter_output_dict()` for scanning tool responses through the output filter.
- **Gateway injection detection** — Automatic injection scanning on every `MCPGateway.authorize()` call when `detect_injection=True`.

### Changed

- **ASI-05 control** now references `OutputFilter` instead of audit logging for Insecure Output Handling coverage.
- **Integrity verifier** expanded from 10 to 16 governance modules.
- **CI matrix** now tests Python 3.9 through 3.13 (previously 3.10+).
- **CI pipeline** adds `pip-audit` dependency vulnerability scanning.

### Fixed

- **CLI entry point** — `pyproject.toml` script pointed to `agent_guard.cli:main` (missing); corrected to `agent_guard.cli.app:main`.
- **Dashboard security** — Kill switch POST endpoints now require Bearer token authentication. Removed wildcard CORS header.
- **Dead imports** — Removed unused `hashlib` and `TrustScore` imports from `mesh/network.py`.

### Security

- Dashboard binds to `127.0.0.1` only by default, with Bearer token auth required for write operations.
- Output filter detects 14 categories of sensitive data with Luhn validation for credit cards.
- Injection detector catches 9 categories of prompt injection with base64 and unicode tag smuggling decoding.
- Added `pip-audit --strict` to CI for automated dependency vulnerability scanning.

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

[0.3.0]: https://github.com/Aveerayy/agent-guard/releases/tag/v0.3.0
[0.2.0]: https://github.com/Aveerayy/agent-guard/releases/tag/v0.2.0
[0.1.0]: https://github.com/Aveerayy/agent-guard/releases/tag/v0.1.0
