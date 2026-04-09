# Contributing to Agent Guard

Thank you for your interest in contributing to Agent Guard! We welcome contributions of all kinds.

## Getting Started

1. **Fork** the repository
2. **Clone** your fork: `git clone https://github.com/<your-username>/agent-guard.git`
3. **Install** in development mode: `pip install -e ".[dev]"`
4. **Run tests**: `pytest tests/ -v`

## Development Workflow

```bash
# Create a branch
git checkout -b feature/my-feature

# Make changes, then run tests
pytest tests/ -v

# Run linting
ruff check src/ tests/
ruff format src/ tests/

# Run type checking
mypy src/agent_guard/ --ignore-missing-imports

# Verify governance attestation
python -c "from agent_guard import GovernanceVerifier; print(GovernanceVerifier().summary())"
```

## What to Contribute

- **Bug fixes** — found something broken? Fix it!
- **New policy templates** — domain-specific policies (e.g., legal, education)
- **Framework integrations** — adapters for new agent frameworks
- **MCP scanner patterns** — new threat detection patterns
- **Documentation** — examples, tutorials, translations
- **Tests** — more coverage is always welcome

## Code Style

- We use **Ruff** for linting and formatting
- Type hints required for all public APIs
- Docstrings with usage examples for all public classes
- Tests for all new features

## Pull Request Process

1. Ensure all tests pass: `pytest tests/ -v`
2. Add tests for new functionality
3. Update README if adding user-facing features
4. Keep PRs focused — one feature per PR

## Architecture

```
src/agent_guard/
├── core/           # Policy engine, actions, Guard
├── identity/       # Agent ID, trust scoring
├── policies/       # Loaders, builtins, rate limiting
├── sandbox/        # Execution sandboxing
├── audit/          # Hash-chained audit logging
├── mesh/           # Agent-to-agent communication
├── mcp/            # MCP scanner, runtime gateway, injection detector
├── filters/        # Output PII/secrets filter & redaction
├── reliability/    # Circuit breakers, SLOs
├── compliance/     # OWASP attestation, integrity verification
├── observability/  # Telemetry hooks & metrics
├── dashboard/      # Real-time web monitoring UI
├── integrations/   # LangChain, OpenAI, CrewAI, AutoGen
└── cli/            # Command-line interface
```

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
