"""
Example: Complete governance setup with all Agent Guard features.

This demonstrates policy enforcement, identity, trust, audit, mesh,
circuit breakers, and SLOs working together.
"""

from agent_guard import (
    Guard, Policy, AgentIdentity, TrustEngine, AuditLog,
    AgentMesh, CircuitBreaker, SLO, Sandbox, PermissionLevel,
)

# --- Setup ---

# Policy
guard = Guard(
    on_deny=lambda d: print(f"  [DENIED] {d.action_name}: {d.reason}"),
    on_audit=lambda d: print(f"  [AUDIT]  {d.action_name}: {d.reason}"),
)
guard.add_policy(Policy.standard())

# Identity
alice = AgentIdentity.create("alice", role="researcher")
bob = AgentIdentity.create("bob", role="writer")

# Trust
trust = TrustEngine()

# Audit
audit = AuditLog()

# Mesh
mesh = AgentMesh(trust_engine=trust)
mesh.register(alice)
mesh.register(bob)
mesh.create_channel("research", allowed_agents=["alice", "bob"])

# Reliability
breaker = CircuitBreaker("external-api", failure_threshold=3)
slo = SLO("agent-availability", target_percent=99.0)

# Sandbox
sandbox = Sandbox(permission_level=PermissionLevel.RESTRICTED)


# --- Simulation ---

print("=" * 60)
print("  Agent Guard — Full Governance Demo")
print("=" * 60)

# 1. Policy enforcement
print("\n📋 Policy Enforcement")
for action in ["web_search", "file_read", "database", "shell_exec", "code_exec"]:
    decision = guard.evaluate(action, agent_id="alice")
    audit.log_decision(decision)
    status = "✅" if decision.allowed else "🚫"
    print(f"  {status} {action}: {decision.effect.value}")
    if decision.allowed:
        trust.record_success("alice")
        slo.record_success()
    else:
        trust.record_violation("alice")
        slo.record_failure()

# 2. Agent communication
print("\n📡 Agent Mesh")
mesh.send("alice", "bob", "Here are the research results", channel="research")
messages = mesh.receive("bob", channel="research")
for msg in messages:
    print(f"  {msg.sender} → {msg.recipient}: {msg.content}")

# 3. Sandboxed execution
print("\n🔒 Sandbox Execution")
result = sandbox.exec_python("print('Hello from sandbox!')")
print(f"  Success: {result.success}")
print(f"  Output: {result.output.strip()}")

# 4. Circuit breaker
print("\n⚡ Circuit Breaker")
print(f"  State: {breaker.state.value}")
breaker.record_success()
breaker.record_success()
print(f"  After 2 successes: {breaker.stats()}")

# 5. SLO status
print("\n📊 SLO Status")
status = slo.status()
print(f"  Target: {slo.target.target_percent}%")
print(f"  Current: {status.current_value:.1f}%")
print(f"  Meeting target: {status.meeting_target}")
print(f"  Error budget: {status.error_budget_remaining:.1%}")

# 6. Trust scores
print("\n🔐 Trust Scores")
print(f"  Alice: {trust.get_score('alice')}")
print(f"  Bob:   {trust.get_score('bob')}")

# 7. Audit trail
print("\n📝 Audit Trail")
summary = audit.summary()
print(f"  Total events: {summary['total_events']}")
print(f"  Allowed: {summary['allowed']}")
print(f"  Denied: {summary['denied']}")
print(f"  Chain valid: {summary['chain_valid']}")

# 8. Kill switch
print("\n🛑 Kill Switch")
guard.activate_kill_switch()
decision = guard.evaluate("web_search", agent_id="alice")
print(f"  After activation — web_search allowed: {decision.allowed}")
guard.deactivate_kill_switch()
decision = guard.evaluate("web_search", agent_id="alice")
print(f"  After deactivation — web_search allowed: {decision.allowed}")

print("\n" + "=" * 60)
print("  Demo complete!")
print("=" * 60)
