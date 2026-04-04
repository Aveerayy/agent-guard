"""
Example: Define governance policies in YAML and load them.
"""

from agent_guard import Guard, Policy

# Load from a YAML string
policy = Policy.from_yaml_string("""
name: my-custom-policy
description: "Custom policy for my AI agent"
default_effect: deny

rules:
  - name: allow_search
    action: web_search
    effect: allow
    reason: "Search is core functionality"

  - name: allow_read
    action: file_read
    effect: allow
    reason: "Reading is safe"

  - name: audit_api
    action: api_call
    effect: audit
    reason: "API calls are logged"

  - name: block_dangerous
    action: "*"
    effect: deny
    priority: -1
    reason: "Everything else is blocked"
""")

guard = Guard()
guard.add_policy(policy)

print("=== Custom YAML Policy ===")
for action in ["web_search", "file_read", "api_call", "shell_exec", "file_write"]:
    decision = guard.evaluate(action)
    status = "✅" if decision.allowed else "🚫"
    print(f"  {status} {action}: {decision.effect.value} — {decision.reason}")
