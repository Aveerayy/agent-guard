"""
Agent Guard — Quickstart Example

Get from zero to governed agents in 60 seconds.
"""

from agent_guard import Guard, Policy

# 1. Create a guard with a built-in policy
guard = Guard()
guard.add_policy(Policy.standard())

# 2. Check actions — simple boolean
print("=== Simple Checks ===")
print(f"web_search allowed?  {guard.check('web_search')}")      # True
print(f"file_read allowed?   {guard.check('file_read')}")       # True
print(f"shell_exec allowed?  {guard.check('shell_exec')}")      # False
print(f"file_write allowed?  {guard.check('file_write')}")      # False

# 3. Full evaluation with details
print("\n=== Detailed Evaluation ===")
decision = guard.evaluate("shell_exec", agent_id="my-agent")
print(f"Allowed: {decision.allowed}")
print(f"Effect:  {decision.effect}")
print(f"Rule:    {decision.matched_rule}")
print(f"Reason:  {decision.reason}")
print(f"Time:    {decision.evaluation_time_ms:.4f} ms")

# 4. Use the decorator
print("\n=== Decorator ===")

@guard.govern("web_search")
def search(query: str) -> str:
    return f"Results for: {query}"

print(search(query="AI governance"))

# 5. Use sessions for agent-scoped checks
print("\n=== Sessions ===")
with guard.session("researcher-agent") as session:
    print(f"Can search: {session.check('web_search')}")
    print(f"Can read:   {session.check('file_read')}")
    print(f"Can exec:   {session.check('shell_exec')}")

# 6. View stats
print("\n=== Stats ===")
for key, value in guard.stats().items():
    print(f"  {key}: {value}")
