"""
Example: Agent identity, cryptographic signatures, and trust scoring.
"""

from agent_guard import AgentIdentity, TrustEngine

# 1. Create agent identities
print("=== Agent Identities ===")
alice = AgentIdentity.create("alice", role="researcher")
bob = AgentIdentity.create("bob", role="writer")

print(f"Alice: {alice}")
print(f"Bob:   {bob}")

# 2. Sign and verify messages
print("\n=== Cryptographic Signatures ===")
message = b"Transfer approved for $10,000"
signature = alice.sign(message)
print(f"Alice signed message: {signature.hex()[:32]}...")
print(f"Verified by Alice: {alice.verify(message, signature)}")
print(f"Verified by Bob:   {bob.verify(message, signature)}")  # False

# 3. Sign JSON payloads
print("\n=== JSON Signing ===")
payload = {"action": "transfer", "amount": 10000, "to": "bob"}
signed = alice.sign_json(payload)
print(f"Signed by: {signed['signer']}")
print(f"Valid: {alice.verify_json(signed)}")

# 4. Trust scoring
print("\n=== Trust Scoring ===")
trust = TrustEngine()

# Alice does well
for _ in range(10):
    trust.record_success("alice")
print(f"Alice after 10 successes: {trust.get_score('alice')}")

# Bob has some failures
for _ in range(5):
    trust.record_success("bob")
trust.record_failure("bob")
trust.record_violation("bob")
print(f"Bob after mixed results: {trust.get_score('bob')}")

# Check trust
print(f"\nAlice trusted (min 500)? {trust.is_trusted('alice', min_score=500)}")
print(f"Bob trusted (min 500)?   {trust.is_trusted('bob', min_score=500)}")

# Summary
print(f"\nTrust summary: {trust.summary()}")
