"""Tests for identity and trust systems."""

from agent_guard import AgentIdentity, TrustEngine


class TestAgentIdentity:
    def test_create(self):
        identity = AgentIdentity.create("test-agent", role="tester")
        assert identity.agent_id == "test-agent"
        assert identity.role == "tester"
        assert identity.public_key_hex

    def test_sign_and_verify(self):
        identity = AgentIdentity.create("signer")
        data = b"test message"
        sig = identity.sign(data)
        assert identity.verify(data, sig)

    def test_verify_wrong_data_fails(self):
        identity = AgentIdentity.create("signer")
        sig = identity.sign(b"original")
        assert not identity.verify(b"tampered", sig)

    def test_cross_identity_verify_fails(self):
        alice = AgentIdentity.create("alice")
        bob = AgentIdentity.create("bob")
        sig = alice.sign(b"message")
        assert not bob.verify(b"message", sig)

    def test_fingerprint(self):
        identity = AgentIdentity.create("test")
        fp = identity.fingerprint()
        assert len(fp) == 16

    def test_to_card(self):
        identity = AgentIdentity.create("test", role="admin")
        card = identity.to_card()
        assert card["agent_id"] == "test"
        assert card["role"] == "admin"
        assert "public_key" in card
        assert "fingerprint" in card

    def test_sign_json(self):
        identity = AgentIdentity.create("test")
        payload = {"action": "transfer", "amount": 100}
        signed = identity.sign_json(payload)
        assert signed["signer"] == "test"
        assert identity.verify_json(signed)

    def test_export_private_key(self):
        identity = AgentIdentity.create("test")
        pem = identity.export_private_key_pem()
        assert "BEGIN PRIVATE KEY" in pem


class TestTrustEngine:
    def test_initial_score(self):
        trust = TrustEngine()
        score = trust.get_score("agent-1")
        assert score.score == 500
        assert score.level == "medium"

    def test_success_increases_score(self):
        trust = TrustEngine()
        trust.record_success("agent-1")
        assert trust.get_score("agent-1").score > 500

    def test_failure_decreases_score(self):
        trust = TrustEngine()
        trust.record_failure("agent-1")
        assert trust.get_score("agent-1").score < 500

    def test_violation_large_penalty(self):
        trust = TrustEngine()
        score_before = trust.get_score("agent-1").score
        trust.record_violation("agent-1")
        score_after = trust.get_score("agent-1").score
        assert score_before - score_after == 50

    def test_is_trusted(self):
        trust = TrustEngine()
        assert trust.is_trusted("agent-1", min_score=500)
        trust.record_violation("agent-1")
        trust.record_violation("agent-1")
        assert not trust.is_trusted("agent-1", min_score=500)

    def test_score_capped_at_1000(self):
        trust = TrustEngine(initial_score=990)
        trust.record_success("agent-1")
        trust.record_success("agent-1")
        assert trust.get_score("agent-1").score == 1000

    def test_score_floors_at_0(self):
        trust = TrustEngine(initial_score=10)
        trust.record_violation("agent-1")
        assert trust.get_score("agent-1").score == 0

    def test_level_transitions(self):
        trust = TrustEngine(initial_score=800)
        assert trust.get_score("agent-1").level == "high"
        trust.set_score("agent-1", 300)
        assert trust.get_score("agent-1").level == "low"
        trust.set_score("agent-1", 100)
        assert trust.get_score("agent-1").level == "untrusted"

    def test_summary(self):
        trust = TrustEngine()
        trust.record_success("a")
        trust.record_failure("b")
        summary = trust.summary()
        assert summary["agents"] == 2
