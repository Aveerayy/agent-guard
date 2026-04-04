"""Tests for agent mesh communication."""

import pytest
from agent_guard import AgentIdentity, AgentMesh, TrustEngine


class TestAgentMesh:
    def setup_method(self):
        self.mesh = AgentMesh()
        self.alice = AgentIdentity.create("alice", role="researcher")
        self.bob = AgentIdentity.create("bob", role="writer")
        self.mesh.register(self.alice)
        self.mesh.register(self.bob)

    def test_send_and_receive(self):
        self.mesh.send("alice", "bob", "hello")
        messages = self.mesh.receive("bob")
        assert len(messages) == 1
        assert messages[0].content == "hello"
        assert messages[0].sender == "alice"

    def test_receive_clears_mailbox(self):
        self.mesh.send("alice", "bob", "hello")
        self.mesh.receive("bob")
        assert self.mesh.receive("bob") == []

    def test_channel_access_control(self):
        self.mesh.create_channel("private", allowed_agents=["alice"])
        self.mesh.send("alice", "alice", "note", channel="private")
        with pytest.raises(PermissionError):
            self.mesh.send("bob", "alice", "blocked", channel="private")

    def test_broadcast(self):
        self.mesh.create_channel("all", allowed_agents=["alice", "bob"])
        messages = self.mesh.broadcast("alice", "update", channel="all")
        assert len(messages) == 1  # bob only (excludes sender)
        assert self.mesh.pending_count("bob") == 1

    def test_trust_gated_channel(self):
        trust = TrustEngine(initial_score=100)
        mesh = AgentMesh(trust_engine=trust)
        mesh.register(self.alice)
        mesh.create_channel("secure", min_trust_score=500)
        with pytest.raises(PermissionError, match="trust score"):
            mesh.send("alice", "alice", "test", channel="secure")

    def test_unknown_channel(self):
        with pytest.raises(ValueError, match="does not exist"):
            self.mesh.send("alice", "bob", "test", channel="nonexistent")

    def test_summary(self):
        self.mesh.send("alice", "bob", "hello")
        summary = self.mesh.summary()
        assert summary["registered_agents"] == 2
        assert summary["total_messages"] == 1

    def test_agents_list(self):
        assert "alice" in self.mesh.agents
        assert "bob" in self.mesh.agents
