"""Agent Mesh — secure agent-to-agent communication and discovery."""

from __future__ import annotations

import time
import threading
import hashlib
from collections import defaultdict
from typing import Any

from pydantic import BaseModel, Field

from agent_guard.identity.agent_id import AgentIdentity
from agent_guard.identity.trust import TrustEngine, TrustScore


class Message(BaseModel):
    """A message passed between agents through the mesh."""

    message_id: str = ""
    sender: str
    recipient: str
    channel: str = "default"
    content: Any = None
    content_type: str = "text"
    timestamp: float = Field(default_factory=time.time)
    signature: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class Channel(BaseModel):
    """A named communication channel in the mesh."""

    name: str
    description: str = ""
    allowed_agents: list[str] = Field(
        default_factory=list, description="Empty = all agents allowed"
    )
    min_trust_score: int = 0
    encrypted: bool = True
    created_at: float = Field(default_factory=time.time)


class AgentMesh:
    """Secure agent-to-agent communication network with trust gating.

    Usage:
        mesh = AgentMesh()

        # Register agents
        alice = AgentIdentity.create("alice", role="researcher")
        bob = AgentIdentity.create("bob", role="writer")
        mesh.register(alice)
        mesh.register(bob)

        # Create a channel
        mesh.create_channel("research", allowed_agents=["alice", "bob"])

        # Send messages
        mesh.send("alice", "bob", "Here are the results", channel="research")

        # Receive messages
        messages = mesh.receive("bob")

        # Broadcast
        mesh.broadcast("alice", "System update", channel="research")
    """

    def __init__(self, *, trust_engine: TrustEngine | None = None):
        self._agents: dict[str, AgentIdentity] = {}
        self._channels: dict[str, Channel] = {"default": Channel(name="default")}
        self._mailboxes: dict[str, list[Message]] = defaultdict(list)
        self._trust = trust_engine or TrustEngine()
        self._lock = threading.Lock()
        self._msg_counter = 0
        self._message_log: list[Message] = []

    def register(self, identity: AgentIdentity) -> None:
        """Register an agent in the mesh."""
        with self._lock:
            self._agents[identity.agent_id] = identity

    def unregister(self, agent_id: str) -> None:
        with self._lock:
            self._agents.pop(agent_id, None)

    def create_channel(
        self,
        name: str,
        *,
        description: str = "",
        allowed_agents: list[str] | None = None,
        min_trust_score: int = 0,
        encrypted: bool = True,
    ) -> Channel:
        """Create a named communication channel."""
        channel = Channel(
            name=name,
            description=description,
            allowed_agents=allowed_agents or [],
            min_trust_score=min_trust_score,
            encrypted=encrypted,
        )
        with self._lock:
            self._channels[name] = channel
        return channel

    def send(
        self,
        sender: str,
        recipient: str,
        content: Any,
        *,
        channel: str = "default",
        content_type: str = "text",
        metadata: dict[str, Any] | None = None,
    ) -> Message:
        """Send a message from one agent to another."""
        self._validate_access(sender, channel)
        self._validate_access(recipient, channel)

        with self._lock:
            self._msg_counter += 1
            msg = Message(
                message_id=f"msg-{self._msg_counter:06d}",
                sender=sender,
                recipient=recipient,
                channel=channel,
                content=content,
                content_type=content_type,
                metadata=metadata or {},
            )

            if sender in self._agents:
                identity = self._agents[sender]
                try:
                    data = f"{msg.sender}:{msg.recipient}:{msg.timestamp}".encode()
                    msg.signature = identity.sign(data).hex()
                except ValueError:
                    pass

            self._mailboxes[recipient].append(msg)
            self._message_log.append(msg)

        return msg

    def receive(
        self,
        agent_id: str,
        *,
        channel: str | None = None,
        clear: bool = True,
    ) -> list[Message]:
        """Retrieve messages for an agent."""
        with self._lock:
            messages = self._mailboxes.get(agent_id, [])
            if channel:
                messages = [m for m in messages if m.channel == channel]

            if clear:
                if channel:
                    self._mailboxes[agent_id] = [
                        m for m in self._mailboxes[agent_id] if m.channel != channel
                    ]
                else:
                    self._mailboxes[agent_id] = []

        return messages

    def broadcast(
        self,
        sender: str,
        content: Any,
        *,
        channel: str = "default",
        exclude_sender: bool = True,
    ) -> list[Message]:
        """Broadcast a message to all agents on a channel."""
        ch = self._channels.get(channel)
        if not ch:
            raise ValueError(f"Channel '{channel}' does not exist")

        targets = ch.allowed_agents if ch.allowed_agents else list(self._agents.keys())
        if exclude_sender:
            targets = [t for t in targets if t != sender]

        messages = []
        for recipient in targets:
            msg = self.send(sender, recipient, content, channel=channel)
            messages.append(msg)
        return messages

    def _validate_access(self, agent_id: str, channel: str) -> None:
        ch = self._channels.get(channel)
        if not ch:
            raise ValueError(f"Channel '{channel}' does not exist")
        if ch.allowed_agents and agent_id not in ch.allowed_agents:
            raise PermissionError(
                f"Agent '{agent_id}' is not allowed on channel '{channel}'"
            )
        if ch.min_trust_score > 0:
            score = self._trust.get_score(agent_id)
            if score.score < ch.min_trust_score:
                raise PermissionError(
                    f"Agent '{agent_id}' trust score ({score.score}) below "
                    f"channel minimum ({ch.min_trust_score})"
                )

    @property
    def agents(self) -> list[str]:
        return list(self._agents.keys())

    @property
    def channels(self) -> list[str]:
        return list(self._channels.keys())

    def pending_count(self, agent_id: str) -> int:
        return len(self._mailboxes.get(agent_id, []))

    def summary(self) -> dict[str, Any]:
        return {
            "registered_agents": len(self._agents),
            "channels": len(self._channels),
            "total_messages": len(self._message_log),
            "pending_messages": sum(len(v) for v in self._mailboxes.values()),
        }
