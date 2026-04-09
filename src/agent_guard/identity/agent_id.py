"""Agent identity — cryptographic credentials and identity management."""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from pydantic import BaseModel, Field


class AgentIdentity(BaseModel):
    """Represents a verified agent identity with cryptographic backing.

    Usage:
        # Create a new identity
        identity = AgentIdentity.create("my-agent", role="researcher")

        # Sign and verify messages
        signature = identity.sign(b"hello")
        assert identity.verify(b"hello", signature)

        # Export for registration
        card = identity.to_card()
    """

    agent_id: str
    display_name: str = ""
    role: str = "default"
    public_key_hex: str = ""
    created_at: float = Field(default_factory=time.time)
    metadata: dict[str, Any] = Field(default_factory=dict)
    _private_key: Ed25519PrivateKey | None = None

    model_config = {"arbitrary_types_allowed": True}

    @classmethod
    def create(
        cls,
        agent_id: str,
        *,
        display_name: str = "",
        role: str = "default",
        metadata: dict[str, Any] | None = None,
    ) -> AgentIdentity:
        """Generate a new identity with a fresh Ed25519 keypair."""
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        pub_hex = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

        identity = cls(
            agent_id=agent_id,
            display_name=display_name or agent_id,
            role=role,
            public_key_hex=pub_hex,
            metadata=metadata or {},
        )
        identity._private_key = private_key
        return identity

    def sign(self, data: bytes) -> bytes:
        """Sign data with this identity's private key."""
        if not self._private_key:
            raise ValueError("Cannot sign: no private key (this may be a public-only identity)")
        return self._private_key.sign(data)

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify a signature against this identity's public key."""
        pub_key = self._get_public_key()
        try:
            pub_key.verify(signature, data)
            return True
        except Exception:
            return False

    def fingerprint(self) -> str:
        """Short SHA-256 fingerprint of the public key."""
        return hashlib.sha256(bytes.fromhex(self.public_key_hex)).hexdigest()[:16]

    def to_card(self) -> dict[str, Any]:
        """Export as a shareable identity card (no private key)."""
        return {
            "agent_id": self.agent_id,
            "display_name": self.display_name,
            "role": self.role,
            "public_key": self.public_key_hex,
            "fingerprint": self.fingerprint(),
            "created_at": self.created_at,
            "metadata": self.metadata,
        }

    def export_private_key_pem(self) -> str:
        if not self._private_key:
            raise ValueError("No private key available")
        return self._private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        ).decode()

    def _get_public_key(self) -> Ed25519PublicKey:
        if self._private_key:
            return self._private_key.public_key()
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        return Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.public_key_hex))

    def sign_json(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Sign a JSON payload, returning {payload, signature}."""
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        sig = self.sign(canonical)
        return {"payload": payload, "signature": sig.hex(), "signer": self.agent_id}

    def verify_json(self, signed: dict[str, Any]) -> bool:
        """Verify a signed JSON payload."""
        canonical = json.dumps(signed["payload"], sort_keys=True, separators=(",", ":")).encode()
        return self.verify(canonical, bytes.fromhex(signed["signature"]))

    def __repr__(self) -> str:
        return f"AgentIdentity(id={self.agent_id!r}, role={self.role!r}, fp={self.fingerprint()})"
