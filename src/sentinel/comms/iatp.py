"""Inter-Agent Transport Protocol (IATP).

A minimal, signed message envelope that two agents can use to communicate
through sentinel. Every envelope is signed by the sender's DID-bound key,
contains a monotonic nonce per conversation, and carries the sender's
declared intent for downstream verification.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

from sentinel.utils.canonical import canonical_bytes
from sentinel.utils.crypto import sign, verify

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )


class IATPEnvelope(BaseModel):
    """One signed inter-agent message."""

    model_config = ConfigDict(extra="forbid")

    sender_did: str
    recipient_did: str
    conversation_id: str
    nonce: int = Field(..., ge=0)
    issued_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    intent: str
    body: dict[str, Any]
    signature_b64: str | None = None

    def canonical_body(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"signature_b64"})


class IATPTransport:
    """Sign and verify IATP envelopes."""

    def __init__(self, private_key: Ed25519PrivateKey, public_key: Ed25519PublicKey) -> None:
        self._priv = private_key
        self._pub = public_key

    def seal(self, envelope: IATPEnvelope) -> IATPEnvelope:
        sig = sign(self._priv, canonical_bytes(envelope.canonical_body()))
        return envelope.model_copy(update={"signature_b64": base64.b64encode(sig).decode("ascii")})

    def verify(self, envelope: IATPEnvelope, *, public_key: Ed25519PublicKey | None = None) -> bool:
        if envelope.signature_b64 is None:
            return False
        try:
            sig = base64.b64decode(envelope.signature_b64)
        except (ValueError, TypeError):
            return False
        return verify(public_key or self._pub, sig, canonical_bytes(envelope.canonical_body()))
