"""Cryptographic Memory Verification Kit.

Every memory write produces a signed :class:`MemoryReceipt` that the
agent's runtime stores alongside the data. On read, the receipt is
re-verified to detect tampering, replay, or substitution attacks against
the agent's long-term memory (OWASP-AGENT-02).
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sentinel.utils.canonical import canonical_bytes, sha256_hex
from sentinel.utils.crypto import sign, verify

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )


@dataclass(slots=True)
class MemoryReceipt:
    """A signed, verifiable receipt for a memory write."""

    id: UUID
    agent_did: str
    key: str
    digest_hex: str
    signature_b64: str
    issued_at: datetime
    version: int = 1


class CMVK:
    """Issue and verify memory receipts."""

    def __init__(self, private_key: Ed25519PrivateKey, public_key: Ed25519PublicKey) -> None:
        self._priv = private_key
        self._pub = public_key

    def issue(self, *, agent_did: str, key: str, value: object) -> MemoryReceipt:
        digest = sha256_hex({"key": key, "value": value, "agent_did": agent_did})
        body = canonical_bytes({"agent_did": agent_did, "key": key, "digest": digest})
        sig = sign(self._priv, body)
        return MemoryReceipt(
            id=uuid4(),
            agent_did=agent_did,
            key=key,
            digest_hex=digest,
            signature_b64=base64.b64encode(sig).decode("ascii"),
            issued_at=datetime.now(UTC),
        )

    def verify(self, receipt: MemoryReceipt, *, value: object) -> bool:
        expected = sha256_hex({"key": receipt.key, "value": value, "agent_did": receipt.agent_did})
        if expected != receipt.digest_hex:
            return False
        body = canonical_bytes(
            {"agent_did": receipt.agent_did, "key": receipt.key, "digest": receipt.digest_hex}
        )
        try:
            sig = base64.b64decode(receipt.signature_b64)
        except (ValueError, TypeError):
            return False
        return verify(self._pub, sig, body)
