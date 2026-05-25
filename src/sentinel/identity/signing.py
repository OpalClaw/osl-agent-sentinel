"""Ed25519 action signing and verification.

Agents may submit signed actions whose payload digest is bound to their
DID's public key. The signer and verifier here are deliberately
side-effect free so callers can manage key storage as they see fit.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from sentinel.models.action import Action
from sentinel.utils.canonical import canonical_bytes
from sentinel.utils.crypto import sign, verify


@dataclass(slots=True)
class SignedAction:
    """An :class:`Action` paired with its signature and key identifier."""

    action: Action
    signature_b64: str
    key_id: str


class ActionSigner:
    """Sign action payloads with an Ed25519 private key."""

    def __init__(self, key: Ed25519PrivateKey, key_id: str) -> None:
        self._key = key
        self._key_id = key_id

    def sign(self, action: Action) -> SignedAction:
        payload = canonical_bytes(action.canonical_dict())
        sig = sign(self._key, payload)
        return SignedAction(
            action=action,
            signature_b64=base64.b64encode(sig).decode("ascii"),
            key_id=self._key_id,
        )


class ActionVerifier:
    """Verify an Ed25519 signature over a canonical action payload."""

    def __init__(self, key: Ed25519PublicKey) -> None:
        self._key = key

    def verify(self, signed: SignedAction) -> bool:
        try:
            sig = base64.b64decode(signed.signature_b64)
        except (ValueError, TypeError):
            return False
        payload = canonical_bytes(signed.action.canonical_dict())
        return verify(self._key, sig, payload)
