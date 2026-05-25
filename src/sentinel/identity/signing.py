"""Ed25519 action signing and verification.

Agents may submit signed actions whose payload digest is bound to their
DID's public key. The signer and verifier are deliberately side-effect
free so callers can manage key storage however they want.
"""

from __future__ import annotations

import base64
import hashlib
from typing import TYPE_CHECKING, Any

from sentinel.utils.canonical import canonical_bytes
from sentinel.utils.crypto import sign, verify

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    from sentinel.models.action import Action


class SignedAction:
    """An :class:`Action` paired with its signature and key identifier.

    The class exposes ``action`` plus a small mutable surface (``args``)
    so callers can construct adversarial tests that mutate the payload
    after signing; the verifier MUST reject any such mutation.
    """

    __slots__ = ("action", "key_id", "signature_b64")

    def __init__(self, action: Action, signature_b64: str, key_id: str) -> None:
        self.action = action
        self.signature_b64 = signature_b64
        self.key_id = key_id

    @property
    def args(self) -> dict[str, Any]:
        return dict(self.action.arguments)

    @args.setter
    def args(self, value: dict[str, Any]) -> None:
        # We deliberately construct a new Action so the canonical encoding
        # changes — that is exactly how a verifier detects tampering.
        self.action = self.action.model_copy(update={"arguments": dict(value)})


def _fingerprint(public_key: Ed25519PublicKey) -> str:
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )

    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return "k_" + hashlib.sha256(raw).hexdigest()[:16]


class ActionSigner:
    """Sign action payloads with an Ed25519 private key.

    The ``key_id`` is optional. When omitted, the signer derives a short
    deterministic identifier from the public key fingerprint so signed
    payloads are still attributable.
    """

    def __init__(self, key: Ed25519PrivateKey, key_id: str | None = None) -> None:
        self._key = key
        self._key_id = key_id or _fingerprint(key.public_key())

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, action: Action) -> SignedAction:
        payload = canonical_bytes(action.model_dump(mode="json", by_alias=True))
        sig = sign(self._key, payload)
        return SignedAction(
            action=action,
            signature_b64=base64.b64encode(sig).decode("ascii"),
            key_id=self._key_id,
        )


class ActionVerifier:
    """Verify an Ed25519 signature over a canonical action payload.

    The public key is supplied at verify time so a single verifier can
    handle actions signed by many identities — typical in a multi-tenant
    control plane where each agent has its own key.
    """

    def verify(self, signed: SignedAction, public_key: Ed25519PublicKey) -> bool:
        try:
            sig = base64.b64decode(signed.signature_b64)
        except (ValueError, TypeError):
            return False
        payload = canonical_bytes(signed.action.model_dump(mode="json", by_alias=True))
        return verify(public_key, sig, payload)


__all__ = ["ActionSigner", "ActionVerifier", "SignedAction"]
