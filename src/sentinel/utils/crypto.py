"""Cryptographic primitives used across the project.

We deliberately keep this surface narrow:

* Ed25519 sign/verify for policy bundles, audit records, and IATP messages.
* SHA-256 for hashing.
* HKDF for derived secrets.
* Constant-time comparison helpers.

All key material is handled as immutable bytes. We never log or repr keys.
"""

from __future__ import annotations

import hmac
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def load_ed25519_private(path: str | Path) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from a PEM file."""
    data = Path(path).read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(f"{path} is not an Ed25519 private key")
    return key


def load_ed25519_public(path: str | Path) -> Ed25519PublicKey:
    """Load an Ed25519 public key from a PEM file."""
    data = Path(path).read_bytes()
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError(f"{path} is not an Ed25519 public key")
    return key


def sign(private_key: Ed25519PrivateKey, payload: bytes) -> bytes:
    """Return a detached Ed25519 signature over ``payload``."""
    return private_key.sign(payload)


def verify(public_key: Ed25519PublicKey, signature: bytes, payload: bytes) -> bool:
    """Verify a detached Ed25519 signature. Returns ``False`` on mismatch."""
    try:
        public_key.verify(signature, payload)
    except Exception:
        return False
    return True


def derive_key(secret: bytes, *, info: bytes, length: int = 32, salt: bytes | None = None) -> bytes:
    """Derive a sub-key using HKDF-SHA256."""
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(secret)


def constant_time_equals(a: bytes, b: bytes) -> bool:
    """Constant-time equality check."""
    return hmac.compare_digest(a, b)


def generate_ed25519_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a fresh Ed25519 keypair.

    Returns
    -------
    tuple
        ``(private_key, public_key)``. The public key is derived from the
        private key — callers MUST treat the private key as a secret and
        store only the public key in any logged or networked artifact.
    """
    private = Ed25519PrivateKey.generate()
    return private, private.public_key()
