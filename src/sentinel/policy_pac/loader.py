"""Policy bundle loader.

Reads a signed YAML/JSON bundle from disk (or any path-like store) and
yields a typed :class:`PolicyBundle`. Verifies the Ed25519 signature when
a public key is supplied. Supports hot-reload via the ``reload()`` method.
"""

from __future__ import annotations

import base64
from pathlib import Path

import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from sentinel.models.policy import PolicyBundle
from sentinel.utils.canonical import canonical_bytes
from sentinel.utils.crypto import verify
from sentinel.utils.errors import PolicyError
from sentinel.utils.logging import get_logger

log = get_logger(__name__)


def load_bundle_from_path(path: str | Path, *, public_key: Ed25519PublicKey | None = None) -> PolicyBundle:
    """Read and (optionally) verify a policy bundle."""

    raw = Path(path).read_text(encoding="utf-8")
    if str(path).endswith((".yaml", ".yml")):
        data = yaml.safe_load(raw)
    else:
        import json

        data = json.loads(raw)

    if not isinstance(data, dict):
        raise PolicyError(f"Policy file {path} must be a mapping")

    signature_b64 = data.pop("signature", None)
    bundle = PolicyBundle.model_validate(data)

    if public_key is not None:
        if not signature_b64:
            raise PolicyError("Public key supplied but bundle has no signature")
        try:
            sig = base64.b64decode(signature_b64)
        except (ValueError, TypeError) as exc:
            raise PolicyError("Bundle signature is not valid base64") from exc
        if not verify(public_key, sig, canonical_bytes(bundle.model_dump(mode="json"))):
            raise PolicyError("Bundle signature verification failed")
        log.info("policy.verified", version=bundle.version, rules=len(bundle.rules))

    return bundle


class PolicyLoader:
    """Holds the active bundle and supports hot reload."""

    def __init__(self, path: str | Path, *, public_key: Ed25519PublicKey | None = None) -> None:
        self._path = Path(path)
        self._public_key = public_key
        self._bundle: PolicyBundle | None = None

    @property
    def bundle(self) -> PolicyBundle:
        if self._bundle is None:
            raise PolicyError("Policy bundle not loaded; call reload() first")
        return self._bundle

    def reload(self) -> PolicyBundle:
        new_bundle = load_bundle_from_path(self._path, public_key=self._public_key)
        old_version = self._bundle.version if self._bundle else "<none>"
        self._bundle = new_bundle
        log.info("policy.reload", old=old_version, new=new_bundle.version)
        return new_bundle
