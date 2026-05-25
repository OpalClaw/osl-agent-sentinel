"""Canonical, deterministic JSON encoding for signing and hashing.

We use a single function across the codebase so that hashes and signatures
are byte-stable across processes, machines, and Python versions. The
encoder transparently handles integers outside the int64 range (which
``orjson`` rejects) by falling back to a stdlib ``json`` encoder with
sorted keys.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import orjson

_INT64_MIN = -(2**63)
_INT64_MAX = 2**63 - 1


def _has_oversized_int(value: Any) -> bool:
    """Walk ``value`` and return True if it contains an int outside int64."""
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value < _INT64_MIN or value > _INT64_MAX
    if isinstance(value, dict):
        return any(_has_oversized_int(k) or _has_oversized_int(v) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return any(_has_oversized_int(v) for v in value)
    return False


def canonical_bytes(value: Any) -> bytes:
    """Serialize ``value`` to canonical JSON bytes (sorted keys, no whitespace).

    Uses ``orjson`` for the common case (fast) and falls back to stdlib
    ``json`` when the input contains integers outside the int64 range,
    which ``orjson`` cannot serialize. The stdlib fallback preserves the
    same canonical contract: sorted keys, no whitespace, UTF-8 output.
    """
    try:
        return orjson.dumps(
            value,
            option=orjson.OPT_SORT_KEYS | orjson.OPT_NON_STR_KEYS | orjson.OPT_NAIVE_UTC,
        )
    except TypeError:
        if _has_oversized_int(value):
            return json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                default=str,
            ).encode("utf-8")
        raise


def sha256_hex(value: Any) -> str:
    """Return the SHA-256 hex digest of canonical bytes for ``value``."""
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def canonical_hash(value: Any) -> bytes:
    """Return the raw 32-byte SHA-256 digest of the canonical encoding."""
    return hashlib.sha256(canonical_bytes(value)).digest()
