"""Canonical, deterministic JSON encoding for signing and hashing.

We use a single function across the codebase so that hashes and signatures
are byte-stable across processes, machines, and Python versions.
"""

from __future__ import annotations

import hashlib
from typing import Any

import orjson


def canonical_bytes(value: Any) -> bytes:
    """Serialize ``value`` to canonical JSON bytes (sorted keys, no whitespace)."""
    return orjson.dumps(
        value,
        option=orjson.OPT_SORT_KEYS | orjson.OPT_NON_STR_KEYS | orjson.OPT_NAIVE_UTC,
    )


def sha256_hex(value: Any) -> str:
    """Return the SHA-256 hex digest of canonical bytes for ``value``."""
    return hashlib.sha256(canonical_bytes(value)).hexdigest()
