"""Identity layer: DID resolution, trust scoring, action signing."""

from __future__ import annotations

from sentinel.identity.resolver import IdentityResolver, InMemoryIdentityStore
from sentinel.identity.signing import ActionSigner, ActionVerifier
from sentinel.identity.trust_scorer import TrustScorer

__all__ = [
    "ActionSigner",
    "ActionVerifier",
    "IdentityResolver",
    "InMemoryIdentityStore",
    "TrustScorer",
]
