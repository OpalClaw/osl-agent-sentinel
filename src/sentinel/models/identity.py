"""Agent identity model.

Agents authenticate to sentinel as DID-bound principals. Identities carry
a capability set, a trust tier, lineage information, and a behavioral
trust score that decays on violations.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class TrustTier(StrEnum):
    """Autonomy tier the agent currently operates in.

    Higher tiers permit broader action classes. Trust degradation
    automatically moves an identity down a tier.
    """

    OBSERVE = "observe"  # read-only, no side effects
    CONSTRAINED = "constrained"  # narrow tool set, low-risk only
    STANDARD = "standard"  # default for established agents
    ELEVATED = "elevated"  # broader access, still policy-gated
    PRIVILEGED = "privileged"  # reserved for explicitly-trusted agents


# --- Short-form aliases ----------------------------------------------------
# Many call-sites (and tests) use a generic LOW/MEDIUM/HIGH naming. We expose
# these as aliases of the canonical tier values so both spellings resolve to
# the same enum member.
TrustTier.BLOCKED = TrustTier.OBSERVE  # type: ignore[attr-defined]
TrustTier.UNTRUSTED = TrustTier.OBSERVE  # type: ignore[attr-defined]
TrustTier.LOW = TrustTier.CONSTRAINED  # type: ignore[attr-defined]
TrustTier.MEDIUM = TrustTier.STANDARD  # type: ignore[attr-defined]
TrustTier.HIGH = TrustTier.ELEVATED  # type: ignore[attr-defined]
TrustTier.TRUSTED = TrustTier.PRIVILEGED  # type: ignore[attr-defined]


class CapabilityGrant(BaseModel):
    """A single capability the identity holds."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    scope: str = "*"
    expires_at: datetime | None = None


# Public alias — the shorter spelling is used throughout the SDK, tests,
# and configuration files. Both names are first-class.
Capability = CapabilityGrant


class Identity(BaseModel):
    """A registered agent identity."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    did: str = Field(..., min_length=8, description="Decentralized identifier.")
    display_name: str = ""
    tenant_id: str = "default"
    public_key_jwk: dict[str, str] = Field(default_factory=dict)
    public_key_b64: str | None = Field(
        default=None,
        description="Base64-encoded raw Ed25519 public key (alternative to JWK).",
    )
    capabilities: list[CapabilityGrant] = Field(default_factory=list)
    tier: TrustTier = TrustTier.STANDARD
    trust_score: float = Field(0.75, ge=0.0, le=1.0)
    parent_did: str | None = Field(
        default=None,
        description="Lineage: the spawning agent or principal, if any.",
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    revoked: bool = False
    metadata: dict[str, str] = Field(default_factory=dict)

    def has_capability(self, name: str, scope: str | None = None) -> bool:
        """Return ``True`` if this identity currently holds the capability."""
        now = datetime.now(UTC)
        for cap in self.capabilities:
            if cap.name != name:
                continue
            if cap.expires_at is not None and cap.expires_at < now:
                continue
            if scope is None or cap.scope in ("*", scope):
                return True
        return False


__all__ = ["Capability", "CapabilityGrant", "Identity", "TrustTier"]
