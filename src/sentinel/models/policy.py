"""Policy model.

A :class:`PolicyBundle` is a signed, versioned collection of
:class:`PolicyRule` objects. Bundles are loaded at startup and may be
hot-reloaded when a new signed version is published.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RuleEffect(StrEnum):
    """The effect a matching rule has on the action."""

    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"
    THROTTLE = "throttle"


class PolicyRule(BaseModel):
    """A single evaluable rule."""

    model_config = ConfigDict(extra="ignore")

    id: str
    description: str = ""
    effect: RuleEffect
    priority: int = Field(100, ge=0, le=10_000)
    enabled: bool = True
    # Match expressions are intentionally restricted to a small language so they
    # can be evaluated quickly and audited statically. See docs/POLICY-LANGUAGE.md.
    match: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    rationale: str | None = None
    owasp_ids: list[str] = Field(default_factory=list)


class PolicyBundle(BaseModel):
    """A signed, versioned set of rules."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    version: str
    issued_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    issuer: str = ""
    bundle_id: str = ""
    rules: list[PolicyRule]
    signature: str | None = Field(
        default=None,
        description="Detached signature over canonical bundle content.",
    )
    tenant_id: str | None = Field(
        default=None,
        description="If set, this bundle is scoped to one tenant.",
    )

    def by_priority(self) -> list[PolicyRule]:
        """Return enabled rules sorted by priority ascending (lower = earlier)."""
        return sorted([r for r in self.rules if r.enabled], key=lambda r: r.priority)
