"""Decision objects emitted by the sentinel pipeline."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class DecisionVerdict(str, Enum):
    """Terminal verdict the pipeline emits for an action."""

    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"
    THROTTLE = "throttle"


class RiskFactor(BaseModel):
    """A single contributing risk signal."""

    model_config = ConfigDict(frozen=True)

    code: str
    severity: float = Field(..., ge=0.0, le=1.0)
    detector: str
    message: str
    evidence: dict[str, str] = Field(default_factory=dict)


class DecisionExplanation(BaseModel):
    """Structured rationale attached to every decision.

    The shape is intentionally machine-readable: SIEMs, audit reviewers, and
    chat agents can all consume the same record.
    """

    model_config = ConfigDict(extra="forbid")

    summary: str
    triggered_rule_ids: list[str] = Field(default_factory=list)
    risk_factors: list[RiskFactor] = Field(default_factory=list)
    risk_score: float = Field(0.0, ge=0.0, le=1.0)
    recommended_remediation: str | None = None
    references: list[str] = Field(
        default_factory=list,
        description="External references such as OWASP IDs, CWEs, or docs URLs.",
    )


class Decision(BaseModel):
    """Final decision for an action."""

    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    action_id: UUID
    verdict: DecisionVerdict
    decided_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    decided_by: str = Field(
        default="sentinel.pipeline",
        description="Component that produced the verdict (pipeline, human reviewer, fallback).",
    )
    explanation: DecisionExplanation
    latency_ms: float | None = Field(
        default=None,
        description="Wall-clock time spent evaluating, in milliseconds.",
    )
    cache_hit: bool = False
    degraded: bool = Field(
        default=False,
        description="True if the decision was made while the pipeline was in fail-closed mode.",
    )

    @property
    def allowed(self) -> bool:
        """Convenience: whether the action may proceed without further gating."""
        return self.verdict == DecisionVerdict.ALLOW
