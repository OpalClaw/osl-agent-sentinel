"""Behavioral trust scoring.

Each identity carries a ``trust_score`` in ``[0, 1]``. The scorer applies
multiplicative decay on policy violations / anomalies, and slow linear
recovery on clean activity. The score gates the identity's
:class:`TrustTier`, which in turn limits what actions the policy engine
allows.
"""

from __future__ import annotations

from sentinel.models.decision import DecisionVerdict, RiskFactor
from sentinel.models.identity import Identity, TrustTier

# Tier thresholds — descending.
_TIER_BANDS: list[tuple[float, TrustTier]] = [
    (0.90, TrustTier.PRIVILEGED),
    (0.70, TrustTier.ELEVATED),
    (0.50, TrustTier.STANDARD),
    (0.25, TrustTier.CONSTRAINED),
    (0.0, TrustTier.OBSERVE),
]


class TrustScorer:
    """Stateless trust adjustment given recent risk factors and verdict."""

    def __init__(
        self,
        *,
        deny_penalty: float = 0.20,
        escalate_penalty: float = 0.08,
        throttle_penalty: float = 0.03,
        clean_recovery: float = 0.005,
    ) -> None:
        self._deny = deny_penalty
        self._escalate = escalate_penalty
        self._throttle = throttle_penalty
        self._recovery = clean_recovery

    def adjust(
        self,
        identity: Identity | None,
        risk_factors: list[RiskFactor],
        verdict: DecisionVerdict,
    ) -> Identity | None:
        if identity is None:
            return None

        score = identity.trust_score
        if verdict == DecisionVerdict.DENY:
            score -= self._deny
        elif verdict == DecisionVerdict.ESCALATE:
            score -= self._escalate
        elif verdict == DecisionVerdict.THROTTLE:
            score -= self._throttle
        else:
            score += self._recovery if not risk_factors else 0.0

        score = max(0.0, min(1.0, score))
        tier = _resolve_tier(score)
        return identity.model_copy(update={"trust_score": round(score, 4), "tier": tier})


def _resolve_tier(score: float) -> TrustTier:
    for threshold, tier in _TIER_BANDS:
        if score >= threshold:
            return tier
    return TrustTier.OBSERVE
