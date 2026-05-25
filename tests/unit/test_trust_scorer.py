"""Unit tests for trust scoring."""

from __future__ import annotations

from sentinel.identity.trust_scorer import TrustScorer
from sentinel.models.decision import DecisionVerdict, RiskFactor
from sentinel.models.identity import Capability, Identity, TrustTier


def _id(score: float = 0.5, tier: TrustTier = TrustTier.MEDIUM) -> Identity:
    return Identity(
        did="did:test:t",
        public_key_b64="A" * 43 + "=",
        tier=tier,
        capabilities=[Capability(name="x")],
        trust_score=score,
    )


def test_clean_run_recovers_score():
    s = TrustScorer()
    identity = _id(score=0.4)
    new_score = s.observe(identity, DecisionVerdict.ALLOW, risk_factors=[])
    assert new_score > 0.4


def test_violation_decays_score():
    s = TrustScorer()
    identity = _id(score=0.9)
    new_score = s.observe(
        identity,
        DecisionVerdict.DENY,
        risk_factors=[RiskFactor(code="intent.mismatch", score=0.9, source="intent")],
    )
    assert new_score < 0.9


def test_tier_downgrades_below_threshold():
    s = TrustScorer()
    identity = _id(score=0.05, tier=TrustTier.LOW)
    s.observe(
        identity, DecisionVerdict.DENY, risk_factors=[RiskFactor(code="x", score=1.0, source="x")]
    )
    assert identity.tier in (TrustTier.LOW, TrustTier.UNTRUSTED)
