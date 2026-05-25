"""Decision pipeline.

The pipeline assembles the policy engine, classifiers, identity resolution,
trust scoring, DLP, and the approval workflow into a single, ordered
evaluation. The pipeline is deterministic given the same inputs and is
designed to fail closed.

Order of evaluation:

1. Resolve identity (with circuit-breaker protection).
2. Run classifiers in parallel: intent, tool validator, anomaly,
   prompt-injection, DLP.
3. Evaluate policy bundle.
4. Aggregate risk score and reconcile with the most restrictive matching
   rule.
5. Apply trust-score gating.
6. Emit the final decision (with explanation).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from sentinel.classifiers.anomaly_detector import AnomalyDetector
from sentinel.classifiers.injection_detector import PromptInjectionDetector
from sentinel.classifiers.intent_classifier import IntentClassifier
from sentinel.classifiers.tool_validator import ToolValidator
from sentinel.core.cache import LocalPolicyCache
from sentinel.core.circuit_breaker import CircuitBreaker
from sentinel.core.policy_engine import PolicyEngine, RuleMatch
from sentinel.dlp.scanner import DLPScanner
from sentinel.identity.resolver import IdentityResolver
from sentinel.identity.trust_scorer import TrustScorer
from sentinel.models.action import Action
from sentinel.models.decision import (
    Decision,
    DecisionExplanation,
    DecisionVerdict,
    RiskFactor,
)
from sentinel.models.identity import Identity, TrustTier
from sentinel.models.policy import RuleEffect
from sentinel.utils.errors import DependencyUnavailableError
from sentinel.utils.logging import get_logger
from sentinel.utils.timing import stopwatch

log = get_logger(__name__)

# Risk-score thresholds for the default risk-only path. Policy effects override.
DENY_THRESHOLD = 0.85
ESCALATE_THRESHOLD = 0.55
THROTTLE_THRESHOLD = 0.35


ClassifierFn = Callable[[Action, Identity | None], Awaitable[list[RiskFactor]]]


@dataclass(slots=True)
class PipelineDeps:
    """Wires the pipeline to its collaborators."""

    policy_engine: PolicyEngine
    identity_resolver: IdentityResolver
    trust_scorer: TrustScorer
    intent_classifier: IntentClassifier
    tool_validator: ToolValidator
    anomaly_detector: AnomalyDetector
    injection_detector: PromptInjectionDetector
    dlp_scanner: DLPScanner
    policy_cache: LocalPolicyCache | None = None
    identity_breaker: CircuitBreaker = field(
        default_factory=lambda: CircuitBreaker(name="identity")
    )


class DecisionPipeline:
    """Composes classifiers and the policy engine into a verdict."""

    def __init__(self, deps: PipelineDeps) -> None:
        self._deps = deps

    async def evaluate(self, action: Action) -> Decision:
        degraded = False
        try:
            identity = await self._deps.identity_breaker.call(
                lambda: self._deps.identity_resolver.resolve(action.agent_did)
            )
        except DependencyUnavailableError:
            identity = None
            degraded = True
            log.warning("pipeline.identity_unavailable", action_id=str(action.id))

        risk_factors: list[RiskFactor] = []
        with stopwatch() as t:
            classifier_results = await asyncio.gather(
                self._safe_run(self._deps.intent_classifier.classify, action, identity),
                self._safe_run(self._deps.tool_validator.validate, action, identity),
                self._safe_run(self._deps.anomaly_detector.score, action, identity),
                self._safe_run(self._deps.injection_detector.scan, action, identity),
                self._safe_run(self._deps.dlp_scanner.scan, action, identity),
            )
        for batch in classifier_results:
            risk_factors.extend(batch)

        matches = self._deps.policy_engine.evaluate(action, identity)

        verdict, summary, rule_ids = self._reconcile(matches, risk_factors, identity)

        trust_adjusted = self._deps.trust_scorer.adjust(identity, risk_factors, verdict)
        if trust_adjusted is not None and trust_adjusted.tier == TrustTier.OBSERVE:
            # Trust collapsed to OBSERVE — only ALLOW read-only actions.
            if verdict == DecisionVerdict.ALLOW and action.type.value not in {
                "file_read",
                "memory_read",
                "llm_prompt",
            }:
                verdict = DecisionVerdict.DENY
                summary = "Identity demoted to OBSERVE tier; write actions denied."

        explanation = DecisionExplanation(
            summary=summary,
            triggered_rule_ids=rule_ids,
            risk_factors=risk_factors,
            risk_score=_aggregate_risk(risk_factors),
            recommended_remediation=_remediation(verdict, risk_factors),
            references=_unique([ref for f in risk_factors for ref in _refs_for(f)]),
        )

        return Decision(
            action_id=action.id,
            verdict=verdict,
            explanation=explanation,
            latency_ms=t["elapsed_ms"],
            degraded=degraded,
        )

    # ----------------------------------------------------------- reconciliation

    @staticmethod
    def _reconcile(
        matches: list[RuleMatch],
        risk_factors: list[RiskFactor],
        identity: Identity | None,
    ) -> tuple[DecisionVerdict, str, list[str]]:
        rule_ids = [m.rule.id for m in matches]
        effects = {m.effect for m in matches}

        if RuleEffect.DENY in effects:
            return (
                DecisionVerdict.DENY,
                "Action denied by policy rule(s): " + ", ".join(rule_ids),
                rule_ids,
            )
        if RuleEffect.ESCALATE in effects:
            return (
                DecisionVerdict.ESCALATE,
                "Action escalated to human review by policy rule(s): " + ", ".join(rule_ids),
                rule_ids,
            )
        if RuleEffect.THROTTLE in effects:
            return (
                DecisionVerdict.THROTTLE,
                "Action throttled by policy rule(s): " + ", ".join(rule_ids),
                rule_ids,
            )

        # No explicit policy effect — fall through to risk-score thresholds.
        score = _aggregate_risk(risk_factors)
        if score >= DENY_THRESHOLD:
            return DecisionVerdict.DENY, f"Aggregate risk score {score:.2f} exceeded deny threshold.", rule_ids
        if score >= ESCALATE_THRESHOLD:
            return DecisionVerdict.ESCALATE, f"Aggregate risk score {score:.2f} exceeded escalate threshold.", rule_ids
        if score >= THROTTLE_THRESHOLD:
            return DecisionVerdict.THROTTLE, f"Aggregate risk score {score:.2f} exceeded throttle threshold.", rule_ids
        if identity is None:
            return DecisionVerdict.ESCALATE, "Agent identity unresolved; escalating.", rule_ids
        return DecisionVerdict.ALLOW, "Action passed all sentinel checks.", rule_ids

    @staticmethod
    async def _safe_run(fn: ClassifierFn, action: Action, identity: Identity | None) -> list[RiskFactor]:
        try:
            return await fn(action, identity)
        except Exception as exc:  # noqa: BLE001
            log.error("classifier.error", classifier=fn.__qualname__, error=str(exc))
            # Fail closed by surfacing a synthetic high-severity risk factor.
            return [
                RiskFactor(
                    code="classifier.error",
                    severity=0.6,
                    detector=fn.__qualname__,
                    message="Classifier failed; treating as elevated risk.",
                    evidence={"error": str(exc)[:200]},
                )
            ]


def _aggregate_risk(factors: list[RiskFactor]) -> float:
    if not factors:
        return 0.0
    # Probabilistic OR: 1 - prod(1 - s). Caps at 1.
    p_safe = 1.0
    for f in factors:
        p_safe *= 1.0 - max(0.0, min(1.0, f.severity))
    return round(1.0 - p_safe, 4)


def _remediation(verdict: DecisionVerdict, factors: list[RiskFactor]) -> str | None:
    if verdict == DecisionVerdict.ALLOW:
        return None
    if not factors:
        return "Review the triggered policy rule(s) and adjust agent behavior."
    top = max(factors, key=lambda f: f.severity)
    return f"Top risk factor: {top.code} ({top.detector}). {top.message}"


def _refs_for(f: RiskFactor) -> list[str]:
    return list(f.evidence.get("references", "").split(",")) if f.evidence.get("references") else []


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out
