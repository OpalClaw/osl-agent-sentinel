"""Shared test fixtures.

The fixtures build a real, in-memory pipeline so individual tests can drive
the production code path without mocking. Where they need a custom-shaped
identity or bundle, helper factories are exposed alongside the fixtures.
"""

from __future__ import annotations

import pytest
import pytest_asyncio

from sentinel.classifiers import (
    AnomalyDetector,
    IntentClassifier,
    PromptInjectionDetector,
    ToolValidator,
)
from sentinel.classifiers.tool_validator import ToolSpec
from sentinel.core.approval import ApprovalWorkflow, InMemoryApprovalBackend
from sentinel.core.circuit_breaker import CircuitBreaker
from sentinel.core.interceptor import Interceptor
from sentinel.core.pipeline import DecisionPipeline, PipelineDeps
from sentinel.core.policy_engine import PolicyEngine
from sentinel.dlp.scanner import DLPRuleSet, DLPScanner
from sentinel.identity.resolver import IdentityResolver, InMemoryIdentityStore
from sentinel.identity.trust_scorer import TrustScorer
from sentinel.models.identity import Capability, Identity, TrustTier
from sentinel.models.policy import PolicyBundle, PolicyRule, RuleEffect
from sentinel.tenancy.manager import TenantManager


def build_default_bundle() -> PolicyBundle:
    """A minimal bundle covering the rules used across the test suite."""
    rules = [
        PolicyRule(
            id="tool-no-capability",
            description="Deny when capability missing.",
            owasp_ids=["AGENT-03"],
            match={"risk.factor_code_any": ["tool.no_capability", "tool.unknown"]},
            effect=RuleEffect.DENY,
            priority=10,
        ),
        PolicyRule(
            id="code-exec-escalate",
            description="Code execution always escalates.",
            owasp_ids=["AGENT-07"],
            match={"action.type": "code_exec"},
            effect=RuleEffect.ESCALATE,
            priority=20,
        ),
        PolicyRule(
            id="default-allow",
            description="Default-allow for known callers (test bundle only).",
            match={},
            effect=RuleEffect.ALLOW,
            priority=1000,
        ),
    ]
    return PolicyBundle(version="test", bundle_id="test", rules=rules)


def make_identity(
    *,
    did: str = "did:test:agent",
    tier: TrustTier = TrustTier.STANDARD,
    capabilities: list[Capability] | None = None,
    trust_score: float = 0.75,
) -> Identity:
    return Identity(
        did=did,
        public_key_b64="A" * 43 + "=",
        tier=tier,
        capabilities=capabilities or [Capability(name="net.http"), Capability(name="fs.read")],
        trust_score=trust_score,
    )


@pytest.fixture
def trusted_identity() -> Identity:
    return make_identity(did="did:test:trusted", tier=TrustTier.TRUSTED, trust_score=0.95)


@pytest.fixture
def untrusted_identity() -> Identity:
    return make_identity(
        did="did:test:untrusted",
        tier=TrustTier.UNTRUSTED,
        capabilities=[],
        trust_score=0.05,
    )


@pytest_asyncio.fixture
async def interceptor(trusted_identity: Identity, untrusted_identity: Identity) -> Interceptor:
    store = InMemoryIdentityStore()
    await store.put(trusted_identity)
    await store.put(untrusted_identity)
    resolver = IdentityResolver(store)

    tool_validator = ToolValidator(
        [
            ToolSpec(
                name="http.get",
                capability="net.http",
                sensitive=False,
                arg_schema={"type": "object"},
            ),
            ToolSpec(
                name="shell.exec",
                capability="code.exec",
                sensitive=True,
                arg_schema={"type": "object"},
            ),
        ]
    )

    deps = PipelineDeps(
        policy_engine=PolicyEngine(build_default_bundle()),
        intent_classifier=IntentClassifier(),
        tool_validator=tool_validator,
        anomaly_detector=AnomalyDetector(),
        injection_detector=PromptInjectionDetector(),
        dlp_scanner=DLPScanner(DLPRuleSet([])),
        identity_resolver=resolver,
        trust_scorer=TrustScorer(),
        approval_workflow=ApprovalWorkflow(InMemoryApprovalBackend()),
        identity_breaker=CircuitBreaker(name="identity"),
        policy_breaker=CircuitBreaker(name="policy"),
        dlp_breaker=CircuitBreaker(name="dlp"),
        tenants=TenantManager.with_default(),
    )
    pipeline = DecisionPipeline(deps)
    return Interceptor(pipeline=pipeline)
