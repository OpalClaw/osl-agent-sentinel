"""Shared test fixtures."""

from __future__ import annotations

import pytest

from sentinel.classifiers import (
    AnomalyDetector,
    IntentClassifier,
    PromptInjectionDetector,
    ToolValidator,
)
from sentinel.classifiers.tool_validator import ToolSpec
from sentinel.core.approval import ApprovalWorkflow, InMemoryApprovalBackend
from sentinel.core.cache import LocalPolicyCache
from sentinel.core.interceptor import Interceptor
from sentinel.core.pipeline import DecisionPipeline
from sentinel.core.policy_engine import PolicyEngine
from sentinel.dlp.scanner import DLPRule, DLPRuleSet, DLPScanner
from sentinel.identity.resolver import IdentityResolver, InMemoryIdentityStore
from sentinel.identity.trust_scorer import TrustScorer
from sentinel.models.identity import Capability, Identity, TrustTier
from sentinel.models.policy import PolicyBundle, PolicyRule, RuleEffect
from sentinel.tenancy.manager import TenantConfig, TenantManager


def _build_default_bundle() -> PolicyBundle:
    rules = [
        PolicyRule(
            id="tool-no-capability",
            description="Deny when capability missing.",
            owasp=["AGENT-03"],
            match={"risk.factor_code_any": ["tool.no_capability"]},
            effect=RuleEffect.DENY,
        ),
        PolicyRule(
            id="code-exec-escalate",
            description="Code exec always escalates.",
            owasp=["AGENT-07"],
            match={"action.type": "code_exec"},
            effect=RuleEffect.ESCALATE,
        ),
    ]
    return PolicyBundle(version="test", bundle_id="test", rules=rules)


@pytest.fixture
def trusted_identity() -> Identity:
    return Identity(
        did="did:test:trusted",
        public_key_b64="A" * 43 + "=",
        tier=TrustTier.TRUSTED,
        capabilities=[Capability(name="net.http"), Capability(name="fs.read")],
        trust_score=0.95,
    )


@pytest.fixture
def untrusted_identity() -> Identity:
    return Identity(
        did="did:test:untrusted",
        public_key_b64="B" * 43 + "=",
        tier=TrustTier.UNTRUSTED,
        capabilities=[],
        trust_score=0.05,
    )


@pytest.fixture
def interceptor(trusted_identity: Identity, untrusted_identity: Identity) -> Interceptor:
    store = InMemoryIdentityStore()
    store.put(trusted_identity)
    store.put(untrusted_identity)
    resolver = IdentityResolver(store)

    tool_validator = ToolValidator(
        [
            ToolSpec(name="http.get", capability="net.http", sensitive=False, arg_schema={"type": "object"}),
            ToolSpec(name="shell.exec", capability="code.exec", sensitive=True, arg_schema={"type": "object"}),
        ]
    )
    dlp = DLPScanner(DLPRuleSet([]))

    pipeline = DecisionPipeline(
        policy_engine=PolicyEngine(_build_default_bundle()),
        intent=IntentClassifier(),
        tool_validator=tool_validator,
        anomaly=AnomalyDetector(),
        injection=PromptInjectionDetector(),
        dlp=dlp,
        identity=resolver,
        trust=TrustScorer(),
        approvals=ApprovalWorkflow(InMemoryApprovalBackend()),
        cache=LocalPolicyCache(path=None),
    )
    return Interceptor(pipeline=pipeline, tenants=TenantManager.with_default())
