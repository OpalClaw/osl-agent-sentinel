"""Unit tests for the policy engine."""

from __future__ import annotations

import pytest

from sentinel.core.policy_engine import PolicyEngine
from sentinel.models.action import Action, ActionType
from sentinel.models.decision import DecisionVerdict, RiskFactor
from sentinel.models.identity import Capability, Identity, TrustTier
from sentinel.models.policy import PolicyBundle, PolicyRule, RuleEffect


def _identity(tier: TrustTier = TrustTier.MEDIUM) -> Identity:
    return Identity(
        did="did:test:engine",
        public_key_b64="A" * 43 + "=",
        tier=tier,
        capabilities=[Capability(name="net.http")],
        trust_score=0.5,
    )


def _action(type_: ActionType = ActionType.TOOL_CALL, tool: str | None = "http.get") -> Action:
    return Action(type=type_, tool=tool, intent="fetch_data", args={"url": "https://example.com"}, tenant_id="t1")


def test_deny_takes_precedence_over_allow():
    bundle = PolicyBundle(
        version="t",
        bundle_id="t",
        rules=[
            PolicyRule(id="allow-all", match={"runtime.always": True}, effect=RuleEffect.ALLOW),
            PolicyRule(
                id="deny-no-cap",
                match={"risk.factor_code_any": ["tool.no_capability"]},
                effect=RuleEffect.DENY,
            ),
        ],
    )
    engine = PolicyEngine(bundle)
    verdict, matched = engine.evaluate(
        _action(),
        _identity(),
        [RiskFactor(code="tool.no_capability", score=1.0, source="tool_validator")],
    )
    assert verdict is DecisionVerdict.DENY
    assert "deny-no-cap" in {r.id for r in matched}


def test_escalate_beats_allow_but_loses_to_deny():
    bundle = PolicyBundle(
        version="t",
        bundle_id="t",
        rules=[
            PolicyRule(id="allow-all", match={"runtime.always": True}, effect=RuleEffect.ALLOW),
            PolicyRule(id="escalate-exec", match={"action.type": "code_exec"}, effect=RuleEffect.ESCALATE),
        ],
    )
    engine = PolicyEngine(bundle)
    verdict, _ = engine.evaluate(_action(type_=ActionType.CODE_EXEC, tool=None), _identity(), [])
    assert verdict is DecisionVerdict.ESCALATE


def test_default_is_deny_when_no_match():
    bundle = PolicyBundle(version="t", bundle_id="t", rules=[])
    engine = PolicyEngine(bundle)
    verdict, matched = engine.evaluate(_action(), _identity(), [])
    assert verdict is DecisionVerdict.DENY
    assert matched == []


@pytest.mark.parametrize("tier,expected", [
    (TrustTier.UNTRUSTED, DecisionVerdict.DENY),
    (TrustTier.TRUSTED, DecisionVerdict.ALLOW),
])
def test_tier_gating(tier: TrustTier, expected: DecisionVerdict):
    bundle = PolicyBundle(
        version="t",
        bundle_id="t",
        rules=[
            PolicyRule(id="allow-trusted", match={"identity.tier": "trusted"}, effect=RuleEffect.ALLOW),
            PolicyRule(id="deny-untrusted", match={"identity.tier": "untrusted"}, effect=RuleEffect.DENY),
        ],
    )
    engine = PolicyEngine(bundle)
    verdict, _ = engine.evaluate(_action(), _identity(tier), [])
    assert verdict is expected
