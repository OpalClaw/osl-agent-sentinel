"""Unit tests for the policy engine."""

from __future__ import annotations

from sentinel.core.policy_engine import PolicyEngine
from sentinel.models.action import Action, ActionType
from sentinel.models.identity import Capability, Identity, TrustTier
from sentinel.models.policy import PolicyBundle, PolicyRule, RuleEffect


def _identity(tier: TrustTier = TrustTier.STANDARD) -> Identity:
    return Identity(
        did="did:test:eval",
        public_key_b64="A" * 43 + "=",
        tier=tier,
        capabilities=[Capability(name="net.http")],
    )


def _action(type_: ActionType = ActionType.TOOL_CALL, tool: str | None = "http.get") -> Action:
    return Action(
        agent_did="did:test:eval",
        type=type_,
        tool=tool,
        arguments={},
    )


def _bundle(rules: list[PolicyRule]) -> PolicyBundle:
    return PolicyBundle(version="t", issuer="test", rules=rules)


def test_default_no_match_returns_empty_list() -> None:
    engine = PolicyEngine(_bundle([]))
    assert engine.evaluate(_action(), _identity()) == []


def test_deny_takes_precedence_when_higher_priority() -> None:
    bundle = _bundle(
        [
            PolicyRule(
                id="deny", effect=RuleEffect.DENY, match={"action.tool": "http.get"}, priority=10
            ),
            PolicyRule(id="allow", effect=RuleEffect.ALLOW, match={}, priority=1000),
        ]
    )
    engine = PolicyEngine(bundle)
    matches = engine.evaluate(_action(), _identity())
    assert matches, "expected at least one match"
    assert matches[0].rule.id == "deny"
    assert matches[0].effect == RuleEffect.DENY


def test_escalate_matches_when_no_deny_present() -> None:
    bundle = _bundle(
        [
            PolicyRule(
                id="escalate-code",
                effect=RuleEffect.ESCALATE,
                match={"action.type": "code_execution"},
                priority=10,
            )
        ]
    )
    engine = PolicyEngine(bundle)
    matches = engine.evaluate(_action(type_=ActionType.CODE_EXECUTION, tool=None), _identity())
    assert any(m.effect == RuleEffect.ESCALATE for m in matches)


def test_tool_match_returns_correct_rule() -> None:
    bundle = _bundle(
        [
            PolicyRule(
                id="allow-http",
                effect=RuleEffect.ALLOW,
                match={"action.tool": "http.get"},
                priority=10,
            )
        ]
    )
    engine = PolicyEngine(bundle)
    matches = engine.evaluate(_action(tool="http.get"), _identity())
    assert any(m.rule.id == "allow-http" for m in matches)
