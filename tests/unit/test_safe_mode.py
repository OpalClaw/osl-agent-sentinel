"""Safe-mode fail-closed coverage."""

from __future__ import annotations

from sentinel.models.action import Action, ActionType
from sentinel.models.decision import DecisionVerdict
from sentinel.resilience.safe_mode import SafeModeConfig, evaluate_safe_mode


def test_read_only_action_is_allowed_in_safe_mode():
    action = Action(type=ActionType.FILE_READ, intent="read config", agent_did="did:test:safe")
    decision = evaluate_safe_mode(action)
    assert decision.verdict is DecisionVerdict.ALLOW
    assert decision.degraded is True


def test_write_action_is_denied_in_safe_mode():
    action = Action(type=ActionType.FILE_WRITE, intent="persist", agent_did="did:test:safe")
    decision = evaluate_safe_mode(action)
    assert decision.verdict is DecisionVerdict.DENY
    assert decision.degraded is True
    assert any(f.code == "safe_mode.deny" for f in decision.explanation.risk_factors)


def test_safe_mode_config_can_widen_or_restrict_allowlist():
    cfg = SafeModeConfig(allow_action_types=frozenset({ActionType.MEMORY_READ}))
    file_read = Action(type=ActionType.FILE_READ, intent="x", agent_did="did:test:safe")
    decision = evaluate_safe_mode(file_read, cfg)
    assert decision.verdict is DecisionVerdict.DENY
