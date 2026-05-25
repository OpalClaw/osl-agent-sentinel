"""Safe-mode runtime.

When the upstream policy source, the identity resolver, or the audit log
becomes unreachable, the sentinel must continue to make decisions — but
those decisions are *fail-closed*: every action is denied unless it
matches a tightly curated, signed safe-mode policy bundle that ships
with the binary.

This module is intentionally simple and stateless. It is the last line
of defense and must be auditable in one screen.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from sentinel.models.action import Action, ActionType
from sentinel.models.decision import Decision, DecisionExplanation, DecisionVerdict, RiskFactor

if TYPE_CHECKING:
    from collections.abc import Iterable

_SAFE_ALLOW_TYPES: frozenset[ActionType] = frozenset(
    {ActionType.MEMORY_READ, ActionType.FILE_READ, ActionType.LLM_PROMPT}
)


@dataclass(slots=True)
class SafeModeConfig:
    """Curated allowlist applied when sentinel runs in fail-closed mode.

    ``allow_action_types`` defaults to read-only verbs. Anything outside the
    allowlist is denied with a structured rationale.
    """

    allow_action_types: frozenset[ActionType] = field(default_factory=lambda: _SAFE_ALLOW_TYPES)
    reason: str = "sentinel safe-mode: upstream control plane unavailable"


def evaluate_safe_mode(action: Action, config: SafeModeConfig | None = None) -> Decision:
    """Render a fail-closed decision for ``action``.

    ``ALLOW`` is only returned for explicitly listed action types. Everything
    else is denied with an explanation carrying the reason so SIEMs and
    operators can correlate the outage.
    """

    cfg = config or SafeModeConfig()
    if action.type in cfg.allow_action_types:
        return Decision(
            action_id=action.id,
            verdict=DecisionVerdict.ALLOW,
            decided_by="sentinel.safe_mode",
            explanation=DecisionExplanation(
                summary="safe-mode allow (read-only verb)",
                risk_score=0.0,
                risk_factors=[],
            ),
            degraded=True,
        )

    return Decision(
        action_id=action.id,
        verdict=DecisionVerdict.DENY,
        decided_by="sentinel.safe_mode",
        explanation=DecisionExplanation(
            summary=cfg.reason,
            risk_score=1.0,
            risk_factors=[
                RiskFactor(
                    code="safe_mode.deny",
                    severity=1.0,
                    detector="safe_mode",
                    message=cfg.reason,
                    evidence={"action_type": action.type.value},
                )
            ],
        ),
        degraded=True,
    )


def safe_mode_decisions(
    actions: Iterable[Action], config: SafeModeConfig | None = None
) -> list[Decision]:
    """Batch helper. Useful for replay / regression testing."""
    return [evaluate_safe_mode(a, config) for a in actions]


__all__ = ["SafeModeConfig", "evaluate_safe_mode", "safe_mode_decisions"]
