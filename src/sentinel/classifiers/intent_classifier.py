"""Goal-hijacking detector.

Compares the declared :attr:`Action.intent` against the action's tool and
argument shape. A semantic mismatch suggests the agent has been redirected
toward an unintended goal (OWASP Agentic AI: goal hijacking).

The classifier ships with a fast lexical baseline and accepts a pluggable
``EmbeddingProvider`` for production deployments that want a semantic model.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol

from sentinel.models.action import Action, ActionType
from sentinel.models.decision import RiskFactor
from sentinel.models.identity import Identity


class EmbeddingProvider(Protocol):
    """Returns a similarity score in ``[0, 1]`` for two strings."""

    async def similarity(self, a: str, b: str) -> float: ...


@dataclass(slots=True)
class IntentClassifierConfig:
    min_similarity_for_match: float = 0.45
    hard_drift_threshold: float = 0.20


# Token sets that should generally accompany each action type's stated intent.
_INTENT_HINTS: dict[ActionType, set[str]] = {
    ActionType.FILE_WRITE: {"write", "save", "create", "update", "edit", "modify"},
    ActionType.FILE_READ: {"read", "load", "open", "fetch", "review"},
    ActionType.HTTP_REQUEST: {"request", "fetch", "post", "get", "call", "api"},
    ActionType.SHELL_COMMAND: {"run", "execute", "shell", "command"},
    ActionType.CODE_EXECUTION: {"execute", "run", "evaluate", "compute"},
    ActionType.PAYMENT: {"pay", "charge", "refund", "transfer", "purchase"},
    ActionType.DATABASE_QUERY: {"query", "select", "insert", "update", "delete"},
}


class IntentClassifier:
    """Detect goal-hijacking by comparing declared intent vs. observed action."""

    def __init__(
        self,
        embedding_provider: EmbeddingProvider | None = None,
        config: IntentClassifierConfig | None = None,
    ) -> None:
        self._embeddings = embedding_provider
        self._config = config or IntentClassifierConfig()

    async def classify(self, action: Action, identity: Identity | None) -> list[RiskFactor]:
        intent = (action.intent or "").strip()
        if not intent:
            return [
                RiskFactor(
                    code="intent.missing",
                    severity=0.25,
                    detector="intent_classifier",
                    message="Action submitted without declared intent.",
                    evidence={"references": "OWASP-AGENT-01"},
                )
            ]

        hints = _INTENT_HINTS.get(action.type, set())
        tokens = set(_tokenize(intent))
        lexical_overlap = len(tokens & hints) / max(len(hints), 1) if hints else 0.5

        semantic_overlap = lexical_overlap
        if self._embeddings is not None and action.tool:
            semantic_overlap = await self._embeddings.similarity(intent, action.tool)

        combined = (lexical_overlap + semantic_overlap) / 2.0
        if combined >= self._config.min_similarity_for_match:
            return []

        severity = min(1.0, 1.0 - combined)
        factor_code = (
            "intent.hard_drift"
            if combined <= self._config.hard_drift_threshold
            else "intent.soft_drift"
        )
        return [
            RiskFactor(
                code=factor_code,
                severity=round(severity, 3),
                detector="intent_classifier",
                message=(
                    "Declared intent does not align with the action being taken. "
                    "Possible goal hijacking or prompt-driven redirection."
                ),
                evidence={
                    "intent": intent[:200],
                    "action_type": action.type.value,
                    "tool": action.tool or "",
                    "lexical_overlap": f"{lexical_overlap:.3f}",
                    "semantic_overlap": f"{semantic_overlap:.3f}",
                    "references": "OWASP-AGENT-01",
                },
            )
        ]


def _tokenize(s: str) -> list[str]:
    return [t.lower() for t in re.findall(r"[A-Za-z_]+", s)]
