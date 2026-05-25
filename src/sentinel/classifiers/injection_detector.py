"""Prompt-injection detector.

Inspects action payloads (notably ``LLM_PROMPT`` and ``MEMORY_WRITE``) and
free-text arguments for patterns associated with prompt-injection,
jailbreak attempts, instruction override, and memory poisoning. Returns a
single composed :class:`RiskFactor` carrying the highest-confidence
detector's score.

This baseline uses fast deterministic heuristics. A pluggable
``InjectionModel`` may be wired in for production deployments that run a
classifier model.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Protocol

from sentinel.models.action import Action, ActionType
from sentinel.models.decision import RiskFactor
from sentinel.models.identity import Identity


class InjectionModel(Protocol):
    """Optional model that returns ``[0, 1]`` confidence for a string."""

    async def score(self, text: str) -> float: ...


@dataclass(slots=True)
class InjectionDetectorConfig:
    threshold: float = 0.75
    max_chars_per_field: int = 16_000


# Conservative pattern set covering common instruction-override and jailbreak shapes.
# These are heuristics, not a complete defense — the pluggable model is for that.
_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|earlier)\s+(?:instructions?|rules?)\b"),
    re.compile(r"(?i)\bdisregard\s+(?:all\s+)?(?:previous|prior|system)\s+(?:instructions?|prompts?)\b"),
    re.compile(r"(?i)\b(?:from\s+now\s+on|new\s+instructions?)\s*[:\-]"),
    re.compile(r"(?i)\byou\s+are\s+now\s+(?:a\s+)?(?:different|new)\b"),
    re.compile(r"(?i)\b(?:reveal|show|print|output)\s+(?:the\s+)?(?:system\s+prompt|hidden\s+prompt|developer\s+prompt)\b"),
    re.compile(r"(?i)\bjailbreak\b|\bDAN\b|\bdo\s+anything\s+now\b"),
    re.compile(r"(?i)\boverride\s+(?:the\s+)?safety\b"),
    re.compile(r"(?i)\b(?:exfiltrate|leak)\s+.*\b(?:api[_\s-]?key|password|token|secret)s?\b"),
    re.compile(r"(?i)\bcurl\s+.*\|\s*(?:sh|bash|python)\b"),
    re.compile(r"(?i)\b(?:base64|hex)\s*decoded?\b.*\b(?:execute|run)\b"),
)


class PromptInjectionDetector:
    """Detect prompt-injection and instruction-override attempts."""

    def __init__(
        self,
        model: InjectionModel | None = None,
        config: InjectionDetectorConfig | None = None,
    ) -> None:
        self._model = model
        self._config = config or InjectionDetectorConfig()

    async def scan(self, action: Action, identity: Identity | None) -> list[RiskFactor]:
        candidates: list[str] = list(self._iter_text(action))
        if not candidates:
            return []

        pattern_hits: list[tuple[str, str]] = []  # (pattern_name, snippet)
        for text in candidates:
            text = text[: self._config.max_chars_per_field]
            for pat in _PATTERNS:
                if (m := pat.search(text)):
                    pattern_hits.append((pat.pattern, m.group(0)[:160]))

        model_score = 0.0
        if self._model is not None:
            try:
                model_score = max(
                    [await self._model.score(t[: self._config.max_chars_per_field]) for t in candidates]
                )
            except Exception:
                model_score = 0.0

        severity = 0.0
        if pattern_hits:
            severity = max(severity, min(1.0, 0.55 + 0.1 * len(pattern_hits)))
        if model_score > self._config.threshold:
            severity = max(severity, model_score)

        if severity <= 0.0:
            return []

        action_kind = (
            "memory_poisoning"
            if action.type in {ActionType.MEMORY_WRITE, ActionType.MEMORY_READ}
            else "prompt_injection"
        )
        return [
            RiskFactor(
                code=f"injection.{action_kind}",
                severity=round(severity, 3),
                detector="prompt_injection_detector",
                message=(
                    "Suspected prompt-injection or instruction-override pattern in agent input. "
                    "Review the offending fields and consider quarantine."
                ),
                evidence={
                    "pattern_hits": str(len(pattern_hits)),
                    "model_score": f"{model_score:.3f}",
                    "references": "OWASP-AGENT-01,OWASP-AGENT-02",
                },
            )
        ]

    @staticmethod
    def _iter_text(action: Action) -> Iterable[str]:
        if action.intent:
            yield action.intent
        for v in action.arguments.values():
            if isinstance(v, str):
                yield v
            elif isinstance(v, (list, tuple)):
                for item in v:
                    if isinstance(item, str):
                        yield item
