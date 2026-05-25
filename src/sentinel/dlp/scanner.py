"""DLP scanner.

Scans action payloads (arguments and output fields) for sensitive data
patterns: credentials, API keys, common PII shapes, payment data hints.
Pluggable rule sets allow tenants to extend the default set.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from sentinel.models.decision import RiskFactor

if TYPE_CHECKING:
    from collections.abc import Iterable

    from sentinel.models.action import Action
    from sentinel.models.identity import Identity


@dataclass(slots=True)
class DLPRule:
    """A single regex-driven DLP rule."""

    code: str
    pattern: re.Pattern[str]
    severity: float
    message: str
    references: str = ""


@dataclass(slots=True)
class DLPRuleSet:
    """Composable bundle of DLP rules."""

    rules: list[DLPRule] = field(default_factory=list)

    def extend(self, more: Iterable[DLPRule]) -> None:
        self.rules.extend(more)


def default_rules() -> DLPRuleSet:
    return DLPRuleSet(
        rules=[
            DLPRule(
                code="dlp.aws_access_key",
                pattern=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
                severity=0.95,
                message="AWS access key identifier detected in payload.",
                references="OWASP-AGENT-04",
            ),
            DLPRule(
                code="dlp.private_key_block",
                pattern=re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----"),
                severity=1.0,
                message="Private-key block detected in payload.",
                references="OWASP-AGENT-04",
            ),
            DLPRule(
                code="dlp.bearer_token",
                pattern=re.compile(r"(?i)\bbearer\s+[A-Za-z0-9_\-\.=]{20,}\b"),
                severity=0.7,
                message="Bearer token detected in payload.",
                references="OWASP-AGENT-04",
            ),
            DLPRule(
                code="dlp.email",
                pattern=re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
                severity=0.15,
                message="Email address detected in payload.",
                references="OWASP-AGENT-04",
            ),
            DLPRule(
                code="dlp.credit_card",
                pattern=re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
                severity=0.6,
                message="Numeric sequence matching a payment-card length detected.",
                references="OWASP-AGENT-04",
            ),
            DLPRule(
                code="dlp.us_ssn",
                pattern=re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
                severity=0.7,
                message="US-style SSN pattern detected.",
                references="OWASP-AGENT-04",
            ),
        ]
    )


class DLPScanner:
    """Run the configured rule set across every text field in the action."""

    def __init__(self, rule_set: DLPRuleSet | None = None, *, enabled: bool = True) -> None:
        self._rules = rule_set or default_rules()
        self._enabled = enabled

    @classmethod
    def default(cls) -> DLPScanner:
        """Build a scanner pre-loaded with the bundled default rule set."""
        return cls(rule_set=default_rules())

    async def scan(self, action: Action, identity: Identity | None) -> list[RiskFactor]:
        if not self._enabled:
            return []
        factors: list[RiskFactor] = []
        for text in _iter_text(action):
            for rule in self._rules.rules:
                m = rule.pattern.search(text)
                if not m:
                    continue
                factors.append(
                    RiskFactor(
                        code=rule.code,
                        severity=rule.severity,
                        detector="dlp_scanner",
                        message=rule.message,
                        evidence={
                            "snippet": _redact(m.group(0))[:64],
                            "references": rule.references,
                        },
                    )
                )
        return factors


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


def _redact(s: str) -> str:
    if len(s) <= 8:
        return "*" * len(s)
    return s[:2] + "*" * (len(s) - 4) + s[-2:]
