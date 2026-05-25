"""Policy engine.

Evaluates a normalized action against the active :class:`PolicyBundle` and
returns a list of matching rule effects. The engine is intentionally pure
and synchronous — all I/O lives in the loader and the pipeline.

The match language is a small, audit-friendly subset:

* ``action.type``               — exact match on the action type string
* ``action.tool``               — exact match, or list-of-strings ``in`` match
* ``identity.tier``             — exact match
* ``identity.did_prefix``       — prefix match
* ``args.<dotted.path>``        — exact match on a nested argument
* ``args_contains``             — list of substrings any of which must be in the JSON-encoded args

Conjunction is implicit (all match keys must be satisfied). Disjunction is
expressed by multiple rules sharing a tag.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable

from sentinel.models.action import Action
from sentinel.models.identity import Identity
from sentinel.models.policy import PolicyBundle, PolicyRule, RuleEffect


@dataclass(slots=True)
class RuleMatch:
    """A rule that matched along with its effect."""

    rule: PolicyRule
    effect: RuleEffect


class PolicyEngine:
    """Stateless, deterministic policy matcher."""

    def __init__(self, bundle: PolicyBundle) -> None:
        self._bundle = bundle

    @property
    def bundle(self) -> PolicyBundle:
        return self._bundle

    def replace_bundle(self, bundle: PolicyBundle) -> None:
        self._bundle = bundle

    def evaluate(self, action: Action, identity: Identity | None) -> list[RuleMatch]:
        matches: list[RuleMatch] = []
        for rule in self._bundle.by_priority():
            if self._matches(rule, action, identity):
                matches.append(RuleMatch(rule=rule, effect=rule.effect))
        return matches

    # ------------------------------------------------------------------ matching

    def _matches(self, rule: PolicyRule, action: Action, identity: Identity | None) -> bool:
        m = rule.match
        if not m:
            return True

        if (val := m.get("action.type")) is not None:
            if action.type.value != val:
                return False

        if (val := m.get("action.tool")) is not None:
            if isinstance(val, list):
                if action.tool not in val:
                    return False
            elif action.tool != val:
                return False

        if (val := m.get("identity.tier")) is not None:
            if identity is None or identity.tier.value != val:
                return False

        if (val := m.get("identity.did_prefix")) is not None:
            if not action.agent_did.startswith(str(val)):
                return False

        for key, expected in m.items():
            if not key.startswith("args."):
                continue
            path = key.removeprefix("args.").split(".")
            if not self._deep_eq(action.arguments, path, expected):
                return False

        if (val := m.get("args_contains")) is not None:
            haystack = json.dumps(action.arguments, sort_keys=True, default=str)
            if not any(needle in haystack for needle in _ensure_list(val)):
                return False

        return True

    @staticmethod
    def _deep_eq(obj: Any, path: list[str], expected: Any) -> bool:
        cur: Any = obj
        for part in path:
            if not isinstance(cur, dict) or part not in cur:
                return False
            cur = cur[part]
        return cur == expected


def _ensure_list(val: Any) -> Iterable[str]:
    return val if isinstance(val, list) else [val]
