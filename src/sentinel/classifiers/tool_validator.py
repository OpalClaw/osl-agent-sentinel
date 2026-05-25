"""Tool misuse and capability validator.

Checks each :class:`Action` against the identity's capability grants and
against a registry of known tools and their argument schemas. Detects:

* Calls to tools the identity does not hold capability for (OWASP-AGENT-03).
* Calls with arguments that violate the tool's declared schema.
* Calls to tools that have been disabled or quarantined.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import jsonschema

from sentinel.models.action import Action
from sentinel.models.decision import RiskFactor
from sentinel.models.identity import Identity


@dataclass(slots=True)
class ToolSpec:
    """Declaration for a single tool the system permits."""

    name: str
    capability: str
    args_schema: dict[str, Any] = field(default_factory=dict)
    quarantined: bool = False
    sensitivity: float = 0.0  # 0.0 = harmless read, 1.0 = irreversible side effect


@dataclass(slots=True)
class ToolRegistry:
    """Lookup of known tools."""

    tools: dict[str, ToolSpec] = field(default_factory=dict)

    def register(self, spec: ToolSpec) -> None:
        self.tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None:
        return self.tools.get(name)


class ToolValidator:
    """Enforce capability bindings and tool argument schemas."""

    def __init__(self, registry: ToolRegistry | None = None) -> None:
        self._registry = registry or ToolRegistry()

    @property
    def registry(self) -> ToolRegistry:
        return self._registry

    async def validate(self, action: Action, identity: Identity | None) -> list[RiskFactor]:
        if not action.tool:
            return []
        spec = self._registry.get(action.tool)
        if spec is None:
            return [
                RiskFactor(
                    code="tool.unknown",
                    severity=0.7,
                    detector="tool_validator",
                    message=f"Tool '{action.tool}' is not registered with sentinel.",
                    evidence={"references": "OWASP-AGENT-03"},
                )
            ]
        if spec.quarantined:
            return [
                RiskFactor(
                    code="tool.quarantined",
                    severity=0.95,
                    detector="tool_validator",
                    message=f"Tool '{spec.name}' is currently quarantined.",
                    evidence={"references": "OWASP-AGENT-03,OWASP-AGENT-06"},
                )
            ]

        factors: list[RiskFactor] = []
        if identity is not None and not identity.has_capability(spec.capability):
            factors.append(
                RiskFactor(
                    code="tool.capability_missing",
                    severity=max(0.6, spec.sensitivity),
                    detector="tool_validator",
                    message=(
                        f"Identity {identity.did} lacks capability '{spec.capability}' "
                        f"required to invoke '{spec.name}'."
                    ),
                    evidence={
                        "required_capability": spec.capability,
                        "references": "OWASP-AGENT-04",
                    },
                )
            )

        if spec.args_schema:
            try:
                jsonschema.validate(action.arguments, spec.args_schema)
            except jsonschema.ValidationError as exc:
                factors.append(
                    RiskFactor(
                        code="tool.args_invalid",
                        severity=0.8,
                        detector="tool_validator",
                        message=f"Tool arguments failed schema validation: {exc.message}",
                        evidence={
                            "tool": spec.name,
                            "error_path": "/".join(str(p) for p in exc.path),
                            "references": "OWASP-AGENT-03",
                        },
                    )
                )
        return factors
