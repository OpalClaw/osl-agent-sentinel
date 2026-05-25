"""MCP protocol validators.

A small set of stateless checks that block the most common MCP-level
abuses *before* an action is even handed to the decision pipeline. Each
validator returns a list of :class:`RiskFactor` so the broader pipeline
can fold them into its risk math; the gateway short-circuits to DENY
when any factor at severity >= 0.9 is emitted.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from sentinel.models.decision import RiskFactor


@dataclass(slots=True)
class MCPInvocation:
    """The minimal surface the gateway needs to validate an MCP call."""

    tool: str
    arguments: dict[str, Any]
    declared_capability: str | None = None
    resource_uri: str | None = None


# -- individual validators ------------------------------------------------


def detect_tool_name_collision(
    invocation: MCPInvocation, allowed_names: set[str]
) -> list[RiskFactor]:
    """Catch homoglyph / zero-width-space / suffix-padding name attacks."""
    factors: list[RiskFactor] = []
    name = invocation.tool

    if not name:
        factors.append(
            RiskFactor(
                code="mcp.tool_name.empty",
                severity=1.0,
                detector="mcp_validators",
                message="MCP invocation arrived with an empty tool name.",
            )
        )
        return factors

    # Reject names with control / zero-width chars.
    if any(ord(c) < 0x20 or 0x200B <= ord(c) <= 0x200F for c in name):
        factors.append(
            RiskFactor(
                code="mcp.tool_name.control_chars",
                severity=0.95,
                detector="mcp_validators",
                message="Tool name contains control or zero-width characters.",
                evidence={"tool": name},
            )
        )

    # Look-alike: tool not in allowed set but ASCII-normalised is.
    if name not in allowed_names:
        ascii_name = name.encode("ascii", "ignore").decode("ascii")
        if ascii_name != name and ascii_name in allowed_names:
            factors.append(
                RiskFactor(
                    code="mcp.tool_name.lookalike",
                    severity=1.0,
                    detector="mcp_validators",
                    message="Tool name matches an allowed tool after Unicode-stripping.",
                    evidence={"tool": name, "matches": ascii_name},
                )
            )

    return factors


def detect_resource_traversal(invocation: MCPInvocation) -> list[RiskFactor]:
    """Detect path-traversal patterns in MCP resource URIs."""
    uri = invocation.resource_uri or invocation.arguments.get("resource") or ""
    if not isinstance(uri, str) or not uri:
        return []

    parsed = urlparse(uri)
    path = parsed.path or uri

    suspicious = ("../", "..\\", "/etc/", "/proc/", "/root/", "%2e%2e", "%2f..")
    if any(s in path.lower() for s in suspicious):
        return [
            RiskFactor(
                code="mcp.resource.traversal",
                severity=1.0,
                detector="mcp_validators",
                message="Resource URI contains traversal or sensitive-path indicators.",
                evidence={"uri": uri[:512]},
            )
        ]
    return []


def detect_capability_spoofing(invocation: MCPInvocation, expected: str | None) -> list[RiskFactor]:
    """Block invocations whose declared capability mismatches the registry."""
    declared = invocation.declared_capability
    if declared and expected and declared != expected:
        return [
            RiskFactor(
                code="mcp.capability.spoof",
                severity=0.95,
                detector="mcp_validators",
                message="Declared capability does not match the registered one for this tool.",
                evidence={"declared": declared, "expected": expected},
            )
        ]
    return []


def validate(
    invocation: MCPInvocation,
    *,
    allowed_names: set[str],
    expected_capability: str | None = None,
) -> list[RiskFactor]:
    """Run every validator. Returns the union of risk factors."""
    out: list[RiskFactor] = []
    out.extend(detect_tool_name_collision(invocation, allowed_names))
    out.extend(detect_resource_traversal(invocation))
    out.extend(detect_capability_spoofing(invocation, expected_capability))
    return out


__all__ = [
    "MCPInvocation",
    "detect_capability_spoofing",
    "detect_resource_traversal",
    "detect_tool_name_collision",
    "validate",
]
