"""MCP validator coverage."""

from __future__ import annotations

from sentinel.gateway.mcp_validators import MCPInvocation, validate


def test_lookalike_tool_name_is_blocked():
    inv = MCPInvocation(tool="http\u200b.get", arguments={})
    factors = validate(inv, allowed_names={"http.get"})
    codes = {f.code for f in factors}
    assert "mcp.tool_name.control_chars" in codes


def test_resource_traversal_is_blocked():
    inv = MCPInvocation(tool="fs.read", arguments={}, resource_uri="file:///../../etc/passwd")
    factors = validate(inv, allowed_names={"fs.read"})
    assert any(f.code == "mcp.resource.traversal" for f in factors)


def test_capability_spoof_is_blocked():
    inv = MCPInvocation(tool="payments.charge", arguments={}, declared_capability="net.http")
    factors = validate(
        inv,
        allowed_names={"payments.charge"},
        expected_capability="payments.write",
    )
    assert any(f.code == "mcp.capability.spoof" for f in factors)


def test_clean_invocation_emits_no_factors():
    inv = MCPInvocation(tool="http.get", arguments={"url": "https://example.com"})
    assert validate(inv, allowed_names={"http.get"}) == []
