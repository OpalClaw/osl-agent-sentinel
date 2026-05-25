"""End-to-end: MCP gateway gates real tool execution."""

from __future__ import annotations

import pytest

from sentinel.core.interceptor import Interceptor
from sentinel.gateway.mcp_gateway import MCPGateway, ToolDeniedError
from sentinel.models.identity import Identity


@pytest.mark.asyncio
async def test_gateway_denies_unknown_tool(interceptor: Interceptor, trusted_identity: Identity):
    gateway = MCPGateway(interceptor=interceptor)

    async def execute(name: str, args: dict) -> dict:
        return {"called": name, "args": args}

    with pytest.raises(ToolDeniedError):
        await gateway.invoke(
            tool="unknown.tool",
            args={},
            principal_did=trusted_identity.did,
            tenant_id="default",
            executor=execute,
        )


@pytest.mark.asyncio
async def test_gateway_executes_allowed_tool(interceptor: Interceptor, trusted_identity: Identity):
    gateway = MCPGateway(interceptor=interceptor)
    calls: list[str] = []

    async def execute(name: str, args: dict) -> dict:
        calls.append(name)
        return {"ok": True}

    result = await gateway.invoke(
        tool="http.get",
        args={"url": "https://example.com"},
        principal_did=trusted_identity.did,
        tenant_id="default",
        executor=execute,
    )
    assert result["ok"] is True
    assert calls == ["http.get"]
