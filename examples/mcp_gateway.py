"""Gate an MCP-style tool runtime with sentinel."""

from __future__ import annotations

import asyncio

from sentinel.bootstrap import build_default_interceptor
from sentinel.gateway.mcp_gateway import MCPGateway, ToolDeniedError


async def execute_tool(name: str, args: dict) -> dict:
    """Pretend MCP tool runtime."""
    return {"tool": name, "args": args, "result": "ok"}


async def main() -> None:
    gateway = MCPGateway(interceptor=build_default_interceptor())

    try:
        result = await gateway.invoke(
            tool="http.get",
            args={"url": "https://example.com"},
            principal_did="did:demo:agent-1",
            tenant_id="default",
            executor=execute_tool,
        )
        print("tool ran:", result)
    except ToolDeniedError as exc:
        print("denied:", exc)


if __name__ == "__main__":
    asyncio.run(main())
