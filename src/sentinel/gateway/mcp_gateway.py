"""MCP-aware gateway.

A thin shim that lets sentinel sit transparently in front of an MCP server
(or any tool-execution endpoint) and gate every call. The gateway accepts
a raw tool invocation, builds an :class:`Action`, asks the
:class:`Interceptor` for a decision, and executes the underlying tool only
when the decision permits.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from sentinel.core.interceptor import Interceptor
from sentinel.models.action import Action, ActionType
from sentinel.models.decision import Decision, DecisionVerdict
from sentinel.utils.logging import get_logger

log = get_logger(__name__)

ToolHandler = Callable[[str, dict[str, Any]], Awaitable[Any]]


@dataclass(slots=True)
class GatewayResult:
    """Outcome of a gated tool call."""

    decision: Decision
    output: Any | None = None
    blocked: bool = False


class MCPGateway:
    """Front the tool execution path with sentinel."""

    def __init__(self, interceptor: Interceptor, handler: ToolHandler) -> None:
        self._interceptor = interceptor
        self._handler = handler

    async def invoke(
        self,
        *,
        agent_did: str,
        tool: str,
        arguments: dict[str, Any],
        intent: str | None = None,
    ) -> GatewayResult:
        action = Action(
            type=ActionType.TOOL_CALL,
            agent_did=agent_did,
            tool=tool,
            arguments=arguments,
            intent=intent,
        )
        decision = await self._interceptor.evaluate(action)
        if decision.verdict != DecisionVerdict.ALLOW:
            log.info(
                "gateway.blocked",
                tool=tool,
                agent_did=agent_did,
                verdict=decision.verdict.value,
            )
            return GatewayResult(decision=decision, blocked=True)
        output = await self._handler(tool, arguments)
        return GatewayResult(decision=decision, output=output, blocked=False)
