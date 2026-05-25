"""MCP-aware gateway.

A thin shim that lets sentinel sit transparently in front of an MCP server
(or any tool-execution endpoint) and gate every call. The gateway accepts
a raw tool invocation, builds an :class:`Action`, asks the
:class:`Interceptor` for a decision, and executes the underlying tool only
when the decision is :class:`~sentinel.models.decision.DecisionVerdict.ALLOW`.

Two integration shapes are supported:

* **Bound-handler mode** — construct the gateway with a handler callable;
  every invocation routes through it.

* **Per-call executor mode** — construct the gateway with just an
  :class:`Interceptor`; the caller supplies an ``executor`` per
  :meth:`invoke` call. Useful in multi-tool runtimes where each tool has
  its own implementation.

By default :meth:`invoke` **raises** :class:`ToolDeniedError` on a
non-ALLOW verdict. Callers that want a result object can use
:meth:`evaluate`.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sentinel.models.action import Action, ActionType
from sentinel.models.decision import Decision, DecisionVerdict
from sentinel.utils.logging import get_logger

if TYPE_CHECKING:
    from sentinel.core.interceptor import Interceptor

log = get_logger(__name__)

ToolHandler = Callable[[str, dict[str, Any]], Awaitable[Any]]


class ToolDeniedError(Exception):
    """Raised by :meth:`MCPGateway.invoke` when the sentinel denies or
    escalates a tool invocation. The associated :class:`Decision` is
    attached for explainability and audit purposes.
    """

    def __init__(self, decision: Decision) -> None:
        reason_codes = (
            [r.code for r in decision.explanation.risk_factors] if decision.explanation else []
        )
        super().__init__(f"tool denied: verdict={decision.verdict.value} reasons={reason_codes}")
        self.decision = decision


@dataclass(slots=True)
class GatewayResult:
    """Outcome of a gated tool call when using :meth:`evaluate`."""

    decision: Decision
    output: Any | None = None
    blocked: bool = False


class MCPGateway:
    """Front the tool execution path with sentinel.

    Parameters
    ----------
    interceptor:
        The sentinel :class:`Interceptor` that owns the decision pipeline.
    handler:
        Optional default handler for bound-handler mode. When omitted,
        callers must pass an ``executor`` to every :meth:`invoke` call.
    """

    def __init__(
        self,
        interceptor: Interceptor,
        handler: ToolHandler | None = None,
    ) -> None:
        self._interceptor = interceptor
        self._handler = handler

    async def evaluate(
        self,
        *,
        tool: str,
        args: dict[str, Any] | None = None,
        principal_did: str | None = None,
        agent_did: str | None = None,
        tenant_id: str = "default",
        intent: str | None = None,
        executor: ToolHandler | None = None,
    ) -> GatewayResult:
        """Evaluate (and conditionally execute) a tool invocation.

        Returns a :class:`GatewayResult` carrying both the decision and the
        executor output (when allowed). Does not raise on denial.
        """
        agent = principal_did or agent_did or "did:anon:unknown"
        action = Action(
            type=ActionType.TOOL_CALL,
            tool=tool,
            arguments=args or {},
            agent_did=agent,
            tenant_id=tenant_id,
            intent=intent,
        )
        decision = await self._interceptor.evaluate(action)
        if decision.verdict != DecisionVerdict.ALLOW:
            log.info(
                "gateway.blocked",
                tool=tool,
                agent_did=agent,
                tenant_id=tenant_id,
                verdict=decision.verdict.value,
            )
            return GatewayResult(decision=decision, blocked=True)

        runner = executor or self._handler
        if runner is None:
            raise RuntimeError(
                "MCPGateway.invoke called without an executor and no default "
                "handler was bound at construction time."
            )
        output = await runner(tool, args or {})
        return GatewayResult(decision=decision, output=output, blocked=False)

    async def invoke(
        self,
        *,
        tool: str,
        args: dict[str, Any] | None = None,
        principal_did: str | None = None,
        agent_did: str | None = None,
        tenant_id: str = "default",
        intent: str | None = None,
        executor: ToolHandler | None = None,
    ) -> Any:
        """Evaluate, execute on ALLOW, raise :class:`ToolDeniedError` otherwise.

        This is the ergonomic default for application code: callers either
        get the executor's return value or an explicit denial error they
        can attach to a user-visible message.
        """
        result = await self.evaluate(
            tool=tool,
            args=args,
            principal_did=principal_did,
            agent_did=agent_did,
            tenant_id=tenant_id,
            intent=intent,
            executor=executor,
        )
        if result.blocked:
            raise ToolDeniedError(result.decision)
        return result.output


__all__ = ["GatewayResult", "MCPGateway", "ToolDeniedError", "ToolHandler"]
