"""Kong external authorization adapter.

Translates a Kong forward-auth request into a sentinel :class:`Action`,
evaluates it, and returns a tuple of ``(status_code, body, headers)`` for
the plugin to apply.
"""

from __future__ import annotations

from typing import Any

from sentinel.core.interceptor import Interceptor
from sentinel.models.action import Action, ActionType
from sentinel.models.decision import DecisionVerdict


class KongPluginAdapter:
    """Bridge for Kong's pre-function or forward-auth plugin."""

    def __init__(self, interceptor: Interceptor) -> None:
        self._interceptor = interceptor

    async def authorize(self, kong_ctx: dict[str, Any]) -> tuple[int, dict[str, Any], dict[str, str]]:
        action = Action(
            type=ActionType.HTTP_REQUEST,
            agent_did=kong_ctx.get("agent_did", "did:unknown:anonymous"),
            tool=f"{kong_ctx.get('method', 'GET')} {kong_ctx.get('path', '/')}",
            arguments={
                "headers": kong_ctx.get("headers", {}),
                "query": kong_ctx.get("query", {}),
                "body_preview": str(kong_ctx.get("body", ""))[:4096],
            },
            intent=kong_ctx.get("intent"),
        )
        decision = await self._interceptor.evaluate(action)
        if decision.verdict == DecisionVerdict.ALLOW:
            return 200, {"ok": True}, {"x-sentinel-decision": "allow"}
        return (
            403,
            {"error": "blocked_by_sentinel", "explanation": decision.explanation},
            {"x-sentinel-decision": decision.verdict.value},
        )
