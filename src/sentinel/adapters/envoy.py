"""Envoy / Istio ext_authz adapter.

Speaks the Envoy ``CheckRequest`` shape and emits a ``CheckResponse``
shape that the proxy can interpret as ALLOW or DENY.
"""

from __future__ import annotations

from typing import Any

from sentinel.core.interceptor import Interceptor
from sentinel.models.action import Action, ActionType
from sentinel.models.decision import DecisionVerdict


class EnvoyExtAuthzAdapter:
    def __init__(self, interceptor: Interceptor) -> None:
        self._interceptor = interceptor

    async def check(self, check_request: dict[str, Any]) -> dict[str, Any]:
        attrs = check_request.get("attributes", {}).get("request", {}).get("http", {})
        action = Action(
            type=ActionType.HTTP_REQUEST,
            agent_did=attrs.get("headers", {}).get("x-agent-did", "did:unknown:anonymous"),
            tool=f"{attrs.get('method', 'GET')} {attrs.get('path', '/')}",
            arguments={"headers": attrs.get("headers", {}), "body": attrs.get("body", "")[:4096]},
            intent=attrs.get("headers", {}).get("x-agent-intent"),
        )
        decision = await self._interceptor.evaluate(action)
        if decision.verdict == DecisionVerdict.ALLOW:
            return {"status": {"code": 0}, "ok_response": {}}
        return {
            "status": {"code": 7},  # PERMISSION_DENIED
            "denied_response": {
                "status": {"code": 403},
                "body": '{"error":"blocked_by_sentinel"}',
                "headers": [
                    {"header": {"key": "x-sentinel-decision", "value": decision.verdict.value}}
                ],
            },
        }
