"""AWS API Gateway Lambda authorizer adapter.

Returns a policy document that API Gateway interprets as Allow or Deny.
"""

from __future__ import annotations

from typing import Any

from sentinel.core.interceptor import Interceptor
from sentinel.models.action import Action, ActionType
from sentinel.models.decision import DecisionVerdict


class AWSAPIGatewayAdapter:
    def __init__(self, interceptor: Interceptor) -> None:
        self._interceptor = interceptor

    async def authorize(self, event: dict[str, Any]) -> dict[str, Any]:
        headers = event.get("headers", {})
        action = Action(
            type=ActionType.HTTP_REQUEST,
            agent_did=headers.get("x-agent-did", "did:unknown:anonymous"),
            tool=f"{event.get('httpMethod', 'GET')} {event.get('path', '/')}",
            arguments={"headers": headers, "query": event.get("queryStringParameters") or {}},
            intent=headers.get("x-agent-intent"),
        )
        decision = await self._interceptor.evaluate(action)
        allow = decision.verdict == DecisionVerdict.ALLOW
        return {
            "principalId": action.agent_did,
            "policyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Action": "execute-api:Invoke",
                        "Effect": "Allow" if allow else "Deny",
                        "Resource": event.get("methodArn", "*"),
                    }
                ],
            },
            "context": {
                "sentinelDecision": decision.verdict.value,
                "explanation": (decision.explanation or "")[:1024],
            },
        }
