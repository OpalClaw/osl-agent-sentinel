"""Embed sentinel directly in an agent runtime.

Run with::

    python examples/embedded_sdk.py
"""

from __future__ import annotations

import asyncio

from sentinel.bootstrap import build_default_interceptor
from sentinel.client import Sentinel
from sentinel.models.action import Action, ActionType


async def main() -> None:
    interceptor = build_default_interceptor()
    sentinel = Sentinel.embedded(interceptor)

    action = Action(
        type=ActionType.TOOL_CALL,
        tool="http.get",
        intent="fetch homepage",
        args={"url": "https://example.com"},
        tenant_id="default",
        principal_did="did:demo:agent-1",
    )

    decision = await sentinel.evaluate(action)
    print(f"verdict={decision.verdict.value} risk_score={decision.risk_score:.2f}")
    if decision.explanation:
        print(f"rationale: {decision.explanation.rationale}")
        print(f"triggered rules: {[r for r in decision.explanation.triggered_rules]}")


if __name__ == "__main__":
    asyncio.run(main())
