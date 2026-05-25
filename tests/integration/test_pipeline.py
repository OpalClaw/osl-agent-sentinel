"""Integration tests for the decision pipeline."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from sentinel.models.action import Action, ActionType
from sentinel.models.decision import DecisionVerdict

if TYPE_CHECKING:
    from sentinel.core.interceptor import Interceptor
    from sentinel.models.identity import Identity


@pytest.mark.asyncio
async def test_unknown_tool_is_denied(interceptor: Interceptor, trusted_identity: Identity):
    action = Action(
        type=ActionType.TOOL_CALL,
        tool="unknown.tool",
        intent="do something",
        args={},
        tenant_id="default",
        principal_did=trusted_identity.did,
    )
    decision = await interceptor.evaluate(action)
    assert decision.verdict is DecisionVerdict.DENY


@pytest.mark.asyncio
async def test_code_exec_escalates(interceptor: Interceptor, trusted_identity: Identity):
    action = Action(
        type=ActionType.CODE_EXEC,
        tool=None,
        intent="run script",
        args={"command": "ls"},
        tenant_id="default",
        principal_did=trusted_identity.did,
    )
    decision = await interceptor.evaluate(action)
    assert decision.verdict is DecisionVerdict.ESCALATE
    assert decision.explanation is not None
    assert decision.explanation.rationale


@pytest.mark.asyncio
async def test_allowed_tool_call(interceptor: Interceptor, trusted_identity: Identity):
    action = Action(
        type=ActionType.TOOL_CALL,
        tool="http.get",
        intent="fetch data",
        args={"url": "https://example.com"},
        tenant_id="default",
        principal_did=trusted_identity.did,
    )
    decision = await interceptor.evaluate(action)
    assert decision.verdict is DecisionVerdict.ALLOW
