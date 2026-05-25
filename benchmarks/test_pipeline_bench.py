"""Pipeline throughput micro-benchmarks."""

from __future__ import annotations

import asyncio

import pytest

from sentinel.models.action import Action, ActionType


@pytest.mark.benchmark(group="evaluate")
def test_pipeline_allow_path(benchmark, interceptor, trusted_identity):
    loop = asyncio.new_event_loop()

    def run() -> None:
        action = Action(
            type=ActionType.TOOL_CALL,
            tool="http.get",
            intent="fetch",
            args={"url": "https://example.com"},
            tenant_id="default",
            principal_did=trusted_identity.did,
        )
        loop.run_until_complete(interceptor.evaluate(action))

    try:
        benchmark(run)
    finally:
        loop.close()
