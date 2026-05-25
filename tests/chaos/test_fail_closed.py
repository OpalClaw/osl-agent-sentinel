"""Chaos: pipeline degrades fail-closed when dependencies fail."""

from __future__ import annotations

import pytest

from sentinel.core.circuit_breaker import CircuitBreaker
from sentinel.utils.errors import DependencyUnavailableError


@pytest.mark.asyncio
async def test_breaker_opens_after_threshold():
    breaker = CircuitBreaker(failure_threshold=2, reset_timeout=10.0)

    async def fail():
        raise RuntimeError("dep down")

    with pytest.raises(RuntimeError):
        await breaker.call(fail)
    with pytest.raises(RuntimeError):
        await breaker.call(fail)
    with pytest.raises(DependencyUnavailableError):
        await breaker.call(fail)
