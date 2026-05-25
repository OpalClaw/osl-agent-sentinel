"""Circuit breaker for dependency failures.

If a downstream dependency (policy source, identity resolver, DLP scanner)
fails repeatedly, we trip the breaker for that dependency. While the
breaker is open, calls fail fast with :class:`DependencyUnavailableError`.
After ``reset_timeout`` we move to half-open and let a small number of
probe calls through.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, TypeVar

from sentinel.utils.errors import DependencyUnavailableError
from sentinel.utils.logging import get_logger

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

log = get_logger(__name__)

T = TypeVar("T")


class CircuitState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass(slots=True)
class CircuitBreaker:
    """A simple, asyncio-safe breaker.

    Attributes
    ----------
    name:
        Used in logs/metrics.
    failure_threshold:
        Consecutive failures that trip the breaker.
    reset_timeout:
        Seconds before transitioning from OPEN to HALF_OPEN.
    half_open_probes:
        Number of probe calls allowed in HALF_OPEN.
    """

    name: str = "breaker"
    failure_threshold: int = 5
    reset_timeout: float = 30.0
    half_open_probes: int = 3
    _state: CircuitState = CircuitState.CLOSED
    _failures: int = 0
    _opened_at: float = 0.0
    _probes_in_flight: int = 0
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    @property
    def state(self) -> CircuitState:
        return self._state

    async def call(self, fn: Callable[[], Awaitable[T]]) -> T:
        async with self._lock:
            self._maybe_transition_to_half_open()
            if self._state is CircuitState.OPEN:
                raise DependencyUnavailableError(f"circuit '{self.name}' is open")
            if self._state is CircuitState.HALF_OPEN:
                if self._probes_in_flight >= self.half_open_probes:
                    raise DependencyUnavailableError(
                        f"circuit '{self.name}' half-open probe budget exhausted"
                    )
                self._probes_in_flight += 1

        try:
            result = await fn()
        except Exception:
            await self._record_failure()
            raise
        else:
            await self._record_success()
            return result

    # ------------------------------------------------------------------ state

    def _maybe_transition_to_half_open(self) -> None:
        if self._state is CircuitState.OPEN:
            if (time.monotonic() - self._opened_at) >= self.reset_timeout:
                log.warning("circuit.half_open", name=self.name)
                self._state = CircuitState.HALF_OPEN
                self._probes_in_flight = 0

    async def _record_failure(self) -> None:
        async with self._lock:
            self._failures += 1
            if self._state is CircuitState.HALF_OPEN or self._failures >= self.failure_threshold:
                self._trip()

    async def _record_success(self) -> None:
        async with self._lock:
            if self._state is CircuitState.HALF_OPEN:
                self._probes_in_flight = max(0, self._probes_in_flight - 1)
                if self._probes_in_flight == 0:
                    log.info("circuit.closed", name=self.name)
                    self._state = CircuitState.CLOSED
                    self._failures = 0
            else:
                self._failures = 0

    def _trip(self) -> None:
        log.error("circuit.open", name=self.name, failures=self._failures)
        self._state = CircuitState.OPEN
        self._opened_at = time.monotonic()
        self._probes_in_flight = 0
