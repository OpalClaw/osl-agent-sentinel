"""Execution sandbox shim.

This module exposes a small Python facade over the Rust ``sentinel-engine``
crate, which provides the actual ring-based isolation. When the Rust
extension is not installed, the sandbox falls back to a pure-Python
emulator suitable for tests and local development. Production deployments
should always install the Rust wheel.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Awaitable, Callable

from sentinel.utils.logging import get_logger

log = get_logger(__name__)


class ExecutionRing(str, Enum):
    """Isolation tiers, increasing in restriction."""

    R0_TRUSTED = "R0"        # local, full host access
    R1_NAMESPACED = "R1"     # OS-level namespace isolation
    R2_CONTAINER = "R2"      # OCI container per call
    R3_REMOTE_VM = "R3"      # ephemeral VM / microVM per call


@dataclass(slots=True)
class SandboxResult:
    """Outcome of a sandboxed call."""

    output: Any | None
    duration_ms: float
    ring: ExecutionRing
    truncated: bool = False
    error: str | None = None


class Sandbox:
    """Runs callable workloads inside the requested isolation ring.

    The Python facade defers to the Rust core when ``sentinel_engine`` is
    importable. Otherwise it runs the workload in-process while still
    enforcing wall-clock and result-size budgets, so tests behave
    consistently.
    """

    def __init__(self) -> None:
        try:
            import sentinel_engine  # type: ignore[import-not-found]

            self._engine = sentinel_engine
        except Exception:
            self._engine = None
            log.info("sandbox.engine_unavailable", fallback="python")

    async def run(
        self,
        workload: Callable[[], Awaitable[Any]],
        *,
        ring: ExecutionRing = ExecutionRing.R2_CONTAINER,
        max_ms: int = 500,
        max_result_bytes: int = 1024 * 1024,
    ) -> SandboxResult:
        if self._engine is not None:
            return await self._run_native(workload, ring, max_ms, max_result_bytes)
        return await self._run_python(workload, ring, max_ms, max_result_bytes)

    async def _run_native(
        self,
        workload: Callable[[], Awaitable[Any]],
        ring: ExecutionRing,
        max_ms: int,
        max_result_bytes: int,
    ) -> SandboxResult:
        # Cooperative bridge: the Rust core enforces the ring; the workload
        # itself still runs in Python. The Rust core is responsible for
        # process / namespace / VM placement around this thread.
        start = time.perf_counter()
        try:
            with self._engine.guard(  # type: ignore[attr-defined]
                ring=ring.value, max_ms=max_ms, max_result_bytes=max_result_bytes
            ):
                output = await workload()
        except Exception as exc:  # noqa: BLE001
            return SandboxResult(
                output=None,
                duration_ms=(time.perf_counter() - start) * 1000.0,
                ring=ring,
                error=str(exc),
            )
        return SandboxResult(
            output=output,
            duration_ms=(time.perf_counter() - start) * 1000.0,
            ring=ring,
        )

    async def _run_python(
        self,
        workload: Callable[[], Awaitable[Any]],
        ring: ExecutionRing,
        max_ms: int,
        max_result_bytes: int,
    ) -> SandboxResult:
        import asyncio

        start = time.perf_counter()
        try:
            output = await asyncio.wait_for(workload(), timeout=max_ms / 1000.0)
        except asyncio.TimeoutError:
            return SandboxResult(
                output=None,
                duration_ms=(time.perf_counter() - start) * 1000.0,
                ring=ring,
                error="timeout",
            )
        except Exception as exc:  # noqa: BLE001
            return SandboxResult(
                output=None,
                duration_ms=(time.perf_counter() - start) * 1000.0,
                ring=ring,
                error=str(exc),
            )

        truncated = False
        try:
            size = len(str(output).encode("utf-8"))
        except Exception:
            size = 0
        if size > max_result_bytes:
            output = None
            truncated = True
        return SandboxResult(
            output=output,
            duration_ms=(time.perf_counter() - start) * 1000.0,
            ring=ring,
            truncated=truncated,
        )
