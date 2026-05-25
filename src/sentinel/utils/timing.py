"""Timing helpers."""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator


@contextmanager
def stopwatch() -> Iterator[dict[str, float]]:
    """Context manager that records elapsed milliseconds in the yielded dict.

    Usage::

        with stopwatch() as t:
            do_work()
        print(t["elapsed_ms"])
    """
    out: dict[str, float] = {"elapsed_ms": 0.0}
    start = time.perf_counter()
    try:
        yield out
    finally:
        out["elapsed_ms"] = (time.perf_counter() - start) * 1000.0
