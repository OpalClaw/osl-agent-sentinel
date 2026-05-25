"""Prometheus-style metrics surface.

We expose a small, stable set of counters and histograms. The
:class:`Metrics` object holds prometheus_client primitives but degrades
to no-ops when prometheus_client is not importable, so the control plane
can run without the dependency.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

try:
    from prometheus_client import Counter, Histogram  # type: ignore

    _PROM = True
except Exception:  # pragma: no cover
    _PROM = False

    class _Noop:
        def labels(self, *_a, **_kw):
            return self

        def inc(self, *_a, **_kw): ...
        def observe(self, *_a, **_kw): ...

    Counter = Histogram = _Noop  # type: ignore[assignment,misc]


@dataclass(slots=True)
class Metrics:
    """Bundle of metric instruments."""

    actions_total: object
    decisions_total: object
    decision_latency_ms: object
    risk_factors_total: object
    policy_reloads_total: object
    breaker_state_changes_total: object

    _singleton: ClassVar[Metrics | None] = None

    @classmethod
    def default(cls) -> Metrics:
        if cls._singleton is not None:
            return cls._singleton
        instance = cls(
            actions_total=Counter(
                "sentinel_actions",
                "Total actions evaluated",
                ["tenant", "action_type"],
            ),
            decisions_total=Counter(
                "sentinel_decisions_total",
                "Total decisions emitted",
                ["tenant", "verdict", "degraded"],
            ),
            decision_latency_ms=Histogram(
                "sentinel_decision_latency_ms",
                "Decision pipeline latency in milliseconds",
                ["tenant"],
                buckets=(1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500),
            ),
            risk_factors_total=Counter(
                "sentinel_risk_factors_total",
                "Number of risk factors raised",
                ["tenant", "detector", "code"],
            ),
            policy_reloads_total=Counter(
                "sentinel_policy_reloads_total",
                "Successful policy bundle reloads",
                ["tenant", "status"],
            ),
            breaker_state_changes_total=Counter(
                "sentinel_breaker_state_changes_total",
                "Circuit breaker state changes",
                ["dependency", "to_state"],
            ),
        )
        cls._singleton = instance
        return instance
