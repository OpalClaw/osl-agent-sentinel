"""Behavioral anomaly detector.

Maintains a per-identity sliding window of recent action types, tools, and
rates. Spikes against the rolling baseline produce risk factors. The model
is intentionally lightweight (no external ML dependency at runtime); a
pluggable ``BaselineStore`` allows production deployments to use Redis or
a feature store.
"""

from __future__ import annotations

import math
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Protocol

from sentinel.models.action import Action
from sentinel.models.decision import RiskFactor
from sentinel.models.identity import Identity


@dataclass(slots=True)
class _AgentWindow:
    """Per-agent rolling window."""

    actions: Deque[tuple[float, str, str]] = field(default_factory=deque)
    horizon_seconds: float = 300.0


class BaselineStore(Protocol):
    """Pluggable backing store for anomaly baselines."""

    async def get_window(self, agent_did: str) -> _AgentWindow: ...
    async def record(self, agent_did: str, action: Action) -> None: ...


class InMemoryBaselineStore:
    """Single-process baseline store used by default."""

    def __init__(self, horizon_seconds: float = 300.0) -> None:
        self._windows: dict[str, _AgentWindow] = {}
        self._horizon = horizon_seconds

    async def get_window(self, agent_did: str) -> _AgentWindow:
        return self._windows.setdefault(agent_did, _AgentWindow(horizon_seconds=self._horizon))

    async def record(self, agent_did: str, action: Action) -> None:
        win = await self.get_window(agent_did)
        now = time.monotonic()
        win.actions.append((now, action.type.value, action.tool or ""))
        cutoff = now - win.horizon_seconds
        while win.actions and win.actions[0][0] < cutoff:
            win.actions.popleft()


class AnomalyDetector:
    """Detect frequency and tool-diversity anomalies."""

    def __init__(
        self,
        store: BaselineStore | None = None,
        *,
        spike_factor: float = 4.0,
        rare_tool_min_observations: int = 25,
    ) -> None:
        self._store = store or InMemoryBaselineStore()
        self._spike_factor = spike_factor
        self._rare_min = rare_tool_min_observations

    async def score(self, action: Action, identity: Identity | None) -> list[RiskFactor]:
        win = await self._store.get_window(action.agent_did)
        factors: list[RiskFactor] = []

        n = len(win.actions)
        rate = n / max(win.horizon_seconds, 1.0)
        if n > 50 and rate > self._spike_factor * (1.0 / 60.0):
            factors.append(
                RiskFactor(
                    code="anomaly.rate_spike",
                    severity=min(1.0, math.log10(rate + 1) / 2.0),
                    detector="anomaly_detector",
                    message="Agent action rate exceeded expected baseline.",
                    evidence={
                        "actions_in_window": str(n),
                        "rate_per_sec": f"{rate:.3f}",
                        "references": "OWASP-AGENT-05,OWASP-AGENT-09",
                    },
                )
            )

        if action.tool:
            tool_observations = sum(1 for _, _, tool in win.actions if tool == action.tool)
            if n >= self._rare_min and tool_observations == 0:
                factors.append(
                    RiskFactor(
                        code="anomaly.novel_tool",
                        severity=0.4,
                        detector="anomaly_detector",
                        message=f"First observed use of tool '{action.tool}' by this agent.",
                        evidence={
                            "tool": action.tool,
                            "window_size": str(n),
                            "references": "OWASP-AGENT-05",
                        },
                    )
                )

        await self._store.record(action.agent_did, action)
        return factors
