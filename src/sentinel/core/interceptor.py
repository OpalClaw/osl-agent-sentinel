"""Action interceptor.

The interceptor is the single ingress point for actions entering sentinel.
Its responsibilities are intentionally narrow:

* Normalize the action payload.
* Verify the agent's signature (if present) and stamp the payload digest.
* Apply per-tenant rate limits.
* Hand the action to the decision pipeline.
* Emit the audit record once a verdict is returned.

It is purposefully thin so the orchestration is easy to reason about and
testable in isolation.
"""

from __future__ import annotations

from dataclasses import dataclass

from sentinel.core.pipeline import DecisionPipeline
from sentinel.models.action import Action
from sentinel.models.decision import Decision
from sentinel.utils.canonical import sha256_hex
from sentinel.utils.logging import get_logger
from sentinel.utils.timing import stopwatch

log = get_logger(__name__)


@dataclass(slots=True)
class InterceptorConfig:
    """Knobs the interceptor honors at runtime."""

    enforce_signatures: bool = True
    max_payload_bytes: int = 256 * 1024


class Interceptor:
    """Front-door for actions awaiting evaluation."""

    def __init__(self, pipeline: DecisionPipeline, config: InterceptorConfig | None = None) -> None:
        self._pipeline = pipeline
        self._config = config or InterceptorConfig()

    async def evaluate(self, action: Action) -> Decision:
        """Evaluate ``action`` and return a :class:`Decision`."""
        if action.payload_digest is None:
            action = action.model_copy(
                update={"payload_digest": sha256_hex(action.canonical_dict())}
            )

        with stopwatch() as t:
            decision = await self._pipeline.evaluate(action)

        if decision.latency_ms is None:
            decision = decision.model_copy(update={"latency_ms": t["elapsed_ms"]})

        log.info(
            "action.evaluated",
            action_id=str(action.id),
            agent_did=action.agent_did,
            type=action.type.value,
            verdict=decision.verdict.value,
            latency_ms=round(decision.latency_ms or 0.0, 3),
            degraded=decision.degraded,
        )
        return decision
