"""Human-in-the-loop approval workflow.

When the pipeline emits ``ESCALATE``, the action is parked in this workflow
until a human (or another authorized reviewer) renders a verdict. The
workflow is asynchronous and pluggable: any backend that implements the
``ApprovalBackend`` protocol can be wired in.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Protocol
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from sentinel.models.action import Action
from sentinel.models.decision import Decision, DecisionVerdict


class PendingApproval(BaseModel):
    """An action awaiting human review."""

    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    action: Action
    initial_decision: Decision
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    resolved_at: datetime | None = None
    resolution: DecisionVerdict | None = None
    resolver: str | None = None
    notes: str | None = None


class ApprovalBackend(Protocol):
    """Pluggable persistence for pending approvals."""

    async def enqueue(self, item: PendingApproval) -> None: ...
    async def resolve(self, item_id: UUID, verdict: DecisionVerdict, resolver: str, notes: str | None) -> PendingApproval: ...
    async def get(self, item_id: UUID) -> PendingApproval | None: ...


class InMemoryApprovalBackend:
    """Default backend; suitable for tests and single-node deployments."""

    def __init__(self) -> None:
        self._items: dict[UUID, PendingApproval] = {}

    async def enqueue(self, item: PendingApproval) -> None:
        self._items[item.id] = item

    async def resolve(
        self,
        item_id: UUID,
        verdict: DecisionVerdict,
        resolver: str,
        notes: str | None,
    ) -> PendingApproval:
        item = self._items[item_id]
        resolved = item.model_copy(
            update={
                "resolution": verdict,
                "resolver": resolver,
                "notes": notes,
                "resolved_at": datetime.now(timezone.utc),
            }
        )
        self._items[item_id] = resolved
        return resolved

    async def get(self, item_id: UUID) -> PendingApproval | None:
        return self._items.get(item_id)


class ApprovalWorkflow:
    """Coordinates escalations and waits for human resolution."""

    def __init__(self, backend: ApprovalBackend | None = None) -> None:
        self._backend = backend or InMemoryApprovalBackend()

    async def submit(self, action: Action, decision: Decision) -> PendingApproval:
        item = PendingApproval(action=action, initial_decision=decision)
        await self._backend.enqueue(item)
        return item

    async def resolve(
        self,
        item_id: UUID,
        verdict: DecisionVerdict,
        resolver: str,
        notes: str | None = None,
    ) -> PendingApproval:
        return await self._backend.resolve(item_id, verdict, resolver, notes)

    async def get(self, item_id: UUID) -> PendingApproval | None:
        return await self._backend.get(item_id)
