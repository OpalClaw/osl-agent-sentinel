"""Audit record model.

Audit records are append-only, hash-chained, and signed. They are the
externally-verifiable substrate that compliance, IR, and forensics teams
consume.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from sentinel.models.action import Action
from sentinel.models.decision import Decision


class AuditRecord(BaseModel):
    """An immutable audit-log entry."""

    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    sequence: int = Field(..., ge=0, description="Monotonic per-tenant sequence number.")
    tenant_id: str = "default"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    action: Action
    decision: Decision
    previous_digest: str = Field(
        ...,
        description="SHA-256 of the previous record. The first record in a chain uses 64 zero hex chars.",
    )
    record_digest: str = Field(
        ...,
        description="SHA-256 of this record's canonical content including previous_digest.",
    )
    signature: str | None = None
