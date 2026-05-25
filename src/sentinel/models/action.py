"""Canonical action schema.

An :class:`Action` is the unit of work an agent proposes to perform.
Sentinel intercepts each one before execution and emits a
:class:`~sentinel.models.decision.Decision` for it.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class ActionType(str, Enum):
    """The kinds of actions sentinel governs."""

    TOOL_CALL = "tool_call"
    FILE_WRITE = "file_write"
    FILE_READ = "file_read"
    HTTP_REQUEST = "http_request"
    CODE_EXECUTION = "code_execution"
    SHELL_COMMAND = "shell_command"
    AGENT_MESSAGE = "agent_message"
    MEMORY_WRITE = "memory_write"
    MEMORY_READ = "memory_read"
    LLM_PROMPT = "llm_prompt"
    PAYMENT = "payment"
    NOTIFICATION = "notification"
    DATABASE_QUERY = "database_query"
    OTHER = "other"


class ActionContext(BaseModel):
    """Operational context attached to every action."""

    model_config = ConfigDict(extra="forbid")

    session_id: UUID = Field(default_factory=uuid4)
    parent_action_id: UUID | None = None
    correlation_id: str | None = None
    tenant_id: str = "default"
    environment: str = "production"
    invoked_by: str | None = Field(
        default=None,
        description="DID or stable identifier of the upstream invoker.",
    )
    plan_id: UUID | None = None
    step_index: int | None = None
    tags: dict[str, str] = Field(default_factory=dict)


class Action(BaseModel):
    """A proposed agent action awaiting evaluation."""

    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    type: ActionType
    agent_did: str = Field(
        ...,
        description="Decentralized identifier of the agent proposing this action.",
        min_length=8,
    )
    tool: str | None = Field(
        default=None,
        description="Name of the tool/operation being invoked, if applicable.",
    )
    arguments: dict[str, Any] = Field(default_factory=dict)
    payload_digest: str | None = Field(
        default=None,
        description="SHA-256 digest of the canonical payload (computed by interceptor).",
    )
    intent: str | None = Field(
        default=None,
        description="Natural-language statement of intent for this action.",
    )
    context: ActionContext = Field(default_factory=ActionContext)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def canonical_dict(self) -> dict[str, Any]:
        """Return a deterministic dict representation for signing/hashing."""
        return self.model_dump(mode="json", exclude={"payload_digest", "created_at"})
