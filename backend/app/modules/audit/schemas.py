import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel

Outcome = Literal["success", "failure", "denied"]


class AuditEventIn(BaseModel):
    """What other modules pass to record_event. Never include secrets or file contents."""

    event_type: str = Field(max_length=64)  # see docs/api-contracts.md "Standard event types"
    outcome: Outcome = "success"
    actor_user_id: uuid.UUID | None = None
    resource_type: str | None = Field(default=None, max_length=32)
    resource_id: str | None = Field(default=None, max_length=64)
    ip_address: str | None = Field(default=None, max_length=45)
    user_agent: str | None = Field(default=None, max_length=512)
    details: dict[str, Any] = Field(default_factory=dict)


class AuditLogOut(ORMModel):
    id: int
    occurred_at: datetime
    actor_user_id: uuid.UUID | None
    event_type: str
    outcome: Outcome
    resource_type: str | None
    resource_id: str | None
    ip_address: str | None
    details: dict[str, Any]
    prev_hash: str
    entry_hash: str


class ChainVerification(BaseModel):
    valid: bool
    checked_entries: int
    first_broken_id: int | None = None
    reason: str | None = None
