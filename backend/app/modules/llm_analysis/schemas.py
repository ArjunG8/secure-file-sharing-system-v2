import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel


class AnalysisRequest(BaseModel):
    since: datetime
    until: datetime
    include_anomalies: bool = True
    max_events: int = Field(default=200, ge=1, le=1000)


class Finding(BaseModel):
    severity: Literal["low", "medium", "high", "critical"]
    title: str
    evidence_event_ids: list[int] = Field(default_factory=list)
    recommendation: str


class AnalysisOut(ORMModel):
    id: uuid.UUID
    status: Literal["pending", "completed", "failed"]
    provider: str
    model: str
    summary: str | None
    findings: list[Finding]
    created_at: datetime
    completed_at: datetime | None
