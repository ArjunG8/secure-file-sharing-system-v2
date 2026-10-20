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
    """Validated shape of one model finding. Anything else in the model output is dropped."""

    model_config = {"extra": "ignore"}

    severity: Literal["low", "medium", "high", "critical"]
    title: str = Field(min_length=1, max_length=200)
    evidence_event_ids: list[int] = Field(default_factory=list, max_length=50)
    recommendation: str = Field(min_length=1, max_length=1000)


class ModelOutput(BaseModel):
    model_config = {"extra": "ignore"}

    summary: str = Field(min_length=1, max_length=4000)
    findings: list[Finding] = Field(default_factory=list, max_length=20)


class AnalysisOut(ORMModel):
    id: uuid.UUID
    status: Literal["pending", "completed", "failed"]
    provider: str
    model: str
    summary: str | None
    findings: list[Finding]
    created_at: datetime
    completed_at: datetime | None
