import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel

from app.schemas.common import ORMModel


class TrainRequest(BaseModel):
    since: datetime | None = None


class ScoreRequest(BaseModel):
    since: datetime | None = None


class ModelInfoOut(BaseModel):
    model_version: str
    trained_on_events: int
    features: list[str]
    contamination: float


class AnomalyOut(ORMModel):
    id: uuid.UUID
    user_id: uuid.UUID | None
    audit_log_id: int | None
    window_start: datetime
    window_end: datetime
    features: dict[str, Any]
    score: float
    is_anomaly: bool
    model_version: str
    created_at: datetime
