"""Owner: M7 (Isolation Forest anomaly detection)."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, utcnow


class AnomalyDetection(Base):
    __tablename__ = "anomaly_detections"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    audit_log_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("audit_logs.id", ondelete="SET NULL")
    )
    window_start: Mapped[datetime]
    window_end: Mapped[datetime]
    features: Mapped[dict[str, Any]]
    # IsolationForest.decision_function: lower = more anomalous.
    score: Mapped[float]
    is_anomaly: Mapped[bool]
    model_version: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
