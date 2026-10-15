"""M7 public interface. Implementation notes: docs/security-design.md, section M7."""

from datetime import datetime

from sqlalchemy.orm import Session

from app.core.errors import NotImplementedFeature
from app.models import AnomalyDetection, AuditLog
from app.modules.anomaly import MODULE_INFO
from app.modules.anomaly.schemas import ModelInfoOut


def extract_features(events: list[AuditLog]) -> list[dict[str, float]]:
    """Aggregate audit events into one feature vector per (user, 1-hour window)."""
    raise NotImplementedFeature(MODULE_INFO, "Feature extraction")


def train_model(db: Session, since: datetime | None = None) -> ModelInfoOut:
    """Fit sklearn IsolationForest on extracted features and persist it to MODEL_DIR."""
    raise NotImplementedFeature(MODULE_INFO, "Isolation Forest training")


def score_recent(db: Session, since: datetime | None = None) -> list[AnomalyDetection]:
    """Score recent windows with the latest model and store rows in anomaly_detections."""
    raise NotImplementedFeature(MODULE_INFO, "Anomaly scoring")
