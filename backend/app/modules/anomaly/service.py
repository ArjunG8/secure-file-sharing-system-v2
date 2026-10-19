"""M7 public interface. Implementation notes: docs/security-design.md, section M7.

Isolation Forest is unsupervised: it learns what "usual" user-hours look like from the
audit log and scores how isolated each new user-hour is. It flags candidates for a human
(or M8) to review; it never blocks anyone by itself.
"""

from datetime import UTC, datetime, timedelta

import numpy as np
from sklearn.ensemble import IsolationForest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import AppError
from app.models import AnomalyDetection, AuditLog
from app.modules.anomaly import MODULE_INFO, model_store
from app.modules.anomaly.features import FEATURES, Window, extract_features, extract_windows
from app.modules.anomaly.schemas import ModelInfoOut
from app.modules.audit import service as audit_service
from app.modules.audit.schemas import AuditEventIn

__all__ = ["extract_features", "train_model", "score_recent", "list_detections"]

MIN_TRAINING_WINDOWS = 20
N_ESTIMATORS = 200
RANDOM_STATE = 42


def _events(db: Session, since: datetime | None) -> list[AuditLog]:
    query = select(AuditLog).where(AuditLog.actor_user_id.is_not(None)).order_by(AuditLog.id)
    if since is not None:
        query = query.where(AuditLog.occurred_at >= since)
    return list(db.scalars(query))


def _matrix(windows: list[Window]) -> np.ndarray:
    return np.array([w.vector() for w in windows], dtype=float)


def _audit(db: Session, event_type: str, outcome: str = "success", **fields) -> None:
    audit_service.record_event(db, AuditEventIn(event_type=event_type, outcome=outcome,
                                                **fields))


def fit(windows: list[Window], contamination: float) -> IsolationForest:
    model = IsolationForest(n_estimators=N_ESTIMATORS, contamination=contamination,
                            random_state=RANDOM_STATE)
    return model.fit(_matrix(windows))


def train_model(db: Session, since: datetime | None = None) -> ModelInfoOut:
    """Fit an Isolation Forest on the audit log's user-hour windows and persist it."""
    events = _events(db, since)
    windows = extract_windows(events)
    if len(windows) < MIN_TRAINING_WINDOWS:
        raise AppError(
            422,
            f"Not enough activity to train: {len(windows)} user-hour windows, "
            f"need at least {MIN_TRAINING_WINDOWS}.",
            module=MODULE_INFO.code,
        )
    contamination = get_settings().anomaly_contamination
    model = fit(windows, contamination)
    version = "iforest-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    meta = model_store.save(model, {
        "model_version": version, "features": list(FEATURES),
        "trained_on_windows": len(windows), "trained_on_events": len(events),
        "contamination": contamination,
    })
    _audit(db, "anomaly.train", details={"model_version": version,
                                         "windows": len(windows), "events": len(events)})
    return ModelInfoOut(model_version=meta.model_version, trained_on_events=len(events),
                        trained_on_windows=len(windows), features=meta.features,
                        contamination=contamination)


def _load_model(db: Session):
    try:
        loaded = model_store.load_latest()
    except model_store.ModelIntegrityError as exc:
        _audit(db, "anomaly.model_integrity_failure", "failure", details={"error": str(exc)})
        raise AppError(500, "The stored model failed its integrity check; retrain it.",
                       module=MODULE_INFO.code) from exc
    if loaded is None:
        raise AppError(409, "No model has been trained yet.", module=MODULE_INFO.code)
    model, meta = loaded
    if meta.features != list(FEATURES):
        raise AppError(409, "The stored model uses different features; retrain it.",
                       module=MODULE_INFO.code)
    return model, meta


def score_windows(model: IsolationForest, windows: list[Window]) -> list[tuple[float, bool]]:
    if not windows:
        return []
    matrix = _matrix(windows)
    scores = model.decision_function(matrix)  # < 0 means "more isolated than usual"
    flags = model.predict(matrix) == -1
    return [(float(s), bool(f)) for s, f in zip(scores, flags, strict=True)]


def score_recent(db: Session, since: datetime | None = None) -> list[AnomalyDetection]:
    """Score user-hour windows since `since` (default: last 24 h) and store detections."""
    model, meta = _load_model(db)
    since = since or datetime.now(UTC) - timedelta(hours=24)
    windows = extract_windows(_events(db, since))
    detections = []
    for window, (score, is_anomaly) in zip(windows, score_windows(model, windows), strict=True):
        detection = AnomalyDetection(
            user_id=window.user_id, audit_log_id=window.last_event_id,
            window_start=window.window_start, window_end=window.window_end,
            features=dict(window.counts), score=score, is_anomaly=is_anomaly,
            model_version=meta.model_version,
        )
        db.add(detection)
        detections.append(detection)
        if is_anomaly:
            _audit(db, "anomaly.detected", actor_user_id=window.user_id,
                   resource_type="user", resource_id=str(window.user_id),
                   details={"score": round(score, 4),
                            "window_start": window.window_start.isoformat()})
    db.flush()
    _audit(db, "anomaly.score", details={"model_version": meta.model_version,
                                         "windows": len(windows),
                                         "anomalies": sum(d.is_anomaly for d in detections)})
    return detections


def list_detections(db: Session, only_anomalies: bool, limit: int, offset: int):
    condition = AnomalyDetection.is_anomaly.is_(True) if only_anomalies else True
    total = db.scalar(select(func.count()).select_from(AnomalyDetection).where(condition))
    rows = db.scalars(select(AnomalyDetection).where(condition)
                      .order_by(AnomalyDetection.created_at.desc(), AnomalyDetection.score)
                      .limit(limit).offset(offset)).all()
    return list(rows), total
