"""Import every model so Base.metadata (and Alembic autogenerate) sees all tables."""

from app.models.analysis import SecurityAnalysis
from app.models.anomaly import AnomalyDetection
from app.models.audit import AuditLog
from app.models.base import Base
from app.models.file import File
from app.models.key import UserKey
from app.models.share import FileAccessGrant
from app.models.user import AuthSession, User
from app.models.verification import VerificationRun

__all__ = [
    "AnomalyDetection",
    "AuditLog",
    "AuthSession",
    "Base",
    "File",
    "FileAccessGrant",
    "SecurityAnalysis",
    "User",
    "UserKey",
    "VerificationRun",
]
