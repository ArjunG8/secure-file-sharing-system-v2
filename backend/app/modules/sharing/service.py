"""M5 public interface. Implementation notes: docs/security-design.md, section M5."""

import uuid
from datetime import datetime

from sqlalchemy.orm import Session

from app.core.errors import NotImplementedFeature
from app.models import File, FileAccessGrant
from app.modules.keys.schemas import WrappedKey
from app.modules.sharing import MODULE_INFO
from app.modules.sharing.schemas import Permission


def create_owner_grant(db: Session, file: File, wrapped: WrappedKey) -> FileAccessGrant:
    """Called by M2 at upload: give the owner a grant holding their wrapped file key."""
    raise NotImplementedFeature(MODULE_INFO, "Owner access grant")


def require_access(
    db: Session, user_id: uuid.UUID, file_id: uuid.UUID, permission: Permission
) -> FileAccessGrant:
    """Return the caller's valid grant or raise AppError(404). Default deny."""
    raise NotImplementedFeature(MODULE_INFO, "Access control check")


def share_file(
    db: Session,
    owner_id: uuid.UUID,
    file_id: uuid.UUID,
    recipient_email: str,
    expires_at: datetime | None,
    max_downloads: int | None,
) -> FileAccessGrant:
    """Unwrap with owner's key (M3), re-wrap for recipient (M3), insert a 'read' grant."""
    raise NotImplementedFeature(MODULE_INFO, "File sharing")


def revoke_share(db: Session, owner_id: uuid.UUID, grant_id: uuid.UUID) -> None:
    raise NotImplementedFeature(MODULE_INFO, "Share revocation")


def record_download(db: Session, grant: FileAccessGrant) -> None:
    """Atomically increment download_count, respecting max_downloads."""
    raise NotImplementedFeature(MODULE_INFO, "Download counting")
