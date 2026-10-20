"""M5 public interface. Implementation notes: docs/security-design.md, section M5.

require_access() is THE enforcement point: default deny, and every failure looks the same
(404 "File not found."), so a caller can't tell a missing file from someone else's file.
The frontend's view of permissions is never trusted.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.orm import Session

from app.core.errors import AppError
from app.models import File, FileAccessGrant, User
from app.modules.audit import service as audit_service
from app.modules.audit.schemas import AuditEventIn
from app.modules.keys import service as keys_service
from app.modules.keys.schemas import WrappedKey
from app.modules.sharing import MODULE_INFO
from app.modules.sharing.schemas import Permission, ShareOut
from app.schemas.common import normalize_email

_NOT_FOUND = "File not found."


def _now() -> datetime:
    return datetime.now(UTC)


def _utc(value: datetime | None) -> datetime | None:
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=UTC)  # SQLite returns naive UTC values


def denial_reason(grant: FileAccessGrant | None, file: File | None,
                  now: datetime | None = None) -> str | None:
    """None if the grant currently allows access, otherwise why not."""
    now = now or _now()
    if file is None or file.deleted_at is not None:
        return "no_such_file"
    if grant is None:
        return "no_grant"
    if grant.revoked_at is not None:
        return "revoked"
    if grant.expires_at is not None and _utc(grant.expires_at) <= now:
        return "expired"
    if grant.max_downloads is not None and grant.download_count >= grant.max_downloads:
        return "download_limit_reached"
    return None


def _audit(db: Session, event_type: str, actor: uuid.UUID, outcome: str = "success",
           resource_id: str | None = None, **details) -> None:
    audit_service.record_event(db, AuditEventIn(
        event_type=event_type, outcome=outcome, actor_user_id=actor, resource_type="file",
        resource_id=resource_id, details=details,
    ))


def _deny(db: Session, user_id: uuid.UUID, file_id: uuid.UUID, reason: str,
          permission: str) -> AppError:
    # Recorded BEFORE raising: denied events survive the request's rollback (M6 rule).
    _audit(db, "share.access_denied", user_id, "denied", str(file_id),
           reason=reason, required=permission)
    return AppError(404, _NOT_FOUND, module=MODULE_INFO.code)


def _grant_for(db: Session, file_id: uuid.UUID, user_id: uuid.UUID) -> FileAccessGrant | None:
    return db.scalar(select(FileAccessGrant).where(
        FileAccessGrant.file_id == file_id, FileAccessGrant.grantee_id == user_id))


# --- enforcement -------------------------------------------------------------------------


def create_owner_grant(db: Session, file: File, wrapped: WrappedKey) -> FileAccessGrant:
    """Called by M2 at upload: the owner's grant holds their wrapped copy of the file key."""
    grant = FileAccessGrant(
        file_id=file.id, grantee_id=file.owner_id, granted_by_id=file.owner_id,
        permission="owner", wrapped_file_key=wrapped.wrapped, wrapping_key_id=wrapped.key_id,
    )
    db.add(grant)
    db.flush()
    return grant


def require_access(
    db: Session, user_id: uuid.UUID, file_id: uuid.UUID, permission: Permission
) -> FileAccessGrant:
    """Return the caller's valid grant, or record share.access_denied and raise 404.

    "read" is satisfied by an owner or read grant; "owner" only by the owner grant.
    """
    file = db.get(File, file_id)
    grant = _grant_for(db, file_id, user_id) if file is not None else None
    reason = denial_reason(grant, file)
    if reason is None and permission == "owner" and grant.permission != "owner":
        reason = "not_owner"
    if reason is not None:
        raise _deny(db, user_id, file_id, reason, permission)
    return grant


def record_download(db: Session, grant: FileAccessGrant) -> None:
    """Atomically count a download. The conditional UPDATE cannot exceed max_downloads even
    under concurrent downloads; losing the race is a denial."""
    if grant.permission == "owner":
        return
    counted = db.execute(
        update(FileAccessGrant)
        .where(
            FileAccessGrant.id == grant.id,
            FileAccessGrant.revoked_at.is_(None),
            or_(FileAccessGrant.max_downloads.is_(None),
                FileAccessGrant.download_count < FileAccessGrant.max_downloads),
        )
        .values(download_count=FileAccessGrant.download_count + 1)
        .returning(FileAccessGrant.id)
    ).scalar_one_or_none()
    if counted is None:
        raise _deny(db, grant.grantee_id, grant.file_id, "download_limit_reached", "read")
    db.refresh(grant)


# --- sharing -----------------------------------------------------------------------------


def share_file(
    db: Session,
    owner_id: uuid.UUID,
    file_id: uuid.UUID,
    recipient_email: str,
    expires_at: datetime | None,
    max_downloads: int | None,
) -> FileAccessGrant:
    """Unwrap with the owner's key (M3), re-wrap for the recipient (M3), store a 'read'
    grant. The raw file key exists only in memory for the duration of this call."""
    owner_grant = require_access(db, owner_id, file_id, "owner")
    expires_at = _utc(expires_at)
    if expires_at is not None and expires_at <= _now():
        raise AppError(422, "expires_at must be in the future.", module=MODULE_INFO.code)
    recipient = db.scalar(select(User).where(User.email == normalize_email(recipient_email)))
    if recipient is None or not recipient.is_active:
        raise AppError(404, "No active account with that email address.",
                       module=MODULE_INFO.code)
    if recipient.id == owner_id:
        raise AppError(422, "You already own this file.", module=MODULE_INFO.code)

    file_key = keys_service.unwrap_key_for_user(db, owner_id, owner_grant.wrapped_file_key,
                                                owner_grant.wrapping_key_id)
    wrapped = keys_service.wrap_key_for_user(db, recipient.id, file_key)
    del file_key

    grant = _grant_for(db, file_id, recipient.id)
    if grant is None:
        grant = FileAccessGrant(file_id=file_id, grantee_id=recipient.id, permission="read")
        db.add(grant)
    # A re-share replaces an earlier (possibly revoked/expired) grant: one row per user/file.
    grant.granted_by_id = owner_id
    grant.wrapped_file_key = wrapped.wrapped
    grant.wrapping_key_id = wrapped.key_id
    grant.expires_at = expires_at
    grant.max_downloads = max_downloads
    grant.download_count = 0
    grant.revoked_at = None
    db.flush()
    _audit(db, "share.create", owner_id, resource_id=str(file_id),
           grant_id=str(grant.id), grantee_id=str(recipient.id),
           expires_at=expires_at.isoformat() if expires_at else None,
           max_downloads=max_downloads)
    return grant


def revoke_share(db: Session, owner_id: uuid.UUID, grant_id: uuid.UUID) -> None:
    grant = db.get(FileAccessGrant, grant_id)
    if grant is None:
        raise AppError(404, "Share not found.", module=MODULE_INFO.code)
    require_access(db, owner_id, grant.file_id, "owner")  # 404 unless caller owns the file
    if grant.permission == "owner":
        raise AppError(422, "The owner's own access cannot be revoked; delete the file instead.",
                       module=MODULE_INFO.code)
    if grant.revoked_at is None:
        grant.revoked_at = _now()
        _audit(db, "share.revoke", owner_id, resource_id=str(grant.file_id),
               grant_id=str(grant.id), grantee_id=str(grant.grantee_id))


# --- listing -----------------------------------------------------------------------------


def _share_out(grant: FileAccessGrant, file: File, grantee: User) -> ShareOut:
    return ShareOut(
        id=grant.id, file_id=grant.file_id, file_name=file.original_filename,
        grantee_id=grant.grantee_id, grantee_email=grantee.email,
        granted_by_id=grant.granted_by_id, permission=grant.permission,
        expires_at=grant.expires_at, revoked_at=grant.revoked_at,
        max_downloads=grant.max_downloads, download_count=grant.download_count,
        created_at=grant.created_at, active=denial_reason(grant, file) is None,
    )


def _list(db: Session, condition, limit: int, offset: int) -> tuple[list[ShareOut], int]:
    base = (
        select(FileAccessGrant, File, User)
        .join(File, File.id == FileAccessGrant.file_id)
        .join(User, User.id == FileAccessGrant.grantee_id)
        .where(condition, FileAccessGrant.permission == "read", File.deleted_at.is_(None))
    )
    total = db.scalar(select(func.count()).select_from(base.subquery()))
    rows = db.execute(base.order_by(FileAccessGrant.created_at.desc())
                      .limit(limit).offset(offset)).all()
    return [_share_out(g, f, u) for g, f, u in rows], total


def outgoing_shares(db: Session, owner_id: uuid.UUID, limit: int, offset: int):
    """Shares of files the caller owns."""
    return _list(db, File.owner_id == owner_id, limit, offset)


def incoming_shares(db: Session, user_id: uuid.UUID, limit: int, offset: int):
    """Files shared with the caller."""
    return _list(db, and_(FileAccessGrant.grantee_id == user_id), limit, offset)


def share_out(db: Session, grant: FileAccessGrant) -> ShareOut:
    return _share_out(grant, db.get(File, grant.file_id), db.get(User, grant.grantee_id))
