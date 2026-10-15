"""Owner: M5 (Secure file sharing and access control)."""

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, utcnow


class FileAccessGrant(Base):
    """Who may access a file, holding that user's RSA-OAEP-wrapped copy of the file key.

    The owner gets a grant with permission "owner" at upload time; each share adds
    a "read" grant for the recipient. No grant (or an expired/revoked one) = no access.
    """

    __tablename__ = "file_access_grants"
    __table_args__ = (
        UniqueConstraint("file_id", "grantee_id", name="uq_file_access_grants_file_grantee"),
        CheckConstraint("permission IN ('owner', 'read')", name="permission"),
        CheckConstraint(
            "max_downloads IS NULL OR max_downloads > 0", name="max_downloads_positive"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    file_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("files.id", ondelete="CASCADE"))
    grantee_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    granted_by_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    permission: Mapped[str] = mapped_column(String(16))
    wrapped_file_key: Mapped[bytes]
    wrapping_key_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("user_keys.id"))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    expires_at: Mapped[datetime | None]
    revoked_at: Mapped[datetime | None]
    max_downloads: Mapped[int | None]
    download_count: Mapped[int] = mapped_column(default=0)
