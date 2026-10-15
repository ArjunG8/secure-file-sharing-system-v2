"""Owner: M3 (RSA-OAEP key management)."""

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKey, Index, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, utcnow


class UserKey(Base):
    """An RSA key pair. The private key is AES-256-GCM encrypted under the master KEK."""

    __tablename__ = "user_keys"
    __table_args__ = (
        CheckConstraint("purpose IN ('encryption', 'signing')", name="purpose"),
        # At most one active key per (user, purpose).
        Index(
            "uq_user_keys_active_purpose",
            "user_id",
            "purpose",
            unique=True,
            postgresql_where=text("is_active"),
            sqlite_where=text("is_active = 1"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    purpose: Mapped[str] = mapped_column(String(16))
    algorithm: Mapped[str] = mapped_column(String(64))
    public_key_pem: Mapped[str] = mapped_column(Text)
    encrypted_private_key: Mapped[bytes]
    private_key_nonce: Mapped[bytes]
    # SHA-256 (hex) of the DER SubjectPublicKeyInfo.
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    revoked_at: Mapped[datetime | None]
