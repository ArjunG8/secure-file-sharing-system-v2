"""Owner: M2 (AES-256-GCM file encryption). Signature columns owned by M4."""

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, utcnow


class File(Base):
    """Metadata for an encrypted file. Ciphertext lives in STORAGE_DIR, not the database."""

    __tablename__ = "files"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    original_filename: Mapped[str] = mapped_column(String(255))
    content_type: Mapped[str] = mapped_column(String(255))
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    storage_path: Mapped[str] = mapped_column(String(512))
    encryption_algorithm: Mapped[str] = mapped_column(String(32), default="AES-256-GCM")
    nonce: Mapped[bytes]
    plaintext_sha256: Mapped[str] = mapped_column(String(64))
    ciphertext_sha256: Mapped[str] = mapped_column(String(64))

    # --- M4: RSA-PSS signature over the canonical manifest ---
    signature: Mapped[bytes | None]
    signature_algorithm: Mapped[str | None] = mapped_column(String(32))
    signing_key_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("user_keys.id"))

    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    deleted_at: Mapped[datetime | None]
