import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from app.schemas.common import ORMModel


@dataclass(frozen=True)
class EncryptedPayload:
    """Result of encrypt_bytes. `key` is the raw 32-byte file key: never persist it."""

    ciphertext: bytes  # ciphertext || 16-byte GCM tag
    nonce: bytes  # 12 bytes
    key: bytes  # 32 bytes


class FileOut(ORMModel):
    id: uuid.UUID
    owner_id: uuid.UUID
    original_filename: str
    content_type: str
    size_bytes: int
    encryption_algorithm: str
    plaintext_sha256: str
    signature_algorithm: str | None
    permission: Literal["owner", "read"]
    created_at: datetime
