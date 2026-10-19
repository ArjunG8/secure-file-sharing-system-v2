"""M2 public interface. Implementation notes: docs/security-design.md, section M2."""

import uuid
from pathlib import Path

from fastapi import UploadFile
from sqlalchemy.orm import Session

from app.core.errors import NotImplementedFeature
from app.models import File, User
from app.modules.encryption import MODULE_INFO
from app.modules.encryption.schemas import EncryptedPayload


def encrypt_bytes(plaintext: bytes, aad: bytes) -> EncryptedPayload:
    """AES-256-GCM encrypt with a fresh random key and 96-bit nonce."""
    raise NotImplementedFeature(MODULE_INFO, "AES-256-GCM encryption")


def decrypt_bytes(ciphertext: bytes, nonce: bytes, key: bytes, aad: bytes) -> bytes:
    """AES-256-GCM decrypt. Must raise AppError(502, code='integrity_failure') on tag failure."""
    raise NotImplementedFeature(MODULE_INFO, "AES-256-GCM decryption")


def store_ciphertext(file_id: uuid.UUID, data: bytes) -> Path:
    """Write ciphertext to STORAGE_DIR/<file_id>.bin and return the path."""
    raise NotImplementedFeature(MODULE_INFO, "Encrypted blob storage")


def load_ciphertext(storage_path: str) -> bytes:
    raise NotImplementedFeature(MODULE_INFO, "Encrypted blob loading")


def upload_file(db: Session, owner: User, upload: UploadFile) -> File:
    """Orchestrate: encrypt (M2) -> sign (M4) -> wrap key (M3) -> owner grant (M5) -> audit (M6)."""
    raise NotImplementedFeature(MODULE_INFO, "File upload")


def download_file(db: Session, user: User, file_id: uuid.UUID) -> tuple[File, bytes]:
    """Orchestrate: access (M5) -> unwrap (M3) -> verify signature (M4) -> decrypt -> audit."""
    raise NotImplementedFeature(MODULE_INFO, "File download")
