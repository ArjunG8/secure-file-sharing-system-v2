"""M3 public interface. Implementation notes: docs/security-design.md, section M3."""

import uuid

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from sqlalchemy.orm import Session

from app.core.errors import NotImplementedFeature
from app.models import UserKey
from app.modules.keys import MODULE_INFO
from app.modules.keys.schemas import KeyPurpose, WrappedKey


def ensure_user_keys(db: Session, user_id: uuid.UUID) -> None:
    """Create the active encryption and signing RSA-3072 key pairs if missing."""
    raise NotImplementedFeature(MODULE_INFO, "RSA key pair generation")


def get_active_key(db: Session, user_id: uuid.UUID, purpose: KeyPurpose) -> UserKey:
    raise NotImplementedFeature(MODULE_INFO, "Active key lookup")


def list_public_keys(db: Session, user_id: uuid.UUID) -> list[UserKey]:
    raise NotImplementedFeature(MODULE_INFO, "Public key listing")


def wrap_key_for_user(db: Session, user_id: uuid.UUID, file_key: bytes) -> WrappedKey:
    """RSA-OAEP(SHA-256) encrypt `file_key` with the user's active encryption public key."""
    raise NotImplementedFeature(MODULE_INFO, "RSA-OAEP key wrapping")


def unwrap_key_for_user(
    db: Session, user_id: uuid.UUID, wrapped: bytes, key_id: uuid.UUID
) -> bytes:
    """Decrypt a wrapped file key with the private key `key_id` (must belong to user_id)."""
    raise NotImplementedFeature(MODULE_INFO, "RSA-OAEP key unwrapping")


def load_private_key(db: Session, key: UserKey) -> RSAPrivateKey:
    """Decrypt the stored private key with MASTER_KEY_ENCRYPTION_KEY. Never log or return it."""
    raise NotImplementedFeature(MODULE_INFO, "Private key decryption")


def rotate_keys(db: Session, user_id: uuid.UUID, purpose: KeyPurpose) -> UserKey:
    raise NotImplementedFeature(MODULE_INFO, "Key rotation")
