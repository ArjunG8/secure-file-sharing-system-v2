"""M3 public interface. Implementation notes: docs/security-design.md, section M3.

Key pairs are created lazily: the first call that needs a user's key (wrap, sign, list)
creates the active encryption and signing pair. M1 therefore has no dependency on M3.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import AppError
from app.models import User, UserKey
from app.modules.audit import service as audit_service
from app.modules.audit.schemas import AuditEventIn
from app.modules.keys import MODULE_INFO, crypto
from app.modules.keys.schemas import ALGORITHMS, KeyFamily, KeyPurpose, WrappedKey

PURPOSES: tuple[KeyPurpose, ...] = ("encryption", "signing")


def _master_key() -> str:
    return get_settings().master_key_encryption_key.get_secret_value()


def family_of(algorithm: str) -> KeyFamily:
    return next(fam for (fam, _), label in ALGORITHMS.items() if label == algorithm)


def _create_key(
    db: Session, user_id: uuid.UUID, purpose: KeyPurpose, family: KeyFamily
) -> UserKey:
    algorithm = ALGORITHMS[(family, purpose)]
    private_key = crypto.generate_private_key(algorithm)
    key_id = uuid.uuid4()
    encrypted, nonce = crypto.encrypt_private_key(private_key, _master_key(), user_id, purpose,
                                                  key_id)
    pem = crypto.public_key_pem(private_key)
    key = UserKey(
        id=key_id,
        user_id=user_id,
        purpose=purpose,
        algorithm=algorithm,
        public_key_pem=pem,
        encrypted_private_key=encrypted,
        private_key_nonce=nonce,
        fingerprint=crypto.fingerprint(pem),
        is_active=True,
    )
    db.add(key)
    db.flush()
    return key


def _audit_generated(db: Session, key: UserKey) -> None:
    audit_service.record_event(db, AuditEventIn(
        event_type="key.generate", actor_user_id=key.user_id, resource_type="key",
        resource_id=str(key.id), details={"purpose": key.purpose, "algorithm": key.algorithm},
    ))


def _active(db: Session, user_id: uuid.UUID, purpose: KeyPurpose) -> UserKey | None:
    return db.scalar(
        select(UserKey).where(
            UserKey.user_id == user_id, UserKey.purpose == purpose, UserKey.is_active
        )
    )


def _require_user(db: Session, user_id: uuid.UUID) -> None:
    if db.get(User, user_id) is None:
        raise AppError(404, "User not found.", module=MODULE_INFO.code)


def get_active_key(db: Session, user_id: uuid.UUID, purpose: KeyPurpose) -> UserKey:
    """Return the user's active key for `purpose`, creating the pair on first use."""
    key = _active(db, user_id, purpose)
    if key is not None:
        return key
    _require_user(db, user_id)
    try:
        with db.begin_nested():  # a concurrent request may create the same key
            key = _create_key(db, user_id, purpose, get_settings().default_key_algorithm)
    except IntegrityError:
        key = _active(db, user_id, purpose)
        if key is None:
            raise
        return key
    _audit_generated(db, key)  # only after the key really exists
    return key


def ensure_user_keys(db: Session, user_id: uuid.UUID) -> None:
    """Create the active encryption and signing key pairs if missing."""
    for purpose in PURPOSES:
        get_active_key(db, user_id, purpose)


def list_public_keys(db: Session, user_id: uuid.UUID) -> list[UserKey]:
    """The user's active public keys (created on first use). 404 for an unknown user."""
    ensure_user_keys(db, user_id)
    return list(db.scalars(
        select(UserKey)
        .where(UserKey.user_id == user_id, UserKey.is_active)
        .order_by(UserKey.purpose)
    ))


def get_key(db: Session, user_id: uuid.UUID, key_id: uuid.UUID, purpose: KeyPurpose) -> UserKey:
    """A specific key of this user and purpose - active OR rotated out (old data stays
    readable/verifiable). Raises 404 rather than revealing other users' key ids."""
    key = db.get(UserKey, key_id)
    if key is None or key.user_id != user_id or key.purpose != purpose:
        raise AppError(404, "Key not found.", module=MODULE_INFO.code)
    return key


def get_public_key(db: Session, key_id: uuid.UUID) -> UserKey:
    """Any key by id, for verifying with its public half (e.g. M4 signature checks)."""
    key = db.get(UserKey, key_id)
    if key is None:
        raise AppError(404, "Key not found.", module=MODULE_INFO.code)
    return key


def load_private_key(db: Session, key: UserKey) -> crypto.PrivateKey:
    """Decrypt the stored private key with MASTER_KEY_ENCRYPTION_KEY. Never log or return
    it from an API. Raises 500 if the key store doesn't match the master key."""
    try:
        return crypto.decrypt_private_key(
            key.encrypted_private_key, key.private_key_nonce, _master_key(),
            key.user_id, key.purpose, key.id,
        )
    except crypto.KeyCryptoError as exc:
        raise AppError(500, "The key store could not be decrypted.",
                       module=MODULE_INFO.code) from exc


def wrap_key_for_user(db: Session, user_id: uuid.UUID, file_key: bytes) -> WrappedKey:
    """Encrypt `file_key` for the user's active encryption key (RSA-OAEP or X25519 ECIES)."""
    key = get_active_key(db, user_id, "encryption")
    return WrappedKey(
        wrapped=crypto.wrap_file_key(key.algorithm, key.public_key_pem, file_key, key.id),
        key_id=key.id,
    )


def unwrap_key_for_user(
    db: Session, user_id: uuid.UUID, wrapped: bytes, key_id: uuid.UUID
) -> bytes:
    """Decrypt a wrapped file key with the private key `key_id`, which must be one of
    `user_id`'s encryption keys (rotated keys still work). 502 on tampered/wrong data."""
    key = get_key(db, user_id, key_id, "encryption")
    try:
        return crypto.unwrap_file_key(key.algorithm, load_private_key(db, key), wrapped, key.id)
    except crypto.KeyCryptoError as exc:
        raise AppError(502, "The file key could not be unwrapped.",
                       module=MODULE_INFO.code) from exc


def rotate_keys(
    db: Session, user_id: uuid.UUID, purpose: KeyPurpose, family: KeyFamily | None = None
) -> UserKey:
    """Replace the active key for `purpose`. The old key is kept (inactive) so files
    wrapped or signed with it stay readable and verifiable."""
    current = _active(db, user_id, purpose)
    if current is None:
        _require_user(db, user_id)
    new_family = family or (family_of(current.algorithm) if current else
                            get_settings().default_key_algorithm)
    if current is not None:
        current.is_active = False
        current.revoked_at = datetime.now(UTC)
        db.flush()  # free the one-active-key-per-purpose slot first
    key = _create_key(db, user_id, purpose, new_family)
    _audit_generated(db, key)
    audit_service.record_event(db, AuditEventIn(
        event_type="key.rotate", actor_user_id=user_id, resource_type="key",
        resource_id=str(key.id),
        details={"purpose": purpose, "algorithm": key.algorithm,
                 "previous_key_id": str(current.id) if current else None},
    ))
    return key
