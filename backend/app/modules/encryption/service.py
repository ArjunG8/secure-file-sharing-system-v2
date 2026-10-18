"""M2 public interface. Implementation notes: docs/security-design.md, section M2.

M2 owns the upload/download flow and calls the other modules only through their
service.py interfaces:
  upload:   encrypt (M2) -> sign manifest (M4) -> wrap file key for owner (M3)
            -> owner grant (M5) -> write blob (M2) -> audit (M6)
  download: require_access (M5) -> ciphertext hash + signature (M4) -> unwrap (M3)
            -> AES-GCM decrypt (M2) -> download counter (M5) -> audit (M6)
"""

import hashlib
import re
import unicodedata
import uuid
from datetime import UTC, datetime
from pathlib import PurePosixPath

from fastapi import UploadFile
from sqlalchemy import and_, event, func, or_, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import AppError
from app.models import File, FileAccessGrant, User
from app.modules.audit import service as audit_service
from app.modules.audit.schemas import AuditEventIn
from app.modules.encryption import MODULE_INFO, aes_gcm, storage
from app.modules.encryption.schemas import EncryptedPayload
from app.modules.keys import service as keys_service
from app.modules.sharing import service as sharing_service
from app.modules.signatures import service as signatures_service

ALGORITHM = "AES-256-GCM"
_CHUNK = 1024 * 1024
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


# --- primitives (also used by M9) --------------------------------------------------------


def encrypt_bytes(plaintext: bytes, aad: bytes) -> EncryptedPayload:
    """AES-256-GCM encrypt with a fresh random key and 96-bit nonce."""
    return aes_gcm.encrypt(plaintext, aad)


def decrypt_bytes(ciphertext: bytes, nonce: bytes, key: bytes, aad: bytes) -> bytes:
    """AES-256-GCM decrypt. Raises AppError(502, code='integrity_failure') on tag failure."""
    try:
        return aes_gcm.decrypt(ciphertext, nonce, key, aad)
    except aes_gcm.DecryptionError as exc:
        raise AppError(502, "The file failed an integrity check and was not returned.",
                       module=MODULE_INFO.code) from exc


def file_aad(file_id: uuid.UUID) -> bytes:
    """Associated data: binds a ciphertext to its own file record."""
    return file_id.bytes


def store_ciphertext(file_id: uuid.UUID, data: bytes) -> str:
    """Write ciphertext to STORAGE_DIR/<file_id>.bin; returns the stored name."""
    return storage.write(file_id, data)


def load_ciphertext(storage_path: str) -> bytes:
    try:
        return storage.read(storage_path)
    except storage.StorageError as exc:
        raise AppError(502, "The encrypted file is missing or unreadable.",
                       module=MODULE_INFO.code) from exc


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --- helpers -----------------------------------------------------------------------------


def safe_filename(name: str | None) -> str:
    """Metadata only (never a path): last path component, no control characters,
    Unicode-normalized, at most 255 characters."""
    name = unicodedata.normalize("NFC", name or "")
    name = PurePosixPath(name.replace("\\", "/")).name
    name = _CONTROL.sub("", name).strip().strip(".")
    return (name or "file")[:255]


def _safe_content_type(value: str | None) -> str:
    value = (value or "").strip()
    if not value or len(value) > 255 or _CONTROL.search(value) or "/" not in value:
        return "application/octet-stream"
    return value


def _read_limited(upload: UploadFile) -> bytes:
    limit = get_settings().max_upload_bytes
    chunks, total = [], 0
    while chunk := upload.file.read(_CHUNK):
        total += len(chunk)
        if total > limit:
            raise AppError(413, f"Files larger than {limit} bytes are not accepted.",
                           module=MODULE_INFO.code)
        chunks.append(chunk)
    return b"".join(chunks)


def _audit(db: Session, event_type: str, user: User, file_id: uuid.UUID,
           outcome: str = "success", **details) -> None:
    audit_service.record_event(db, AuditEventIn(
        event_type=event_type, outcome=outcome, actor_user_id=user.id,
        resource_type="file", resource_id=str(file_id), details=details,
    ))


def _integrity_failure(db: Session, user: User, file: File, check: str) -> AppError:
    _audit(db, "file.integrity_failure", user, file.id, "failure", check=check)
    return AppError(502, "The file failed an integrity check and was not returned.",
                    module=MODULE_INFO.code, details={"check": check})


def _delete_blob_if_rolled_back(db: Session, name: str) -> None:
    event.listen(db, "after_rollback", lambda _s: storage.delete(name), once=True)


def _delete_blob_after_commit(db: Session, name: str) -> None:
    event.listen(db, "after_commit", lambda _s: storage.delete(name), once=True)


def _get_live_file(db: Session, file_id: uuid.UUID) -> File:
    file = db.get(File, file_id)
    if file is None or file.deleted_at is not None:
        raise AppError(404, "File not found.", module=MODULE_INFO.code)
    return file


# --- flows -------------------------------------------------------------------------------


def upload_file(db: Session, owner: User, upload: UploadFile) -> File:
    """Encrypt and store an upload; every step runs in the request transaction."""
    plaintext = _read_limited(upload)
    file_id = uuid.uuid4()
    payload = encrypt_bytes(plaintext, file_aad(file_id))
    file = File(
        id=file_id,
        owner_id=owner.id,
        original_filename=safe_filename(upload.filename),
        content_type=_safe_content_type(upload.content_type),
        size_bytes=len(plaintext),
        storage_path=storage.blob_name(file_id),
        encryption_algorithm=ALGORITHM,
        nonce=payload.nonce,
        plaintext_sha256=sha256_hex(plaintext),
        ciphertext_sha256=sha256_hex(payload.ciphertext),
    )
    db.add(file)
    db.flush()

    signature = signatures_service.sign_manifest(
        db, owner.id, signatures_service.build_manifest(file)
    )
    file.signature = signature.signature
    file.signature_algorithm = signature.algorithm
    file.signing_key_id = signature.key_id

    wrapped = keys_service.wrap_key_for_user(db, owner.id, payload.key)
    sharing_service.create_owner_grant(db, file, wrapped)
    db.flush()

    # Last step: if anything later fails (including COMMIT), the blob is removed again.
    store_ciphertext(file_id, payload.ciphertext)
    _delete_blob_if_rolled_back(db, file.storage_path)
    _audit(db, "file.upload", owner, file_id, size_bytes=file.size_bytes)
    return file


def get_file(db: Session, user: User, file_id: uuid.UUID) -> tuple[File, FileAccessGrant]:
    grant = sharing_service.require_access(db, user.id, file_id, "read")
    return _get_live_file(db, file_id), grant


def download_file(db: Session, user: User, file_id: uuid.UUID) -> tuple[File, bytes]:
    """Return the decrypted file only if every integrity check passes."""
    grant = sharing_service.require_access(db, user.id, file_id, "read")
    file = _get_live_file(db, file_id)

    ciphertext = load_ciphertext(file.storage_path)
    if sha256_hex(ciphertext) != file.ciphertext_sha256:
        raise _integrity_failure(db, user, file, "ciphertext_sha256")
    if not signatures_service.verify_manifest(db, file):
        raise _integrity_failure(db, user, file, "signature")

    key = keys_service.unwrap_key_for_user(db, user.id, grant.wrapped_file_key,
                                           grant.wrapping_key_id)
    try:
        plaintext = aes_gcm.decrypt(ciphertext, file.nonce, key, file_aad(file.id))
    except aes_gcm.DecryptionError:
        raise _integrity_failure(db, user, file, "gcm_tag") from None
    if sha256_hex(plaintext) != file.plaintext_sha256:
        raise _integrity_failure(db, user, file, "plaintext_sha256")

    sharing_service.record_download(db, grant)
    _audit(db, "file.download", user, file.id, size_bytes=file.size_bytes)
    return file, plaintext


def list_files(
    db: Session, user: User, limit: int, offset: int
) -> tuple[list[tuple[File, str]], int]:
    """Files the user may currently read (own or shared). Mirrors M5's grant rules for
    listing only; every read of content still goes through sharing.require_access."""
    now = datetime.now(UTC)
    conditions = and_(
        FileAccessGrant.grantee_id == user.id,
        FileAccessGrant.revoked_at.is_(None),
        or_(FileAccessGrant.expires_at.is_(None), FileAccessGrant.expires_at > now),
        or_(FileAccessGrant.max_downloads.is_(None),
            FileAccessGrant.download_count < FileAccessGrant.max_downloads),
        File.deleted_at.is_(None),
    )
    base = select(File, FileAccessGrant.permission).join(
        FileAccessGrant, FileAccessGrant.file_id == File.id).where(conditions)
    total = db.scalar(select(func.count()).select_from(base.subquery()))
    rows = db.execute(base.order_by(File.created_at.desc()).limit(limit).offset(offset)).all()
    return [(file, permission) for file, permission in rows], total


def delete_file(db: Session, user: User, file_id: uuid.UUID) -> None:
    """Owner only. Soft-deletes the record (grants stop working) and removes the blob
    after the transaction commits."""
    sharing_service.require_access(db, user.id, file_id, "owner")
    file = _get_live_file(db, file_id)
    file.deleted_at = datetime.now(UTC)
    _delete_blob_after_commit(db, file.storage_path)
    _audit(db, "file.delete", user, file.id)
