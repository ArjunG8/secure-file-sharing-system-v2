import base64
import hashlib
import json
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import DbSession
from app.core.errors import AppError
from app.models import File, User, UserKey
from app.modules.audit import service as audit_service
from app.modules.audit.schemas import AuditEventIn
from app.modules.encryption import service as encryption_service
from app.modules.sharing import service as sharing_service
from app.modules.signatures import MODULE_INFO, service
from app.modules.signatures.schemas import SignatureOut, SignatureVerifyResult

router = APIRouter()


def _accessible_file(db: Session, user: User, file_id: uuid.UUID) -> File:
    sharing_service.require_access(db, user.id, file_id, "read")  # 404 if no access
    file = db.get(File, file_id)
    if file is None or file.deleted_at is not None:
        raise AppError(404, "File not found.", module=MODULE_INFO.code)
    return file


@router.get("/files/{file_id}", response_model=SignatureOut)
def get_signature(
    db: DbSession,
    file_id: uuid.UUID,
    user: User = Depends(get_current_user),
) -> SignatureOut:
    file = _accessible_file(db, user, file_id)
    if not file.signature or file.signing_key_id is None:
        raise AppError(404, "This file has no signature.", module=MODULE_INFO.code)
    key = db.get(UserKey, file.signing_key_id)
    return SignatureOut(
        file_id=file.id,
        algorithm=file.signature_algorithm,
        signature_b64=base64.b64encode(file.signature).decode(),
        signing_key_id=file.signing_key_id,
        signer_id=key.user_id if key else file.owner_id,
        manifest=json.loads(service.build_manifest(file)),
    )


@router.post("/files/{file_id}/verify", response_model=SignatureVerifyResult)
def verify_signature(
    db: DbSession,
    file_id: uuid.UUID,
    user: User = Depends(get_current_user),
) -> SignatureVerifyResult:
    """Check authorship (signature) and integrity (stored ciphertext vs signed hash)."""
    file = _accessible_file(db, user, file_id)
    signature_problem = service.explain_verification(db, file)
    try:
        blob = encryption_service.load_ciphertext(file.storage_path)
        ciphertext_intact = hashlib.sha256(blob).hexdigest() == file.ciphertext_sha256
    except AppError:
        ciphertext_intact = False
    reason = signature_problem or (
        None if ciphertext_intact
        else "stored ciphertext does not match the signed ciphertext hash"
    )
    valid = reason is None
    audit_service.record_event(db, AuditEventIn(
        event_type="file.signature_verify", outcome="success" if valid else "failure",
        actor_user_id=user.id, resource_type="file", resource_id=str(file.id),
        details={"valid": valid, "reason": reason},
    ))
    return SignatureVerifyResult(
        file_id=file.id, valid=valid, signature_valid=signature_problem is None,
        ciphertext_intact=ciphertext_intact, checked_at=datetime.now(UTC), reason=reason,
    )
