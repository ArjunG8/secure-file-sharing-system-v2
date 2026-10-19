
import base64
import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException

from app.api.deps import get_current_user
from app.core.database import DbSession
from app.models import File, User
from app.modules.signatures import MODULE_INFO, service
from app.modules.signatures.schemas import SignatureOut, SignatureVerifyResult

router = APIRouter()


def get_owned_file(db: DbSession, file_id: uuid.UUID, user: User) -> File:
    file = db.get(File, file_id)
    if file is None or file.owner_id != user.id:
        raise HTTPException(status_code=404, detail="File not found")
    return file


@router.get("/files/{file_id}", response_model=SignatureOut)
def get_signature(
    db: DbSession,
    file_id: uuid.UUID,
    user: User = Depends(get_current_user),
) -> SignatureOut:
    file = get_owned_file(db, file_id, user)

    if not file.signature or not file.signing_key_id:
        raise HTTPException(status_code=404, detail="Signature not found")

    return SignatureOut(
        file_id=file.id,
        algorithm=file.signature_algorithm or service.ALGORITHM,
        signature_b64=base64.b64encode(file.signature).decode("ascii"),
        signing_key_id=file.signing_key_id,
        signer_id=file.owner_id,
        manifest=json.loads(service.build_manifest(file).decode("utf-8")),
    )


@router.post("/files/{file_id}/verify", response_model=SignatureVerifyResult)
def verify_signature(
    db: DbSession,
    file_id: uuid.UUID,
    user: User = Depends(get_current_user),
) -> SignatureVerifyResult:
    file = get_owned_file(db, file_id, user)
    valid = service.verify_manifest(db, file)

    return SignatureVerifyResult(
        file_id=file.id,
        valid=valid,
        checked_at=datetime.now(timezone.utc),
        reason=None if valid else "missing_or_invalid_signature",
    )
