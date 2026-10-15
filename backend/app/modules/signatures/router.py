import uuid

from fastapi import APIRouter, Depends

from app.api.deps import get_current_user
from app.core.database import DbSession
from app.core.errors import NotImplementedFeature
from app.models import User
from app.modules.signatures import MODULE_INFO
from app.modules.signatures.schemas import SignatureOut, SignatureVerifyResult

router = APIRouter()


@router.get("/files/{file_id}", response_model=SignatureOut)
def get_signature(
    db: DbSession,
    file_id: uuid.UUID,
    user: User = Depends(get_current_user),
) -> SignatureOut:
    raise NotImplementedFeature(MODULE_INFO, "Signature retrieval")


@router.post("/files/{file_id}/verify", response_model=SignatureVerifyResult)
def verify_signature(
    db: DbSession,
    file_id: uuid.UUID,
    user: User = Depends(get_current_user),
) -> SignatureVerifyResult:
    raise NotImplementedFeature(MODULE_INFO, "Signature verification")
