import uuid

from fastapi import APIRouter, Depends

from app.api.deps import get_current_user
from app.core.database import DbSession
from app.models import User
from app.modules.keys import service
from app.modules.keys.schemas import PublicKeyOut, RotateKeyRequest

router = APIRouter()


@router.get("/me", response_model=list[PublicKeyOut])
def my_keys(
    db: DbSession,
    user: User = Depends(get_current_user),
) -> list[PublicKeyOut]:
    return [PublicKeyOut.model_validate(k) for k in service.list_public_keys(db, user.id)]


@router.post("/rotate", response_model=PublicKeyOut)
def rotate(
    db: DbSession,
    data: RotateKeyRequest,
    user: User = Depends(get_current_user),
) -> PublicKeyOut:
    key = service.rotate_keys(db, user.id, data.purpose, data.algorithm)
    return PublicKeyOut.model_validate(key)


@router.get("/users/{user_id}/public", response_model=list[PublicKeyOut])
def user_public_keys(
    db: DbSession,
    user_id: uuid.UUID,
    user: User = Depends(get_current_user),
) -> list[PublicKeyOut]:
    return [PublicKeyOut.model_validate(k) for k in service.list_public_keys(db, user_id)]
