import uuid

from fastapi import APIRouter, Depends, UploadFile, status
from fastapi.responses import Response

from app.api.deps import get_current_user
from app.core.database import DbSession
from app.core.errors import NotImplementedFeature
from app.models import User
from app.modules.encryption import MODULE_INFO, service
from app.modules.encryption.schemas import FileOut
from app.schemas.common import Page, PageParams, page_params

router = APIRouter()


@router.post("", response_model=FileOut, status_code=status.HTTP_201_CREATED)
def upload(
    db: DbSession,
    file: UploadFile,
    user: User = Depends(get_current_user),
) -> FileOut:
    service.upload_file(db, user, file)
    raise NotImplementedFeature(MODULE_INFO, "File upload response")


@router.get("", response_model=Page[FileOut])
def list_files(
    db: DbSession,
    page: PageParams = Depends(page_params),
    user: User = Depends(get_current_user),
) -> Page[FileOut]:
    raise NotImplementedFeature(MODULE_INFO, "File listing")


@router.get("/{file_id}", response_model=FileOut)
def get_file(
    db: DbSession,
    file_id: uuid.UUID,
    user: User = Depends(get_current_user),
) -> FileOut:
    raise NotImplementedFeature(MODULE_INFO, "File metadata")


@router.get(
    "/{file_id}/download",
    response_class=Response,
    responses={200: {"content": {"application/octet-stream": {}}}},
)
def download(
    db: DbSession,
    file_id: uuid.UUID,
    user: User = Depends(get_current_user),
) -> Response:
    service.download_file(db, user, file_id)
    raise NotImplementedFeature(MODULE_INFO, "File download response")


@router.delete("/{file_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_file(
    db: DbSession,
    file_id: uuid.UUID,
    user: User = Depends(get_current_user),
) -> None:
    raise NotImplementedFeature(MODULE_INFO, "File deletion")
