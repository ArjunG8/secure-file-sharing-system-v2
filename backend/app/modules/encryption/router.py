import uuid
from urllib.parse import quote

from fastapi import APIRouter, Depends, UploadFile, status
from fastapi.responses import Response

from app.api.deps import get_current_user
from app.core.database import DbSession
from app.models import File, User
from app.modules.encryption import service
from app.modules.encryption.schemas import FileOut
from app.schemas.common import Page, PageParams, page_params

router = APIRouter()


def _out(file: File, permission: str) -> FileOut:
    return FileOut(
        id=file.id, owner_id=file.owner_id, original_filename=file.original_filename,
        content_type=file.content_type, size_bytes=file.size_bytes,
        encryption_algorithm=file.encryption_algorithm,
        plaintext_sha256=file.plaintext_sha256,
        signature_algorithm=file.signature_algorithm, permission=permission,
        created_at=file.created_at,
    )


def _content_disposition(filename: str) -> str:
    # ASCII fallback with quotes/backslashes removed, plus the RFC 5987 UTF-8 form.
    fallback = "".join(c for c in filename if 32 <= ord(c) < 127 and c not in '"\\') or "file"
    return f"attachment; filename=\"{fallback}\"; filename*=UTF-8''{quote(filename, safe='')}"


@router.post("", response_model=FileOut, status_code=status.HTTP_201_CREATED)
def upload(
    db: DbSession,
    file: UploadFile,
    user: User = Depends(get_current_user),
) -> FileOut:
    return _out(service.upload_file(db, user, file), "owner")


@router.get("", response_model=Page[FileOut])
def list_files(
    db: DbSession,
    page: PageParams = Depends(page_params),
    user: User = Depends(get_current_user),
) -> Page[FileOut]:
    rows, total = service.list_files(db, user, page.limit, page.offset)
    return Page[FileOut](items=[_out(f, p) for f, p in rows], total=total,
                         limit=page.limit, offset=page.offset)


@router.get("/{file_id}", response_model=FileOut)
def get_file(
    db: DbSession,
    file_id: uuid.UUID,
    user: User = Depends(get_current_user),
) -> FileOut:
    file, grant = service.get_file(db, user, file_id)
    return _out(file, grant.permission)


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
    file, plaintext = service.download_file(db, user, file_id)
    # Full body built here: the DB session closes before the response is sent.
    return Response(
        content=plaintext,
        media_type="application/octet-stream",  # never render user content inline
        headers={
            "Content-Disposition": _content_disposition(file.original_filename),
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
    )


@router.delete("/{file_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_file(
    db: DbSession,
    file_id: uuid.UUID,
    user: User = Depends(get_current_user),
) -> None:
    service.delete_file(db, user, file_id)
