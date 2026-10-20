import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, EmailStr, Field

from app.schemas.common import NormalizedEmail, ORMModel

Permission = Literal["owner", "read"]


class ShareCreate(BaseModel):
    file_id: uuid.UUID
    recipient_email: NormalizedEmail
    expires_at: datetime | None = None
    max_downloads: int | None = Field(default=None, ge=1, le=1000)


class ShareOut(ORMModel):
    id: uuid.UUID
    file_id: uuid.UUID
    file_name: str
    grantee_id: uuid.UUID
    grantee_email: EmailStr
    granted_by_id: uuid.UUID
    permission: Permission
    expires_at: datetime | None
    revoked_at: datetime | None
    max_downloads: int | None
    download_count: int
    created_at: datetime
    # Not revoked, not expired, downloads remaining (and the file still exists).
    active: bool
