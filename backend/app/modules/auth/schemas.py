import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, EmailStr, Field

from app.schemas.common import NormalizedEmail, ORMModel


class RegisterRequest(BaseModel):
    email: NormalizedEmail
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=128)


class LoginRequest(BaseModel):
    email: NormalizedEmail
    password: str = Field(min_length=1, max_length=128)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105 - OAuth2 token type, not a secret
    expires_in: int


class TokenPair(BaseModel):
    """Internal: returned by authenticate(); the router sets refresh_token as a cookie."""

    access: TokenResponse
    refresh_token: str


class UserOut(ORMModel):
    id: uuid.UUID
    email: EmailStr
    username: str
    role: Literal["user", "admin"]
    created_at: datetime
