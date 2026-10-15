"""Schemas shared by every module."""

from typing import Annotated, Any, Literal

from fastapi import Query
from pydantic import AfterValidator, BaseModel, BeforeValidator, ConfigDict, EmailStr


def normalize_email(value: str) -> str:
    """The single email normalization rule: trimmed and lowercased.

    Applied by NormalizedEmail (API input), the User model (every write) and the
    database CHECK constraint ck_users_email_normalized, so "Alice@Uni.edu" and
    "alice@uni.edu" can never be two different accounts.
    """
    return value.strip().lower()


def _strip(value: Any) -> Any:
    return value.strip() if isinstance(value, str) else value


# Use for every email field in request schemas.
NormalizedEmail = Annotated[EmailStr, BeforeValidator(_strip), AfterValidator(normalize_email)]


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class ErrorBody(BaseModel):
    code: str
    message: str
    module: str | None = None
    details: Any = None


class ErrorResponse(BaseModel):
    error: ErrorBody


class Page[T](BaseModel):
    items: list[T]
    total: int
    limit: int
    offset: int


class PageParams(BaseModel):
    limit: int = 50
    offset: int = 0


def page_params(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> PageParams:
    return PageParams(limit=limit, offset=offset)


class HealthOut(BaseModel):
    status: Literal["ok"]
    version: str
    database: Literal["ok", "unavailable"]


class ModuleOut(BaseModel):
    number: int
    code: str
    key: str
    name: str
    implemented: bool
