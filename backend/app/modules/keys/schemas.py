import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from pydantic import BaseModel

from app.schemas.common import ORMModel

KeyPurpose = Literal["encryption", "signing"]


@dataclass(frozen=True)
class WrappedKey:
    """A file key encrypted with RSA-OAEP under the public key `key_id`."""

    wrapped: bytes
    key_id: uuid.UUID


class PublicKeyOut(ORMModel):
    """Private keys are never part of any response model."""

    id: uuid.UUID
    user_id: uuid.UUID
    purpose: KeyPurpose
    algorithm: str
    public_key_pem: str
    fingerprint: str
    is_active: bool
    created_at: datetime


class RotateKeyRequest(BaseModel):
    purpose: KeyPurpose
