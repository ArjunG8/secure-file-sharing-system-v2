import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from pydantic import BaseModel


@dataclass(frozen=True)
class SignatureResult:
    signature: bytes
    key_id: uuid.UUID
    algorithm: str  # "RSA-PSS-SHA256"


class SignatureOut(BaseModel):
    file_id: uuid.UUID
    algorithm: str
    signature_b64: str
    signing_key_id: uuid.UUID
    signer_id: uuid.UUID
    manifest: dict[str, Any]


class SignatureVerifyResult(BaseModel):
    file_id: uuid.UUID
    valid: bool
    checked_at: datetime
    reason: str | None = None
