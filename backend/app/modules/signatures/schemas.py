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
    # True only if the signature is valid AND the stored ciphertext matches the
    # signed ciphertext hash.
    valid: bool
    signature_valid: bool  # authorship: the owner's key signed this manifest
    ciphertext_intact: bool  # integrity: the stored blob hashes to the signed value
    checked_at: datetime
    reason: str | None = None
