import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel

from app.schemas.common import ORMModel


class CheckResult(BaseModel):
    name: str  # e.g. "gcm_tag", "rsa_pss_signature", "ciphertext_sha256", "audit_chain"
    passed: bool
    detail: str | None = None


class VerificationReport(ORMModel):
    id: uuid.UUID
    target_type: Literal["file", "audit_chain", "system"]
    target_id: str | None
    passed: bool
    checks: list[CheckResult]
    created_at: datetime
