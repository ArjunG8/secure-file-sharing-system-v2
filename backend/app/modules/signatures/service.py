"""M4 public interface. Implementation notes: docs/security-design.md, section M4."""

import uuid

from sqlalchemy.orm import Session

from app.core.errors import NotImplementedFeature
from app.models import File
from app.modules.signatures import MODULE_INFO
from app.modules.signatures.schemas import SignatureResult


def build_manifest(file: File) -> bytes:
    """Canonical JSON bytes (sorted keys, no whitespace) of the fields listed in the design doc."""
    raise NotImplementedFeature(MODULE_INFO, "Signature manifest")


def sign_manifest(db: Session, user_id: uuid.UUID, manifest: bytes) -> SignatureResult:
    """RSA-PSS (MGF1-SHA256, salt=digest length) sign with the user's active signing key."""
    raise NotImplementedFeature(MODULE_INFO, "RSA-PSS signing")


def verify_manifest(db: Session, file: File) -> bool:
    """Verify files.signature over build_manifest(file) using files.signing_key_id."""
    raise NotImplementedFeature(MODULE_INFO, "RSA-PSS verification")
