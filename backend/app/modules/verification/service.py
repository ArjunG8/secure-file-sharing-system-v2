"""M9 public interface. Implementation notes: docs/security-design.md, section M9.

Attack/negative tests live in backend/tests/security/ (also owned by M9).
"""

import uuid

from sqlalchemy.orm import Session

from app.core.errors import NotImplementedFeature
from app.models import VerificationRun
from app.modules.verification import MODULE_INFO


def verify_file(db: Session, user_id: uuid.UUID, file_id: uuid.UUID) -> VerificationRun:
    """Run ciphertext SHA-256, GCM tag and RSA-PSS checks; store a VerificationRun."""
    raise NotImplementedFeature(MODULE_INFO, "File verification")


def verify_audit_chain(db: Session, user_id: uuid.UUID) -> VerificationRun:
    """Wrap audit.service.verify_chain into a stored VerificationRun."""
    raise NotImplementedFeature(MODULE_INFO, "Audit chain verification run")
