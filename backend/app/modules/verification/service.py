"""M9 public interface. Implementation notes: docs/security-design.md, section M9.

Verification re-runs every integrity check of a stored file WITHOUT returning its
content or counting a download, and records the result in verification_runs. It only
calls the other modules' service interfaces. Attack tests live in backend/tests/security/.
"""

import hashlib
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.errors import AppError
from app.models import File, VerificationRun
from app.modules.audit import service as audit_service
from app.modules.audit.schemas import AuditEventIn
from app.modules.encryption import service as encryption_service
from app.modules.keys import service as keys_service
from app.modules.sharing import service as sharing_service
from app.modules.signatures import service as signatures_service
from app.modules.verification import MODULE_INFO


class _Checks:
    def __init__(self) -> None:
        self.items: list[dict] = []

    def add(self, name: str, passed: bool, detail: str | None = None) -> bool:
        self.items.append({"name": name, "passed": passed, "detail": detail})
        return passed

    def skip(self, name: str, because: str) -> None:
        self.add(name, False, f"not checked: {because}")

    @property
    def passed(self) -> bool:
        return bool(self.items) and all(c["passed"] for c in self.items)


def _store(db: Session, user_id: uuid.UUID, target_type: str, target_id: str | None,
           checks: _Checks) -> VerificationRun:
    run = VerificationRun(requested_by_id=user_id, target_type=target_type, target_id=target_id,
                          passed=checks.passed, checks=checks.items)
    db.add(run)
    db.flush()
    audit_service.record_event(db, AuditEventIn(
        event_type="verification.run", outcome="success" if run.passed else "failure",
        actor_user_id=user_id, resource_type=target_type, resource_id=target_id,
        details={"failed": [c["name"] for c in checks.items if not c["passed"]]},
    ))
    return run


def verify_file(db: Session, user_id: uuid.UUID, file_id: uuid.UUID) -> VerificationRun:
    """Checks, in order: blob_present, ciphertext_sha256, signature, file_key_unwrap,
    gcm_tag, plaintext_sha256. A check whose prerequisite failed is reported as failed
    ("not checked"), never as passed."""
    grant = sharing_service.require_access(db, user_id, file_id, "read")  # 404 otherwise
    file = db.get(File, file_id)
    if file is None or file.deleted_at is not None:
        raise AppError(404, "File not found.", module=MODULE_INFO.code)
    checks = _Checks()

    try:
        ciphertext = encryption_service.load_ciphertext(file.storage_path)
        checks.add("blob_present", True)
    except AppError:
        ciphertext = None
        checks.add("blob_present", False, "encrypted blob missing or unreadable")

    if ciphertext is None:
        checks.skip("ciphertext_sha256", "no blob")
    else:
        matches = hashlib.sha256(ciphertext).hexdigest() == file.ciphertext_sha256
        checks.add("ciphertext_sha256", matches,
                   None if matches else "stored blob does not match the recorded hash")

    signature_ok = signatures_service.verify_manifest(db, file)
    checks.add("signature", signature_ok,
               None if signature_ok else "manifest signature invalid or not by the owner")

    try:
        key = keys_service.unwrap_key_for_user(db, user_id, grant.wrapped_file_key,
                                               grant.wrapping_key_id)
        checks.add("file_key_unwrap", True)
    except AppError:
        key = None
        checks.add("file_key_unwrap", False, "file key could not be unwrapped")

    plaintext = None
    if ciphertext is None or key is None:
        checks.skip("gcm_tag", "no blob or no key")
    else:
        try:
            plaintext = encryption_service.decrypt_bytes(ciphertext, file.nonce, key,
                                                         file.id.bytes)
            checks.add("gcm_tag", True)
        except AppError:
            checks.add("gcm_tag", False, "authentication tag mismatch (tampered or wrong data)")
    del key

    if plaintext is None:
        checks.skip("plaintext_sha256", "not decrypted")
    else:
        same = hashlib.sha256(plaintext).hexdigest() == file.plaintext_sha256
        checks.add("plaintext_sha256", same, None if same else "decrypted content changed")
    del plaintext  # verification never returns or keeps file content

    return _store(db, user_id, "file", str(file.id), checks)


def verify_audit_chain(db: Session, user_id: uuid.UUID) -> VerificationRun:
    """Wrap audit.service.verify_chain into a stored VerificationRun."""
    result = audit_service.verify_chain(db)
    checks = _Checks()
    detail = (f"{result.checked_entries} entries verified" if result.valid
              else f"broken at entry {result.first_broken_id}: {result.reason}")
    checks.add("audit_chain", result.valid, detail)
    return _store(db, user_id, "audit_chain", None, checks)


def list_runs(db: Session, limit: int, offset: int) -> tuple[list[VerificationRun], int]:
    total = db.scalar(select(func.count()).select_from(VerificationRun))
    rows = db.scalars(select(VerificationRun).order_by(VerificationRun.created_at.desc())
                      .limit(limit).offset(offset)).all()
    return list(rows), total
