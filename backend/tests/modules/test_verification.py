"""M9 verification service with TEST DOUBLES for M2-M6 (stubs on this branch).

Real AES-256-GCM data is used (cryptography's AESGCM), so the gcm_tag / hash checks run on
genuine ciphertext. End-to-end attacks against the real modules are in tests/security/.
"""

import hashlib
import os
import uuid
from types import SimpleNamespace

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select

from app.core.errors import AppError
from app.models import AuditLog, File, VerificationRun
from app.modules.audit import service as audit_service
from app.modules.audit.schemas import ChainVerification
from app.modules.encryption import service as encryption_service
from app.modules.keys import service as keys_service
from app.modules.sharing import service as sharing_service
from app.modules.signatures import service as signatures_service
from app.modules.verification import service as verification
from tests.helpers import fake_append_entries

PLAINTEXT = b"top secret quarterly numbers"


@pytest.fixture
def world(monkeypatch, db, create_user):
    owner = create_user()
    key, nonce, file_id = AESGCM.generate_key(256), os.urandom(12), uuid.uuid4()
    blob = AESGCM(key).encrypt(nonce, PLAINTEXT, file_id.bytes)
    file = File(id=file_id, owner_id=owner.id, original_filename="q.txt", content_type="text/plain",
                size_bytes=len(PLAINTEXT), storage_path=f"{file_id}.bin",
                encryption_algorithm="AES-256-GCM", nonce=nonce,
                plaintext_sha256=hashlib.sha256(PLAINTEXT).hexdigest(),
                ciphertext_sha256=hashlib.sha256(blob).hexdigest())
    db.add(file)
    db.commit()
    state = {"blob": blob, "key": key, "signature_ok": True, "chain": None}

    def require_access(db_, user_id, fid, permission):
        if user_id != owner.id or fid != file_id:
            raise AppError(404, "File not found.")
        return SimpleNamespace(wrapped_file_key=b"wrapped", wrapping_key_id=uuid.uuid4())

    def unwrap(db_, uid, wrapped, kid):
        if state["key"] is None:
            raise AppError(502, "The file key could not be unwrapped.")
        return state["key"]

    def load(path):
        if state["blob"] is None:
            raise AppError(502, "missing")
        return state["blob"]

    def decrypt(ct, n, k, aad):
        try:
            return AESGCM(k).decrypt(n, ct, aad)
        except InvalidTag as exc:
            raise AppError(502, "integrity") from exc

    monkeypatch.setattr(sharing_service, "require_access", require_access)
    monkeypatch.setattr(keys_service, "unwrap_key_for_user", unwrap)
    monkeypatch.setattr(encryption_service, "load_ciphertext", load)
    monkeypatch.setattr(encryption_service, "decrypt_bytes", decrypt)
    monkeypatch.setattr(signatures_service, "verify_manifest", lambda db_, f: state["signature_ok"])
    monkeypatch.setattr(audit_service, "verify_chain", lambda db_: state["chain"])
    monkeypatch.setattr(audit_service, "append_entries", fake_append_entries)
    return SimpleNamespace(owner=owner, file=file, state=state)


def _checks(run):
    return {c["name"]: c["passed"] for c in run.checks}


def test_intact_file_passes_every_check(world, db):
    run = verification.verify_file(db, world.owner.id, world.file.id)
    assert run.passed and set(_checks(run).values()) == {True}
    assert list(_checks(run)) == ["blob_present", "ciphertext_sha256", "signature",
                                  "file_key_unwrap", "gcm_tag", "plaintext_sha256"]
    assert PLAINTEXT.decode() not in str(run.checks)  # content never in the report


def test_tampered_blob_fails_hash_and_tag(world, db):
    blob = bytearray(world.state["blob"])
    blob[3] ^= 0x01
    world.state["blob"] = bytes(blob)
    checks = _checks(verification.verify_file(db, world.owner.id, world.file.id))
    assert checks["ciphertext_sha256"] is False and checks["gcm_tag"] is False
    assert checks["plaintext_sha256"] is False  # "not checked" is never reported as passed


def test_wrong_key_fails_unwrap_or_tag(world, db):
    world.state["key"] = AESGCM.generate_key(256)
    assert _checks(verification.verify_file(db, world.owner.id, world.file.id))["gcm_tag"] is False
    world.state["key"] = None
    checks = _checks(verification.verify_file(db, world.owner.id, world.file.id))
    assert checks["file_key_unwrap"] is False and checks["gcm_tag"] is False


def test_missing_blob_and_bad_signature(world, db):
    world.state["blob"] = None
    world.state["signature_ok"] = False
    run = verification.verify_file(db, world.owner.id, world.file.id)
    checks = _checks(run)
    assert not run.passed and checks["blob_present"] is False and checks["signature"] is False


def test_verification_needs_access(world, db, create_user):
    with pytest.raises(AppError) as err:
        verification.verify_file(db, create_user().id, world.file.id)
    assert err.value.status_code == 404


def test_audit_chain_run(world, db):
    world.state["chain"] = ChainVerification(valid=False, checked_entries=9, first_broken_id=4,
                                             reason="entry content or entry_hash was modified")
    run = verification.verify_audit_chain(db, world.owner.id)
    assert run.passed is False and "broken at entry 4" in run.checks[0]["detail"]


def test_api_reports_and_history(world, client_as, create_user, db):
    admin = create_user(role="admin")
    world.state["chain"] = ChainVerification(valid=True, checked_entries=3)
    r = client_as(world.owner).post(f"/api/v1/verification/files/{world.file.id}")
    assert r.status_code == 200 and r.json()["passed"] is True
    assert r.json()["target_type"] == "file" and len(r.json()["checks"]) == 6
    assert client_as(world.owner).post("/api/v1/verification/audit-chain").status_code == 403
    assert client_as(admin).post("/api/v1/verification/audit-chain").json()["passed"] is True
    runs = client_as(admin).get("/api/v1/verification/runs").json()
    assert runs["total"] == 2
    assert client_as(world.owner).get("/api/v1/verification/runs").status_code == 403
    assert db.scalar(select(VerificationRun.passed).where(VerificationRun.target_type == "file"))
    events = db.scalars(select(AuditLog.event_type)).all()
    assert events.count("verification.run") == 2
