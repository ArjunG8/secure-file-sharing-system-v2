"""M2: AES-256-GCM, blob storage, upload/download flow, integrity failures, limits.

On this branch M3/M4/M5 are stubs, so the `deps` fixture replaces them with TEST DOUBLES
(fake wrapping, a fake hash-based "signature", a minimal grant check). They exist only to
exercise M2's orchestration; the real end-to-end flow is tested in tests/security
(M9) once every module is merged.
"""

import hashlib
import json
import os
import uuid

import pytest
from sqlalchemy import func, select, update

from app.core.config import get_settings
from app.core.errors import AppError
from app.models import AuditLog, File, FileAccessGrant, UserKey
from app.modules.audit import service as audit_service
from app.modules.encryption import aes_gcm, storage
from app.modules.encryption import service as enc
from app.modules.keys import service as keys_service
from app.modules.keys.schemas import WrappedKey
from app.modules.sharing import service as sharing_service
from app.modules.signatures import service as signatures_service
from app.modules.signatures.schemas import SignatureResult
from tests.helpers import fake_append_entries

PLAINTEXT = b"Quarterly report: confidential numbers 42\n" * 100


def _dummy_key_id(db, user_id, purpose):
    """A placeholder user_keys row (FK target), created in the CALLER's transaction."""
    key = db.scalar(select(UserKey).where(UserKey.user_id == user_id, UserKey.purpose == purpose))
    if key is None:
        key = UserKey(user_id=user_id, purpose=purpose, algorithm="TEST-ONLY", public_key_pem="-",
                      encrypted_private_key=b"-", private_key_nonce=b"-",
                      fingerprint=uuid.uuid4().hex + uuid.uuid4().hex)
        db.add(key)
        db.flush()
    return key.id


@pytest.fixture
def deps(monkeypatch, db):
    """Test doubles for M3 (wrap/unwrap), M4 (sign/verify) and M5 (grants)."""
    def manifest(file):
        return json.dumps({"id": str(file.id), "c": file.ciphertext_sha256,
                           "p": file.plaintext_sha256, "n": file.nonce.hex()}).encode()

    monkeypatch.setattr(signatures_service, "build_manifest", manifest)
    monkeypatch.setattr(signatures_service, "sign_manifest", lambda db_, uid, m: SignatureResult(
        signature=hashlib.sha256(m).digest(), key_id=_dummy_key_id(db_, uid, "signing"),
        algorithm="TEST-ONLY"))
    monkeypatch.setattr(signatures_service, "verify_manifest", lambda db_, f: (
        f.signature == hashlib.sha256(manifest(f)).digest()))
    monkeypatch.setattr(keys_service, "wrap_key_for_user", lambda db_, uid, k: WrappedKey(
        wrapped=b"W" + k, key_id=_dummy_key_id(db_, uid, "encryption")))
    monkeypatch.setattr(keys_service, "unwrap_key_for_user", lambda db_, uid, w, kid: w[1:])

    def owner_grant(db_, file, wrapped):
        grant = FileAccessGrant(file_id=file.id, grantee_id=file.owner_id,
                                granted_by_id=file.owner_id, permission="owner",
                                wrapped_file_key=wrapped.wrapped, wrapping_key_id=wrapped.key_id)
        db_.add(grant)
        return grant

    def require_access(db_, user_id, file_id, permission):
        grant = db_.scalar(select(FileAccessGrant).where(
            FileAccessGrant.file_id == file_id, FileAccessGrant.grantee_id == user_id,
            FileAccessGrant.revoked_at.is_(None)))
        if grant is None or (permission == "owner" and grant.permission != "owner"):
            raise AppError(404, "File not found.")
        return grant

    monkeypatch.setattr(sharing_service, "create_owner_grant", owner_grant)
    monkeypatch.setattr(sharing_service, "require_access", require_access)
    monkeypatch.setattr(sharing_service, "record_download", lambda db_, g: None)
    monkeypatch.setattr(audit_service, "append_entries", fake_append_entries)


def upload(client, name="report.txt", data=PLAINTEXT, ctype="text/plain"):
    return client.post("/api/v1/files", files={"file": (name, data, ctype)})


# --- primitives --------------------------------------------------------------------------


def test_aes_gcm_round_trip_with_fresh_key_and_nonce():
    a, b = aes_gcm.encrypt(PLAINTEXT, b"aad"), aes_gcm.encrypt(PLAINTEXT, b"aad")
    assert len(a.key) == 32 and len(a.nonce) == 12
    assert a.key != b.key and a.nonce != b.nonce and a.ciphertext != b.ciphertext
    assert len(a.ciphertext) == len(PLAINTEXT) + 16
    assert aes_gcm.decrypt(a.ciphertext, a.nonce, a.key, b"aad") == PLAINTEXT


@pytest.mark.parametrize("mutate", ["ciphertext", "tag", "nonce", "aad", "key"])
def test_any_tampering_fails_authentication(mutate):
    p = aes_gcm.encrypt(PLAINTEXT, b"file-a")
    ct, nonce, key, aad = bytearray(p.ciphertext), bytearray(p.nonce), bytearray(p.key), b"file-a"
    if mutate == "ciphertext":
        ct[0] ^= 1
    elif mutate == "tag":
        ct[-1] ^= 1
    elif mutate == "nonce":
        nonce[0] ^= 1
    elif mutate == "aad":
        aad = b"file-b"
    else:
        key[0] ^= 1
    with pytest.raises(aes_gcm.DecryptionError):
        aes_gcm.decrypt(bytes(ct), bytes(nonce), bytes(key), aad)
    with pytest.raises(AppError) as err:
        enc.decrypt_bytes(bytes(ct), bytes(nonce), bytes(key), aad)
    assert err.value.status_code == 502


@pytest.mark.parametrize(("raw", "safe"), [
    ("../../etc/passwd", "passwd"), ("..\\..\\boot.ini", "boot.ini"), ("a\x00b\nc.txt", "abc.txt"),
    ("", "file"), ("...", "file"), ("x" * 400, "x" * 255), ("résumé.pdf", "résumé.pdf"),
])
def test_filenames_are_metadata_never_paths(raw, safe):
    assert enc.safe_filename(raw) == safe


@pytest.mark.parametrize("name", ["../escape.bin", "sub/dir.bin", "", "..", "/abs.bin"])
def test_storage_refuses_paths_outside_its_root(name):
    with pytest.raises(storage.StorageError):
        storage.resolve(name)


# --- upload / download -------------------------------------------------------------------


def test_upload_stores_only_ciphertext(deps, client_as, create_user, db):
    alice = create_user()
    r = upload(client_as(alice))
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["encryption_algorithm"] == "AES-256-GCM" and body["permission"] == "owner"
    assert not {"nonce", "key", "file_key", "wrapped_file_key", "storage_path"} & set(body)
    file = db.get(File, uuid.UUID(body["id"]))
    blob = storage.read(file.storage_path)
    assert file.storage_path == f"{file.id}.bin" and len(file.nonce) == 12
    assert PLAINTEXT not in blob and b"confidential" not in blob
    assert hashlib.sha256(blob).hexdigest() == file.ciphertext_sha256
    assert hashlib.sha256(PLAINTEXT).hexdigest() == file.plaintext_sha256
    grant = db.scalar(select(FileAccessGrant).where(FileAccessGrant.file_id == file.id))
    assert grant.permission == "owner" and grant.wrapped_file_key != b"W"  # wrapped, not raw


def test_download_round_trip_with_safe_headers(deps, client_as, create_user):
    alice = create_user()
    c = client_as(alice)
    file_id = upload(c, name="Résumé \"final\".txt").json()["id"]
    r = c.get(f"/api/v1/files/{file_id}/download")
    assert r.status_code == 200 and r.content == PLAINTEXT
    assert r.headers["content-type"] == "application/octet-stream"
    assert r.headers["x-content-type-options"] == "nosniff"
    disposition = r.headers["content-disposition"]
    assert disposition.startswith("attachment;") and "filename*=UTF-8''R%C3%A9sum%C3%A9" in disposition


def test_empty_file(deps, client_as, create_user):
    c = client_as(create_user())
    file_id = upload(c, data=b"").json()["id"]
    assert c.get(f"/api/v1/files/{file_id}/download").content == b""


def _uploaded(deps, client_as, create_user, db):
    alice = create_user()
    c = client_as(alice)
    file = db.get(File, uuid.UUID(upload(c).json()["id"]))
    return c, file


def _integrity_events(db):
    return db.scalars(select(AuditLog.details).where(
        AuditLog.event_type == "file.integrity_failure")).all()


def test_tampered_blob_is_rejected_and_audited(deps, client_as, create_user, db):
    c, file = _uploaded(deps, client_as, create_user, db)
    path = storage.resolve(file.storage_path)
    blob = bytearray(path.read_bytes())
    blob[10] ^= 0x01
    path.write_bytes(bytes(blob))
    r = c.get(f"/api/v1/files/{file.id}/download")
    assert r.status_code == 502 and r.json()["error"]["code"] == "integrity_failure"
    assert PLAINTEXT[:20] not in r.content
    assert _integrity_events(db) == [{"check": "ciphertext_sha256"}]


def test_tampered_blob_with_matching_hash_still_fails_the_gcm_tag(deps, client_as, create_user,
                                                                   db, monkeypatch):
    c, file = _uploaded(deps, client_as, create_user, db)
    path = storage.resolve(file.storage_path)
    blob = bytearray(path.read_bytes())
    blob[-1] ^= 0x01  # flip a tag bit
    path.write_bytes(bytes(blob))
    db.execute(update(File).where(File.id == file.id)
               .values(ciphertext_sha256=hashlib.sha256(bytes(blob)).hexdigest()))
    db.commit()
    monkeypatch.setattr(signatures_service, "verify_manifest", lambda db_, f: True)
    r = c.get(f"/api/v1/files/{file.id}/download")
    assert r.status_code == 502
    assert _integrity_events(db) == [{"check": "gcm_tag"}]


def test_changed_nonce_is_rejected(deps, client_as, create_user, db, monkeypatch):
    c, file = _uploaded(deps, client_as, create_user, db)
    db.execute(update(File).where(File.id == file.id).values(nonce=os.urandom(12)))
    db.commit()
    monkeypatch.setattr(signatures_service, "verify_manifest", lambda db_, f: True)
    assert c.get(f"/api/v1/files/{file.id}/download").status_code == 502


def test_ciphertext_moved_to_another_file_fails_the_aad_check(deps, client_as, create_user, db,
                                                               monkeypatch):
    alice = create_user()
    c = client_as(alice)
    a = db.get(File, uuid.UUID(upload(c, name="a.txt").json()["id"]))
    b = db.get(File, uuid.UUID(upload(c, name="b.txt", data=b"other").json()["id"]))
    # Attacker with storage + DB access makes B point at A's blob, nonce, hash and key.
    a_grant = db.scalar(select(FileAccessGrant).where(FileAccessGrant.file_id == a.id))
    db.execute(update(File).where(File.id == b.id).values(
        storage_path=a.storage_path, nonce=a.nonce, ciphertext_sha256=a.ciphertext_sha256))
    db.execute(update(FileAccessGrant).where(FileAccessGrant.file_id == b.id)
               .values(wrapped_file_key=a_grant.wrapped_file_key))
    db.commit()
    monkeypatch.setattr(signatures_service, "verify_manifest", lambda db_, f: True)
    assert c.get(f"/api/v1/files/{b.id}/download").status_code == 502  # AAD = B's id


def test_invalid_signature_blocks_the_download(deps, client_as, create_user, db, monkeypatch):
    c, file = _uploaded(deps, client_as, create_user, db)
    monkeypatch.setattr(signatures_service, "verify_manifest", lambda db_, f: False)
    r = c.get(f"/api/v1/files/{file.id}/download")
    assert r.status_code == 502 and _integrity_events(db) == [{"check": "signature"}]


def test_missing_blob_is_an_integrity_error_not_a_crash(deps, client_as, create_user, db):
    c, file = _uploaded(deps, client_as, create_user, db)
    storage.delete(file.storage_path)
    assert c.get(f"/api/v1/files/{file.id}/download").status_code == 502


# --- limits and failure cleanup ----------------------------------------------------------


def test_oversized_upload_is_rejected_without_leftovers(deps, client_as, create_user, db,
                                                         monkeypatch):
    monkeypatch.setattr(get_settings(), "max_upload_bytes", 1000)
    before = set(storage.storage_root().iterdir())
    r = upload(client_as(create_user()), data=b"x" * 1001)
    assert r.status_code == 413
    assert db.scalar(select(func.count()).select_from(File)) == 0
    assert set(storage.storage_root().iterdir()) == before
    assert upload(client_as(create_user()), data=b"x" * 1000).status_code == 201


def test_blob_is_removed_when_the_transaction_fails(deps, app, create_user, db, monkeypatch):
    from fastapi.testclient import TestClient

    from app.api.deps import get_current_user

    def broken_append(db_, events):
        raise RuntimeError("audit store down")  # fails at the very end, before COMMIT

    monkeypatch.setattr(audit_service, "append_entries", broken_append)
    user = create_user()
    app.dependency_overrides[get_current_user] = lambda: user
    before = set(storage.storage_root().iterdir())
    with TestClient(app, raise_server_exceptions=False) as client:
        r = client.post("/api/v1/files", files={"file": ("a.txt", b"data", "text/plain")})
    app.dependency_overrides.clear()
    assert r.status_code == 500
    assert db.scalar(select(func.count()).select_from(File)) == 0
    assert set(storage.storage_root().iterdir()) == before


# --- access ------------------------------------------------------------------------------


def test_other_users_cannot_read_list_or_delete(deps, client_as, create_user, db):
    alice, mallory = create_user(), create_user()
    file_id = upload(client_as(alice)).json()["id"]
    m = client_as(mallory)
    assert m.get(f"/api/v1/files/{file_id}/download").status_code == 404
    assert m.get(f"/api/v1/files/{file_id}").status_code == 404
    assert m.delete(f"/api/v1/files/{file_id}").status_code == 404
    assert m.get("/api/v1/files").json()["total"] == 0


def test_list_and_metadata(deps, client_as, create_user):
    c = client_as(create_user())
    ids = [upload(c, name=f"f{i}.txt").json()["id"] for i in range(3)]
    page = c.get("/api/v1/files?limit=2").json()
    assert page["total"] == 3 and len(page["items"]) == 2
    assert {i["permission"] for i in page["items"]} == {"owner"}
    meta = c.get(f"/api/v1/files/{ids[0]}").json()
    assert meta["original_filename"] == "f0.txt" and meta["size_bytes"] == len(PLAINTEXT)


def test_owner_delete_removes_blob_and_access(deps, client_as, create_user, db):
    c, file = _uploaded(deps, client_as, create_user, db)
    path = storage.resolve(file.storage_path)
    assert path.exists()
    assert c.delete(f"/api/v1/files/{file.id}").status_code == 204
    assert not path.exists()
    assert c.get(f"/api/v1/files/{file.id}/download").status_code == 404
    db.expire_all()
    assert db.get(File, file.id).deleted_at is not None  # soft delete keeps the audit trail


def test_upload_and_download_are_audited(deps, client_as, create_user, db):
    c, file = _uploaded(deps, client_as, create_user, db)
    c.get(f"/api/v1/files/{file.id}/download")
    events = db.scalars(select(AuditLog.event_type).order_by(AuditLog.id)).all()
    assert events == ["file.upload", "file.download"]
