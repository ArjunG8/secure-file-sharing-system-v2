"""M5 integration: real M2 (AES-256-GCM, storage, integrity checks), real M3 (RSA-3072 /
X25519 key wrapping, rotation) and real M5 (grants, require_access), driven over HTTP.

test_sharing.py replaces M3 wrapping with a test double; this file does not, so it proves
M5 re-wraps the file key with the recipient's real key pair.

Test doubles, and why:
- M4 (signatures) is a stub on this branch, and upload signs the manifest. While M4 reports
  implemented=False, `m4` substitutes a SHA-256 digest of the manifest (NOT a signature).
  Once M4 is merged the fixture does nothing and these tests run against real RSA-PSS.
- M6: audit_service.append_entries is replaced by the shared fake_append_entries helper
  (as in test_sharing.py / test_encryption.py), so these tests check which events M5
  records without depending on M6's HMAC chain (covered by test_audit.py).
"""

import hashlib
import uuid

import pytest
from sqlalchemy import select, update

from app.core.config import get_settings
from app.core.errors import AppError
from app.models import AuditLog, File, FileAccessGrant, UserKey
from app.modules.audit import service as audit_service
from app.modules.encryption import storage
from app.modules.keys import service as keys_service
from app.modules.keys.schemas import ALGORITHMS
from app.modules.signatures import MODULE_INFO as M4_INFO
from app.modules.signatures import service as signatures_service
from app.modules.signatures.schemas import SignatureResult
from tests.helpers import fake_append_entries

DATA = b"Board minutes: acquisition target and price, strictly confidential.\n" * 200
OTHER = {"rsa": "ecc", "ecc": "rsa"}


@pytest.fixture(autouse=True)
def m4(monkeypatch):
    if M4_INFO.implemented:
        return

    def manifest(file):
        return "|".join([str(file.id), file.ciphertext_sha256, file.plaintext_sha256,
                         file.nonce.hex(), str(file.owner_id)]).encode()

    def sign(db, user_id, data):
        key = keys_service.get_active_key(db, user_id, "signing")  # real M3 signing key
        return SignatureResult(signature=hashlib.sha256(data).digest(), key_id=key.id,
                               algorithm=key.algorithm)

    monkeypatch.setattr(signatures_service, "build_manifest", manifest)
    monkeypatch.setattr(signatures_service, "sign_manifest", sign)
    monkeypatch.setattr(signatures_service, "verify_manifest",
                        lambda db, f: f.signature == hashlib.sha256(manifest(f)).digest())


@pytest.fixture(autouse=True)
def audit(monkeypatch):
    monkeypatch.setattr(audit_service, "append_entries", fake_append_entries)


@pytest.fixture(params=["rsa", "ecc"])
def family(request, monkeypatch):
    monkeypatch.setattr(get_settings(), "default_key_algorithm", request.param)
    return request.param


@pytest.fixture
def people(create_user):
    # @example.com: recipient_email must pass email validation.
    return [create_user(email=f"{name}-{uuid.uuid4().hex[:6]}@example.com")
            for name in ("alice", "bob", "eve")]


def upload(client, data=DATA):
    r = client.post("/api/v1/files", files={"file": ("minutes.txt", data, "text/plain")})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def share_with(client, file_id, user):
    r = client.post("/api/v1/shares", json={"file_id": file_id, "recipient_email": user.email})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def grant_of(db, file_id, user):
    db.expire_all()
    return db.scalar(select(FileAccessGrant).where(
        FileAccessGrant.file_id == uuid.UUID(file_id), FileAccessGrant.grantee_id == user.id))


def events(db, event_type):
    """Audit rows of one type in insertion order (PostgreSQL has no default order)."""
    db.expire_all()
    return db.scalars(select(AuditLog).where(AuditLog.event_type == event_type)
                      .order_by(AuditLog.id)).all()


def test_share_download_and_revoke_with_real_keys(family, people, client_as, db):
    alice, bob, eve = people
    file_id = upload(client_as(alice))
    file = db.get(File, uuid.UUID(file_id))
    assert file.owner_id == alice.id
    blob = storage.read(file.storage_path)
    assert DATA[:40] not in blob and hashlib.sha256(blob).hexdigest() == file.ciphertext_sha256

    # Before sharing: Bob and Eve get the same 404 as for a missing file.
    for user in (bob, eve):
        assert client_as(user).get(f"/api/v1/files/{file_id}").status_code == 404
        assert client_as(user).get(f"/api/v1/files/{file_id}/download").status_code == 404
    assert {e.actor_user_id for e in events(db, "share.access_denied")} == {bob.id, eve.id}

    grant_id = share_with(client_as(alice), file_id, bob)

    # Bob's grant holds the file key wrapped with HIS real encryption key.
    owner_grant, bob_grant = grant_of(db, file_id, alice), grant_of(db, file_id, bob)
    bob_key = db.get(UserKey, bob_grant.wrapping_key_id)
    assert bob_key.user_id == bob.id and bob_key.purpose == "encryption"
    assert bob_key.algorithm == ALGORITHMS[(family, "encryption")]
    assert bob_grant.wrapped_file_key != owner_grant.wrapped_file_key
    assert keys_service.unwrap_key_for_user(
        db, bob.id, bob_grant.wrapped_file_key, bob_grant.wrapping_key_id
    ) == keys_service.unwrap_key_for_user(
        db, alice.id, owner_grant.wrapped_file_key, owner_grant.wrapping_key_id)
    with pytest.raises(AppError) as denied:  # Bob's key id is not usable as Eve
        keys_service.unwrap_key_for_user(db, eve.id, bob_grant.wrapped_file_key,
                                         bob_grant.wrapping_key_id)
    assert denied.value.status_code == 404

    r = client_as(bob).get(f"/api/v1/files/{file_id}/download")
    assert r.status_code == 200 and r.content == DATA
    assert client_as(bob).get(f"/api/v1/files/{file_id}").json()["permission"] == "read"
    assert [e.actor_user_id for e in events(db, "file.download")] == [bob.id]

    # An unrelated user still can't read it, reshare it, or revoke Bob.
    assert client_as(eve).get(f"/api/v1/files/{file_id}/download").status_code == 404
    assert client_as(eve).post("/api/v1/shares", json={
        "file_id": file_id, "recipient_email": eve.email}).status_code == 404
    assert client_as(eve).delete(f"/api/v1/shares/{grant_id}").status_code == 404
    assert client_as(bob).post("/api/v1/shares", json={  # a read grant can't reshare
        "file_id": file_id, "recipient_email": eve.email}).status_code == 404

    assert client_as(alice).delete(f"/api/v1/shares/{grant_id}").status_code == 204
    assert client_as(bob).get(f"/api/v1/files/{file_id}/download").status_code == 404
    assert client_as(bob).get("/api/v1/files").json()["total"] == 0
    assert [e.details["reason"] for e in events(db, "share.access_denied")
            if e.actor_user_id == bob.id][-1] == "revoked"
    assert client_as(alice).get(f"/api/v1/files/{file_id}/download").content == DATA


def test_key_rotation_keeps_shared_files_readable(family, people, client_as, db):
    alice, bob, _ = people
    file_id = upload(client_as(alice))
    share_with(client_as(alice), file_id, bob)
    old_key_id = grant_of(db, file_id, bob).wrapping_key_id

    # Rotate both users' encryption keys, Bob's to the other family as well.
    r = client_as(bob).post("/api/v1/keys/rotate",
                            json={"purpose": "encryption", "algorithm": OTHER[family]})
    assert r.status_code == 200, r.text
    assert r.json()["algorithm"] == ALGORITHMS[(OTHER[family], "encryption")]
    assert client_as(alice).post("/api/v1/keys/rotate",
                                 json={"purpose": "encryption"}).status_code == 200
    db.expire_all()
    assert db.get(UserKey, old_key_id).is_active is False

    # Grants wrapped under the old (now inactive) keys still decrypt.
    assert client_as(bob).get(f"/api/v1/files/{file_id}/download").content == DATA
    assert client_as(alice).get(f"/api/v1/files/{file_id}/download").content == DATA

    # A new share after rotation is wrapped under Bob's NEW key.
    newer_id = upload(client_as(alice), data=b"after rotation")
    share_with(client_as(alice), newer_id, bob)
    assert str(grant_of(db, newer_id, bob).wrapping_key_id) == r.json()["id"]
    assert client_as(bob).get(f"/api/v1/files/{newer_id}/download").content == b"after rotation"


def test_tampered_ciphertext_is_rejected_for_the_recipient(family, people, client_as, db,
                                                          monkeypatch):
    alice, bob, _ = people
    file_id = upload(client_as(alice))
    share_with(client_as(alice), file_id, bob)
    file = db.get(File, uuid.UUID(file_id))
    path = storage.resolve(file.storage_path)
    original = path.read_bytes()

    tampered = bytearray(original)
    tampered[20] ^= 0x01
    path.write_bytes(bytes(tampered))
    r = client_as(bob).get(f"/api/v1/files/{file_id}/download")
    assert r.status_code == 502 and r.json()["error"]["details"]["check"] == "ciphertext_sha256"
    assert DATA[:40] not in r.content

    # Tamper the GCM tag AND update the stored hash: the real AES-GCM tag check still fails.
    tampered = bytearray(original)
    tampered[-1] ^= 0x01
    path.write_bytes(bytes(tampered))
    db.execute(update(File).where(File.id == file.id)
               .values(ciphertext_sha256=hashlib.sha256(bytes(tampered)).hexdigest()))
    db.commit()
    monkeypatch.setattr(signatures_service, "verify_manifest", lambda db_, f: True)
    r = client_as(bob).get(f"/api/v1/files/{file_id}/download")
    assert r.status_code == 502 and r.json()["error"]["details"]["check"] == "gcm_tag"
    assert [e.details["check"] for e in events(db, "file.integrity_failure")] == [
        "ciphertext_sha256", "gcm_tag"]


def test_tampered_wrapped_key_is_rejected_by_m3(family, people, client_as, db):
    alice, bob, _ = people
    file_id = upload(client_as(alice))
    share_with(client_as(alice), file_id, bob)
    grant = grant_of(db, file_id, bob)
    wrapped = bytearray(grant.wrapped_file_key)
    wrapped[-1] ^= 0x01
    db.execute(update(FileAccessGrant).where(FileAccessGrant.id == grant.id)
               .values(wrapped_file_key=bytes(wrapped)))
    db.commit()
    r = client_as(bob).get(f"/api/v1/files/{file_id}/download")
    assert r.status_code == 502 and r.json()["error"]["module"] == "M3"
    assert client_as(alice).get(f"/api/v1/files/{file_id}/download").content == DATA


def test_deleted_file_denies_the_recipient(family, people, client_as, db):
    alice, bob, _ = people
    file_id = upload(client_as(alice))
    share_with(client_as(alice), file_id, bob)
    path = storage.resolve(db.get(File, uuid.UUID(file_id)).storage_path)
    assert client_as(alice).delete(f"/api/v1/files/{file_id}").status_code == 204
    assert client_as(bob).get(f"/api/v1/files/{file_id}/download").status_code == 404
    assert not path.exists()
