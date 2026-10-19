"""M5: default-deny access control, sharing, revocation, expiry, download limits, IDOR.

M3 is a stub on this branch, so key wrapping is a TEST DOUBLE that tags each wrapped key
with its recipient's user id - enough to prove M5 re-wraps for the right user without
ever storing the raw key. Real RSA/ECC wrapping is covered by M3 and the M9 suite.
"""

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select, update

from app.core.database import session_scope
from app.core.errors import AppError
from app.models import AuditLog, File, FileAccessGrant, UserKey
from app.modules.audit import service as audit_service
from app.modules.keys import service as keys_service
from app.modules.keys.schemas import WrappedKey
from app.modules.sharing import service as sharing
from tests.helpers import fake_append_entries


def _key_id(db, user_id):
    key = db.scalar(select(UserKey).where(UserKey.user_id == user_id))
    if key is None:
        key = UserKey(user_id=user_id, purpose="encryption", algorithm="TEST-ONLY",
                      public_key_pem="-", encrypted_private_key=b"-", private_key_nonce=b"-",
                      fingerprint=uuid.uuid4().hex * 2)
        db.add(key)
        db.flush()
    return key.id


@pytest.fixture(autouse=True)
def doubles(monkeypatch):
    def wrap(db, user_id, file_key):
        return WrappedKey(wrapped=b"W" + user_id.bytes + file_key, key_id=_key_id(db, user_id))

    def unwrap(db, user_id, wrapped, key_id):
        if wrapped[1:17] != user_id.bytes:
            raise AppError(502, "wrapped for someone else")
        return wrapped[17:]

    monkeypatch.setattr(keys_service, "wrap_key_for_user", wrap)
    monkeypatch.setattr(keys_service, "unwrap_key_for_user", unwrap)
    monkeypatch.setattr(audit_service, "append_entries", fake_append_entries)


FILE_KEY = os.urandom(32)


def owned_file(db, owner):
    file = File(owner_id=owner.id, original_filename="plan.pdf", content_type="application/pdf",
                size_bytes=1, storage_path="x.bin", encryption_algorithm="AES-256-GCM",
                nonce=os.urandom(12), plaintext_sha256="0" * 64, ciphertext_sha256="1" * 64)
    db.add(file)
    db.flush()
    sharing.create_owner_grant(db, file, keys_service.wrap_key_for_user(db, owner.id, FILE_KEY))
    db.commit()
    return file


def share(db, owner, file, recipient, **kw):
    with session_scope() as s:
        grant = sharing.share_file(s, owner.id, file.id, recipient.email, kw.get("expires_at"),
                                   kw.get("max_downloads"))
        return grant.id


def access(user, file_id, permission="read"):
    with session_scope() as s:
        return sharing.require_access(s, user.id, file_id, permission).id


def denied_reasons(db):
    db.expire_all()
    return [d["reason"] for d in db.scalars(select(AuditLog.details).where(
        AuditLog.event_type == "share.access_denied").order_by(AuditLog.id))]


# --- default deny ------------------------------------------------------------------------


def test_owner_has_access_and_strangers_get_the_same_404_as_missing_files(create_user, db):
    alice, mallory = create_user(), create_user()
    file = owned_file(db, alice)
    access(alice, file.id, "owner")
    errors = []
    for file_id in (file.id, uuid.uuid4()):
        with pytest.raises(AppError) as err:
            access(mallory, file_id)
        errors.append((err.value.status_code, err.value.message))
    assert errors[0] == errors[1] == (404, "File not found.")  # no existence oracle
    assert denied_reasons(db) == ["no_grant", "no_such_file"]  # survived the rollbacks


def test_deleted_file_denies_everyone(create_user, db):
    alice = create_user()
    file = owned_file(db, alice)
    db.execute(update(File).where(File.id == file.id).values(deleted_at=datetime.now(UTC)))
    db.commit()
    with pytest.raises(AppError):
        access(alice, file.id)


# --- sharing -----------------------------------------------------------------------------


def test_share_rewraps_the_file_key_for_the_recipient(create_user, db):
    alice, bob = create_user(), create_user()
    file = owned_file(db, alice)
    grant = db.get(FileAccessGrant, share(db, alice, file, bob))
    assert grant.permission == "read" and grant.granted_by_id == alice.id
    assert grant.wrapped_file_key[1:17] == bob.id.bytes  # wrapped for bob, not alice
    assert keys_service.unwrap_key_for_user(db, bob.id, grant.wrapped_file_key,
                                            grant.wrapping_key_id) == FILE_KEY
    access(bob, file.id)
    with pytest.raises(AppError):
        access(bob, file.id, "owner")  # read grant can't act as owner


def test_recipient_cannot_reshare_and_strangers_cannot_share(create_user, db):
    alice, bob, carol = create_user(), create_user(), create_user()
    file = owned_file(db, alice)
    share(db, alice, file, bob)
    for actor in (bob, carol):
        with pytest.raises(AppError) as err:
            share(db, actor, file, carol if actor is bob else bob)
        assert err.value.status_code == 404
    assert db.scalar(select(func.count()).select_from(FileAccessGrant)) == 2


def test_share_validation(create_user, db):
    alice = create_user()
    file = owned_file(db, alice)
    with pytest.raises(AppError) as err:
        share(db, alice, file, alice)
    assert err.value.status_code == 422
    ghost = type("U", (), {"email": "ghost@example.com"})()
    with pytest.raises(AppError) as err:
        share(db, alice, file, ghost)
    assert err.value.status_code == 404
    bob = create_user()
    with pytest.raises(AppError) as err:
        share(db, alice, file, bob, expires_at=datetime.now(UTC) - timedelta(minutes=1))
    assert err.value.status_code == 422


def test_expired_share_denies_access(create_user, db):
    alice, bob = create_user(), create_user()
    file = owned_file(db, alice)
    grant_id = share(db, alice, file, bob, expires_at=datetime.now(UTC) + timedelta(hours=1))
    access(bob, file.id)
    db.execute(update(FileAccessGrant).where(FileAccessGrant.id == grant_id)
               .values(expires_at=datetime.now(UTC) - timedelta(seconds=1)))
    db.commit()
    with pytest.raises(AppError):
        access(bob, file.id)
    assert denied_reasons(db) == ["expired"]


def test_revoked_share_denies_access_and_reshare_reactivates(create_user, db):
    alice, bob = create_user(), create_user()
    file = owned_file(db, alice)
    grant_id = share(db, alice, file, bob, max_downloads=1)
    with session_scope() as s:
        sharing.revoke_share(s, alice.id, grant_id)
    with pytest.raises(AppError):
        access(bob, file.id)
    again = share(db, alice, file, bob)
    assert again == grant_id  # same row, reactivated with a fresh wrapped key
    access(bob, file.id)
    db.expire_all()
    assert db.get(FileAccessGrant, grant_id).download_count == 0


def test_only_the_owner_can_revoke_and_owner_grant_is_protected(create_user, db):
    alice, bob, mallory = create_user(), create_user(), create_user()
    file = owned_file(db, alice)
    grant_id = share(db, alice, file, bob)
    for actor in (bob, mallory):
        with pytest.raises(AppError) as err, session_scope() as s:
            sharing.revoke_share(s, actor.id, grant_id)
        assert err.value.status_code == 404
    owner_grant = db.scalar(select(FileAccessGrant.id).where(
        FileAccessGrant.permission == "owner"))
    with pytest.raises(AppError) as err, session_scope() as s:
        sharing.revoke_share(s, alice.id, owner_grant)
    assert err.value.status_code == 422
    with pytest.raises(AppError) as err, session_scope() as s:
        sharing.revoke_share(s, alice.id, uuid.uuid4())
    assert err.value.status_code == 404


# --- download limits ---------------------------------------------------------------------


def download(user, file_id):
    with session_scope() as s:
        sharing.record_download(s, sharing.require_access(s, user.id, file_id, "read"))


def test_download_limit_is_enforced(create_user, db):
    alice, bob = create_user(), create_user()
    file = owned_file(db, alice)
    share(db, alice, file, bob, max_downloads=2)
    download(bob, file.id)
    download(bob, file.id)
    with pytest.raises(AppError):
        download(bob, file.id)
    for _ in range(3):
        download(alice, file.id)  # owner downloads are never limited


def test_concurrent_downloads_never_exceed_the_limit(create_user, db):
    if db.get_bind().dialect.name != "postgresql":
        pytest.skip("needs PostgreSQL (TEST_DATABASE_URL); runs in CI")
    from concurrent.futures import ThreadPoolExecutor

    alice, bob = create_user(), create_user()
    file = owned_file(db, alice)
    grant_id = share(db, alice, file, bob, max_downloads=3)

    def attempt(_):
        try:
            download(bob, file.id)
            return True
        except AppError:
            return False

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(attempt, range(10)))
    db.expire_all()
    assert sum(results) == 3
    assert db.get(FileAccessGrant, grant_id).download_count == 3


# --- API ---------------------------------------------------------------------------------


def _api_user(create_user):
    return create_user(email=f"{uuid.uuid4().hex[:8]}@example.com")  # passes email validation


def test_share_api_and_listings(client_as, create_user, db):
    alice, bob, carol = (_api_user(create_user) for _ in range(3))
    file = owned_file(db, alice)
    r = client_as(alice).post("/api/v1/shares", json={
        "file_id": str(file.id), "recipient_email": bob.email.upper(), "max_downloads": 5})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["grantee_email"] == bob.email and body["active"] and body["file_name"] == "plan.pdf"
    assert "wrapped_file_key" not in body

    out = client_as(alice).get("/api/v1/shares/outgoing").json()
    inc = client_as(bob).get("/api/v1/shares/incoming").json()
    assert out["total"] == inc["total"] == 1 and out["items"][0]["id"] == inc["items"][0]["id"]
    assert client_as(carol).get("/api/v1/shares/incoming").json()["total"] == 0
    assert client_as(carol).get("/api/v1/shares/outgoing").json()["total"] == 0

    assert client_as(carol).delete(f"/api/v1/shares/{body['id']}").status_code == 404  # IDOR
    assert client_as(alice).delete(f"/api/v1/shares/{body['id']}").status_code == 204
    after = client_as(bob).get("/api/v1/shares/incoming").json()["items"][0]
    assert after["active"] is False and after["revoked_at"] is not None


def test_sharing_someone_elses_file_via_api_is_404(client_as, create_user, db):
    alice, mallory = _api_user(create_user), _api_user(create_user)
    file = owned_file(db, alice)
    r = client_as(mallory).post("/api/v1/shares", json={
        "file_id": str(file.id), "recipient_email": mallory.email})
    assert r.status_code == 404


def test_share_events_are_audited(create_user, db):
    alice, bob = create_user(), create_user()
    file = owned_file(db, alice)
    grant_id = share(db, alice, file, bob)
    with session_scope() as s:
        sharing.revoke_share(s, alice.id, grant_id)
    events = db.scalars(select(AuditLog.event_type).order_by(AuditLog.id)).all()
    assert events == ["share.create", "share.revoke"]
