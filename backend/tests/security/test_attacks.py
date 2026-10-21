"""End-to-end attack tests against the REAL modules, through the HTTP API.

Every test states which modules it needs. A test is skipped only while one of those
modules is still a stub (MODULE_INFO.implemented is False).
"""

import hashlib
import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, func, select, update

from app.core.config import get_settings
from app.core.modules import all_modules
from app.models import AuditLog, File, FileAccessGrant, User

IMPLEMENTED = {m.code for m in all_modules() if m.implemented}

def needs(*codes):
    missing = [c for c in codes if c not in IMPLEMENTED]
    return pytest.mark.skipif(
        bool(missing),
        reason=f"end-to-end attack test: needs {', '.join(missing)} merged (stub here)",
    )


CORE = ("M1", "M2", "M3", "M4", "M5", "M6")
PASSWORD = "correct horse battery staple"
SECRET = b"Payroll 2026: confidential salary table\n" * 20


# --- Fixtures and helpers ---------------------------------------------------------------

@pytest.fixture
def api(app, monkeypatch):
    settings = get_settings()
    if hasattr(settings, "default_key_algorithm"):
        monkeypatch.setattr(settings, "default_key_algorithm", "ecc")

    try:
        from app.modules.auth.rate_limit import limiter
        limiter.reset()
    except ImportError:
        pass

    with TestClient(app, base_url="https://testserver") as client:
        yield client


class Actor:
    def __init__(self, api, name, role="user", db=None):
        self.email = f"{name}-{uuid.uuid4().hex[:6]}@example.com"
        username = f"{name}{uuid.uuid4().hex[:6]}"

        response = api.post(
            "/api/v1/auth/register",
            json={
                "email": self.email,
                "username": username,
                "password": PASSWORD,
            },
        )
        assert response.status_code == 201, response.text
        self.id = uuid.UUID(response.json()["id"])

        if role == "admin":
            db.execute(
                update(User)
                .where(User.id == self.id)
                .values(role="admin")
            )
            db.commit()

        response = api.post(
            "/api/v1/auth/login",
            json={"email": self.email, "password": PASSWORD},
        )
        assert response.status_code == 200, response.text
        self.headers = {
            "Authorization": f"Bearer {response.json()['access_token']}"
        }


def upload(api, actor, data=SECRET, name="payroll.csv"):
    response = api.post(
        "/api/v1/files",
        headers=actor.headers,
        files={"file": (name, data, "text/csv")},
    )
    assert response.status_code == 201, response.text
    return uuid.UUID(response.json()["id"])


def blob_path(file_id):
    return get_settings().storage_dir.resolve() / f"{file_id}.bin"


def download(api, actor, file_id):
    return api.get(
        f"/api/v1/files/{file_id}/download",
        headers=actor.headers,
    )


def verify(api, actor, file_id):
    response = api.post(
        f"/api/v1/verification/files/{file_id}",
        headers=actor.headers,
    )
    assert response.status_code == 200, response.text
    return {check["name"]: check["passed"] for check in response.json()["checks"]}


def assert_integrity_failure(response):
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "integrity_failure"
    assert SECRET[:20] not in response.content


# --- End-to-end baseline ----------------------------------------------------------------

@needs(*CORE, "M9")
@pytest.mark.parametrize("family", ["rsa", "ecc"])
def test_share_and_download_end_to_end(api, db, family, monkeypatch):
    monkeypatch.setattr(get_settings(), "default_key_algorithm", family)

    alice = Actor(api, "alice")
    bob = Actor(api, "bob")
    file_id = upload(api, alice)

    response = api.post(
        "/api/v1/shares",
        headers=alice.headers,
        json={
            "file_id": str(file_id),
            "recipient_email": bob.email,
        },
    )
    assert response.status_code == 201, response.text

    assert download(api, alice, file_id).content == SECRET
    assert download(api, bob, file_id).content == SECRET
    assert set(verify(api, bob, file_id).values()) == {True}

    from app.modules.audit.service import verify_chain
    assert verify_chain(db).valid


@needs(*CORE)
def test_plaintext_is_never_stored(api, db):
    alice = Actor(api, "alice")
    file_id = upload(api, alice)

    assert SECRET[:30] not in blob_path(file_id).read_bytes()

    row = db.get(File, file_id)
    grant = db.scalar(
        select(FileAccessGrant).where(FileAccessGrant.file_id == file_id)
    )

    for value in (row.nonce, row.signature, grant.wrapped_file_key):
        assert SECRET[:30] not in value

    audit_details = db.scalars(select(AuditLog.details))
    assert not any(SECRET[:20].decode() in str(details) for details in audit_details)


# --- AES-GCM attacks --------------------------------------------------------------------

@needs(*CORE, "M9")
def test_tampered_ciphertext_byte_fails_gcm_tag(api, db):
    alice = Actor(api, "alice")
    file_id = upload(api, alice)

    path = blob_path(file_id)
    blob = bytearray(path.read_bytes())
    blob[len(blob) // 2] ^= 0x01
    path.write_bytes(bytes(blob))

    assert_integrity_failure(download(api, alice, file_id))

    # Even if the stored ciphertext hash is changed, the signature must fail.
    db.execute(
        update(File)
        .where(File.id == file_id)
        .values(ciphertext_sha256=hashlib.sha256(bytes(blob)).hexdigest())
    )
    db.commit()

    assert_integrity_failure(download(api, alice, file_id))

    checks = verify(api, alice, file_id)
    assert checks["gcm_tag"] is False
    assert checks["signature"] is False


@needs(*CORE)
def test_ciphertext_moved_to_another_file_fails_aad_check(api, db):
    from app.modules.encryption import aes_gcm
    from app.modules.keys import service as keys

    alice = Actor(api, "alice")
    file_a_id = upload(api, alice, b"file A " * 10, "a.txt")
    file_b_id = upload(api, alice, b"file B", "b.txt")

    blob_path(file_b_id).write_bytes(blob_path(file_a_id).read_bytes())
    assert_integrity_failure(download(api, alice, file_b_id))

    grant = db.scalar(
        select(FileAccessGrant).where(FileAccessGrant.file_id == file_a_id)
    )
    key = keys.unwrap_key_for_user(
        db,
        alice.id,
        grant.wrapped_file_key,
        grant.wrapping_key_id,
    )

    file_a = db.get(File, file_a_id)
    ciphertext = blob_path(file_a_id).read_bytes()

    assert aes_gcm.decrypt(
        ciphertext, file_a.nonce, key, file_a_id.bytes
    ) == b"file A " * 10

    with pytest.raises(aes_gcm.DecryptionError):
        aes_gcm.decrypt(
            ciphertext, file_a.nonce, key, file_b_id.bytes
        )


@needs(*CORE, "M9")
def test_modified_nonce_fails_decryption(api, db):
    alice = Actor(api, "alice")
    file_id = upload(api, alice)

    db.execute(
        update(File)
        .where(File.id == file_id)
        .values(nonce=b"\x00" * 12)
    )
    db.commit()

    assert_integrity_failure(download(api, alice, file_id))
    assert verify(api, alice, file_id)["gcm_tag"] is False


# --- M4 digital-signature attacks --------------------------------------------------------

@needs(*CORE)
def test_modified_manifest_fails_signature(api, db):
    alice = Actor(api, "alice")
    file_id = upload(api, alice)

    db.execute(
        update(File)
        .where(File.id == file_id)
        .values(original_filename="invoice.exe")
    )
    db.commit()

    assert_integrity_failure(download(api, alice, file_id))

    response = api.post(
        f"/api/v1/signatures/files/{file_id}/verify",
        headers=alice.headers,
    )
    assert response.status_code == 200, response.text
    assert response.json()["signature_valid"] is False
    assert response.json()["ciphertext_intact"] is True


@needs(*CORE)
def test_signature_from_other_user_key_is_rejected(api, db):
    from app.modules.signatures import service as sig

    alice = Actor(api, "alice")
    mallory = Actor(api, "mallory")
    file_id = upload(api, alice)

    file = db.get(File, file_id)
    file.original_filename = "malware.exe"

    # Mallory signs the modified manifest with her own signing key.
    forged = sig.sign_manifest(
        db,
        mallory.id,
        sig.build_manifest(file),
    )
    file.signature = forged.signature
    file.signing_key_id = forged.key_id
    db.commit()

    response = api.post(
        f"/api/v1/signatures/files/{file_id}/verify",
        headers=alice.headers,
    )
    assert response.status_code == 200, response.text
    assert response.json()["signature_valid"] is False
    assert "owner" in response.json()["reason"]

    assert_integrity_failure(download(api, alice, file_id))


# --- M3 key-management attacks -----------------------------------------------------------

@needs(*CORE)
def test_wrong_private_key_cannot_unwrap_file_key(api, db):
    from app.core.errors import AppError
    from app.modules.keys import service as keys

    alice = Actor(api, "alice")
    bob = Actor(api, "bob")
    file_id = upload(api, alice)

    grant = db.scalar(
        select(FileAccessGrant).where(FileAccessGrant.file_id == file_id)
    )

    # Bob cannot use Alice's key ID under his identity.
    with pytest.raises(AppError) as err:
        keys.unwrap_key_for_user(
            db,
            bob.id,
            grant.wrapped_file_key,
            grant.wrapping_key_id,
        )
    assert err.value.status_code == 404

    # Bob's own private key cannot unwrap Alice's wrapped file key.
    bob_key = keys.get_active_key(db, bob.id, "encryption")
    with pytest.raises(AppError) as err:
        keys.unwrap_key_for_user(
            db,
            bob.id,
            grant.wrapped_file_key,
            bob_key.id,
        )
    assert err.value.status_code == 502


# --- M5 access-control attacks -----------------------------------------------------------

@needs(*CORE, "M9")
def test_idor_on_other_users_file_returns_404(api, db):
    alice = Actor(api, "alice")
    bob = Actor(api, "bob")
    file_id = upload(api, alice)

    for target in (file_id, uuid.uuid4()):
        responses = [
            api.get(f"/api/v1/files/{target}", headers=bob.headers),
            api.get(f"/api/v1/files/{target}/download", headers=bob.headers),
            api.get(f"/api/v1/signatures/files/{target}", headers=bob.headers),
            api.post(
                f"/api/v1/verification/files/{target}",
                headers=bob.headers,
            ),
            api.delete(f"/api/v1/files/{target}", headers=bob.headers),
            api.post(
                "/api/v1/shares",
                headers=bob.headers,
                json={
                    "file_id": str(target),
                    "recipient_email": bob.email,
                },
            ),
        ]

        assert [response.status_code for response in responses] == [404] * 6
        assert {
            response.json()["error"]["message"]
            for response in responses[:5]
        } == {"File not found."}

    grant_id = db.scalar(
        select(FileAccessGrant.id).where(FileAccessGrant.file_id == file_id)
    )
    assert api.delete(
        f"/api/v1/shares/{grant_id}",
        headers=bob.headers,
    ).status_code == 404

    assert download(api, alice, file_id).status_code == 200

    denied = db.scalar(
        select(func.count())
        .select_from(AuditLog)
        .where(AuditLog.event_type == "share.access_denied")
    )
    assert denied >= 6


@needs(*CORE)
def test_expired_or_revoked_share_denies_download(api, db):
    alice = Actor(api, "alice")
    bob = Actor(api, "bob")
    file_id = upload(api, alice)

    def share(**extra):
        response = api.post(
            "/api/v1/shares",
            headers=alice.headers,
            json={
                "file_id": str(file_id),
                "recipient_email": bob.email,
                **extra,
            },
        )
        assert response.status_code == 201, response.text
        return response.json()["id"]

    grant_id = share(
        expires_at=(datetime.now(UTC) + timedelta(hours=1)).isoformat()
    )
    assert download(api, bob, file_id).status_code == 200

    db.execute(
        update(FileAccessGrant)
        .where(FileAccessGrant.id == uuid.UUID(grant_id))
        .values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
    )
    db.commit()
    assert download(api, bob, file_id).status_code == 404

    grant_id = share()
    assert api.delete(
        f"/api/v1/shares/{grant_id}",
        headers=alice.headers,
    ).status_code == 204
    assert download(api, bob, file_id).status_code == 404

    share(max_downloads=1)
    assert download(api, bob, file_id).status_code == 200
    assert download(api, bob, file_id).status_code == 404


@needs("M1", "M6", "M7", "M8", "M9")
def test_regular_user_cannot_use_admin_endpoints(api, db):
    user = Actor(api, "user")
    now = datetime.now(UTC)

    responses = [
        api.get("/api/v1/audit/verify", headers=user.headers),
        api.post("/api/v1/anomaly/train", headers=user.headers, json={}),
        api.post(
            "/api/v1/analysis",
            headers=user.headers,
            json={
                "since": (now - timedelta(hours=1)).isoformat(),
                "until": now.isoformat(),
            },
        ),
        api.get("/api/v1/verification/runs", headers=user.headers),
        api.post("/api/v1/verification/audit-chain", headers=user.headers),
    ]

    assert [response.status_code for response in responses] == [403] * 5


# --- M6 audit-chain attacks --------------------------------------------------------------

@needs("M1", "M6")
def test_edited_audit_row_breaks_chain(api, db):
    admin = Actor(api, "admin", role="admin", db=db)
    Actor(api, "alice")

    response = api.get("/api/v1/audit/verify", headers=admin.headers)
    assert response.json()["valid"] is True

    victim = db.scalar(
        select(AuditLog)
        .where(AuditLog.event_type == "auth.register")
        .limit(1)
    )
    db.execute(
        update(AuditLog)
        .where(AuditLog.id == victim.id)
        .values(outcome="failure")
    )
    db.commit()

    response = api.get("/api/v1/audit/verify", headers=admin.headers)
    assert response.json()["valid"] is False
    assert response.json()["first_broken_id"] == victim.id


@needs("M1", "M6")
def test_deleted_audit_row_breaks_chain(api, db):
    admin = Actor(api, "admin", role="admin", db=db)
    Actor(api, "alice")

    ids = db.scalars(select(AuditLog.id).order_by(AuditLog.id)).all()
    db.execute(delete(AuditLog).where(AuditLog.id == ids[1]))
    db.commit()

    response = api.get("/api/v1/audit/verify", headers=admin.headers)
    assert response.json()["valid"] is False
    assert response.json()["first_broken_id"] == ids[2]


# --- M1 authentication attacks -----------------------------------------------------------

@needs("M1", "M6")
def test_jwt_alg_none_and_wrong_secret_rejected(api, db):
    admin = Actor(api, "admin", role="admin", db=db)
    real = admin.headers["Authorization"].split()[1]
    claims = jwt.decode(real, options={"verify_signature": False})

    forged_tokens = [
        jwt.encode(claims, key=None, algorithm="none"),
        jwt.encode(claims, "guessed-secret-" * 4, algorithm="HS256"),
        jwt.encode(
            claims
            | {
                "exp": int(
                    (datetime.now(UTC) - timedelta(minutes=5)).timestamp()
                )
            },
            get_settings().jwt_secret_key.get_secret_value(),
            algorithm="HS256",
        ),
        real[:-4] + ("AAAA" if not real.endswith("AAAA") else "BBBB"),
    ]

    for token in forged_tokens:
        response = api.get(
            "/api/v1/audit/verify",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 401

    assert api.get(
        "/api/v1/audit/verify",
        headers=admin.headers,
    ).status_code == 200


@needs("M1")
def test_sql_injection_strings_in_login_are_harmless(api, db):
    Actor(api, "alice")
    users_before = db.scalar(select(func.count()).select_from(User))

    malicious_emails = (
        "' OR '1'='1",
        "admin'--@example.com",
        "x@example.com' OR 1=1 --",
        "a@example.com'; DROP TABLE users;--",
    )

    for email in malicious_emails:
        response = api.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "' OR '1'='1"},
        )
        assert response.status_code in (401, 422), response.text

    assert db.scalar(select(func.count()).select_from(User)) == users_before
    assert api.get(
        "/api/v1/files/1%20OR%201=1",
        headers={},
    ).status_code in (401, 422)


@needs("M1", "M6")
def test_sql_injection_in_audit_filters(api, db):
    admin = Actor(api, "admin", role="admin", db=db)

    response = api.get(
        "/api/v1/audit/logs",
        headers=admin.headers,
        params={"event_type": "x' OR '1'='1"},
    )
    assert response.status_code == 200
    assert response.json()["total"] == 0


@needs("M1")
def test_bruteforce_login_triggers_lockout(api, db):
    alice = Actor(api, "alice")

    for _ in range(get_settings().max_failed_logins):
        response = api.post(
            "/api/v1/auth/login",
            json={"email": alice.email, "password": "guess guess 1"},
        )
        assert response.status_code == 401

    response = api.post(
        "/api/v1/auth/login",
        json={"email": alice.email, "password": PASSWORD},
    )
    assert response.status_code == 423


@needs("M1")
def test_refresh_token_reuse_revokes_every_session(api, db):
    alice = Actor(api, "alice")
    stolen = api.cookies.get("sfs_refresh")
    csrf = api.cookies.get("sfs_csrf")

    rotated = api.post(
        "/api/v1/auth/refresh",
        headers={"X-CSRF-Token": csrf},
    )
    assert rotated.status_code == 200

    fresh = {"Authorization": f"Bearer {rotated.json()['access_token']}"}

    thief = TestClient(api.app, base_url="https://testserver")
    thief.cookies.set("sfs_refresh", stolen)
    thief.cookies.set("sfs_csrf", "t")

    response = thief.post(
        "/api/v1/auth/refresh",
        headers={"X-CSRF-Token": "t"},
    )
    assert response.status_code == 401

    assert api.get("/api/v1/auth/me", headers=fresh).status_code == 401
    assert api.get("/api/v1/auth/me", headers=alice.headers).status_code == 401


@needs("M1")
def test_refresh_without_csrf_header_is_rejected(api):
    Actor(api, "alice")
    assert api.post("/api/v1/auth/refresh").status_code == 403


# --- Upload attacks ----------------------------------------------------------------------

@needs(*CORE)
def test_oversized_upload_returns_413(api, db, monkeypatch):
    alice = Actor(api, "alice")
    monkeypatch.setattr(get_settings(), "max_upload_bytes", 1024)

    response = api.post(
        "/api/v1/files",
        headers=alice.headers,
        files={
            "file": (
                "big.bin",
                b"\x00" * 1025,
                "application/octet-stream",
            )
        },
    )
    assert response.status_code == 413
    assert db.scalar(select(func.count()).select_from(File)) == 0


@needs(*CORE)
def test_path_traversal_filename_cannot_choose_the_storage_path(api, db):
    alice = Actor(api, "alice")
    file_id = upload(api, alice, name="../../../../etc/cron.d/evil")

    file = db.get(File, file_id)
    assert file.original_filename == "evil"
    assert file.storage_path == f"{file_id}.bin"
    assert blob_path(file_id).parent == get_settings().storage_dir.resolve()