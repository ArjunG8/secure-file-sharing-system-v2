"""M4: canonical manifests, RSA-PSS / Ed25519 signing and verification, integrity checks.

The first tests use an in-memory RSA key record (no database). The rest use no test
doubles: signing keys come from the real M3 key store (created on first use, private
keys decrypted with the master key), uploads go through real M2, access checks through
real M5, and audit events are appended to the real M6 hash chain.
"""

import base64
import json
import os
import uuid
from types import SimpleNamespace

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pydantic import SecretStr
from sqlalchemy import select

from app.core.config import get_settings
from app.core.errors import AppError
from app.models import AuditLog, File, UserKey
from app.modules.audit import service as audit_service
from app.modules.encryption import storage
from app.modules.keys import service as keys_service
from app.modules.keys.schemas import RSA_PSS
from app.modules.signatures import service
from app.modules.signatures import service as sig

DATA = b"Quarterly results: draft, do not distribute.\n" * 100


# --- unit tests with an in-memory key record ---------------------------------------------


@pytest.fixture
def signing_setup(monkeypatch):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )

    file_owner_id = uuid.uuid4()
    # A signing key row as M3 stores it: owned by the file's owner, so verification
    # gets past the ownership check and the cryptographic check decides.
    key_record = SimpleNamespace(
        id=uuid.uuid4(),
        user_id=file_owner_id,
        purpose="signing",
        algorithm=RSA_PSS,
        public_key_pem=private_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode(),
    )

    monkeypatch.setattr(
        service.keys_service,
        "get_active_key",
        lambda *args: key_record,
    )
    monkeypatch.setattr(
        service.keys_service,
        "load_private_key",
        lambda *args: private_key,
    )

    file = SimpleNamespace(
        id=uuid.uuid4(),
        owner_id=file_owner_id,
        original_filename="test.txt",
        size_bytes=5,
        content_type="text/plain",
        plaintext_sha256="abc123",
        ciphertext_sha256="def456",
        nonce=b"012345678901",
        encryption_algorithm="AES-256-GCM",
        signature=None,
        signing_key_id=None,
        signature_algorithm=service.RSA_PSS_SHA256,
    )

    class FakeDB:
        def get(self, model, key_id):
            return key_record if key_id == key_record.id else None

    return private_key, key_record, file, FakeDB()


def test_rsa_pss_sign_and_verify(signing_setup):
    _, key, file, db = signing_setup

    manifest = service.build_manifest(file)
    result = service.sign_manifest(db, file.owner_id, manifest)

    assert result.signature
    assert result.key_id == key.id
    assert result.algorithm == service.RSA_PSS_SHA256

    assert service.verify_signature(
        result.algorithm,
        key.public_key_pem,
        result.signature,
        manifest,
    )


def test_modified_manifest_fails_verification(signing_setup):
    _, key, file, db = signing_setup

    result = service.sign_manifest(
        db,
        file.owner_id,
        service.build_manifest(file),
    )

    file.signature = result.signature
    file.signing_key_id = result.key_id

    original_manifest = service.build_manifest(file)
    file.original_filename = "modified.txt"
    modified_manifest = service.build_manifest(file)

    assert original_manifest != modified_manifest
    assert not service.verify_signature(
        result.algorithm,
        key.public_key_pem,
        result.signature,
        modified_manifest,
    )
    assert service.verify_manifest(db, file) is False
    assert service.explain_verification(db, file) == (
        "signature does not match the file manifest"
    )


def test_missing_signature_fails(signing_setup):
    _, _, file, db = signing_setup

    assert service.verify_manifest(db, file) is False
    assert service.explain_verification(db, file) == "file has no signature"


def test_invalid_signature_fails(signing_setup):
    _, key, file, _ = signing_setup

    manifest = service.build_manifest(file)
    invalid_signature = b"\x00" * 384

    assert service.verify_signature(
        service.RSA_PSS_SHA256,
        key.public_key_pem,
        invalid_signature,
        manifest,
    ) is False


def test_signature_from_another_key_fails(signing_setup):
    _, key, file, db = signing_setup

    other_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )

    manifest = service.build_manifest(file)
    forged_signature = other_private_key.sign(
        manifest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.DIGEST_LENGTH,
        ),
        hashes.SHA256(),
    )

    file.signature = forged_signature
    file.signing_key_id = key.id

    # The key record is the owner's, so only the cryptographic check can reject this.
    assert service.verify_manifest(db, file) is False
    assert service.explain_verification(db, file) == (
        "signature does not match the file manifest"
    )


# --- real M3 keys, M2 files, M5 access, M6 audit ---------------------------------------


@pytest.fixture(params=["rsa", "ecc"])
def family(request, monkeypatch):
    monkeypatch.setattr(get_settings(), "default_key_algorithm", request.param)
    return request.param


@pytest.fixture
def rsa_keys(monkeypatch):
    monkeypatch.setattr(get_settings(), "default_key_algorithm", "rsa")


@pytest.fixture
def ecc_keys(monkeypatch):
    monkeypatch.setattr(get_settings(), "default_key_algorithm", "ecc")


def make_file(db, owner, **overrides):
    fields = {
        "owner_id": owner.id, "original_filename": "report.pdf",
        "content_type": "application/pdf", "size_bytes": 48, "storage_path": "x.bin",
        "encryption_algorithm": "AES-256-GCM", "nonce": os.urandom(12),
        "plaintext_sha256": "a" * 64, "ciphertext_sha256": "b" * 64,
    }
    file = File(**(fields | overrides))
    db.add(file)
    db.commit()
    return file


def signed_file(db, owner, **overrides):
    file = make_file(db, owner, **overrides)
    result = sig.sign_manifest(db, owner.id, sig.build_manifest(file))
    file.signature, file.signature_algorithm, file.signing_key_id = (
        result.signature, result.algorithm, result.key_id)
    db.commit()
    return file


def public_key_of(db, file):
    key = db.get(UserKey, file.signing_key_id)
    return serialization.load_pem_public_key(key.public_key_pem.encode())


# --- manifest ----------------------------------------------------------------------------


def test_manifest_is_canonical_json_of_the_documented_fields(create_user, db):
    owner = create_user()
    file = make_file(db, owner, id=uuid.UUID("00000000-0000-4000-8000-000000000001"),
                     nonce=bytes(range(12)), original_filename="Q3 report.pdf")
    expected = (
        '{"ciphertext_sha256":"' + "b" * 64 + '","content_type":"application/pdf",'
        '"encryption_algorithm":"AES-256-GCM","file_id":"00000000-0000-4000-8000-000000000001",'
        '"nonce_b64":"AAECAwQFBgcICQoL","original_filename":"Q3 report.pdf",'
        f'"owner_id":"{owner.id}","plaintext_sha256":"' + "a" * 64 + '","size_bytes":48,"v":1}'
    ).encode()
    assert sig.build_manifest(file) == expected


def test_manifest_is_deterministic_across_loads(create_user, db):
    file = make_file(db, create_user(), original_filename="Ünïcødé – résumé.pdf")
    first = sig.build_manifest(file)
    db.expire_all()
    again = sig.build_manifest(db.get(File, file.id))
    assert first == again
    assert first.isascii()  # non-ASCII is \u-escaped, so the bytes never depend on encoding
    parsed = json.loads(first)
    assert parsed["original_filename"] == "Ünïcødé – résumé.pdf"
    assert first == json.dumps(parsed, sort_keys=True, separators=(",", ":")).encode()


# --- sign / verify (real M3 keys) --------------------------------------------------------


def test_sign_and_verify_with_real_m3_keys(family, create_user, db):
    owner = create_user()
    file = signed_file(db, owner)
    key = keys_service.get_active_key(db, owner.id, "signing")
    assert file.signing_key_id == key.id and key.user_id == owner.id
    assert file.signature_algorithm == ("RSA-PSS-SHA256" if family == "rsa" else "Ed25519")
    assert sig.verify_manifest(db, file)
    assert sig.explain_verification(db, file) is None


def test_rsa_signature_uses_pss_mgf1_sha256_with_digest_length_salt(rsa_keys, create_user, db):
    file = signed_file(db, create_user())
    public_key = public_key_of(db, file)
    assert public_key.key_size == 3072 and len(file.signature) == 384
    manifest = sig.build_manifest(file)

    def pss(salt):
        return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=salt)

    # Independent check with the cryptography library: salt is exactly 32 bytes (SHA-256).
    public_key.verify(file.signature, manifest, pss(32), hashes.SHA256())
    with pytest.raises(InvalidSignature):
        public_key.verify(file.signature, manifest, pss(0), hashes.SHA256())


def test_rsa_pss_is_randomized_but_both_signatures_verify(rsa_keys, create_user, db):
    owner = create_user()
    file = signed_file(db, owner)
    again = sig.sign_manifest(db, owner.id, sig.build_manifest(file))
    assert again.signature != file.signature  # fresh random salt per signature
    file.signature = again.signature
    db.commit()
    assert sig.verify_manifest(db, file)


@pytest.mark.parametrize(("field", "value"), [
    ("original_filename", "invoice.pdf"), ("size_bytes", 49), ("content_type", "text/html"),
    ("plaintext_sha256", "0" * 64), ("ciphertext_sha256", "f" * 64), ("nonce", b"\x00" * 12),
    ("encryption_algorithm", "AES-128-GCM"),
])
def test_any_signed_field_change_invalidates_the_signature(field, value, family, create_user,
                                                           db):
    file = signed_file(db, create_user())
    setattr(file, field, value)
    db.commit()
    assert not sig.verify_manifest(db, file)
    assert sig.explain_verification(db, file) == "signature does not match the file manifest"


def test_owner_change_is_detected(ecc_keys, create_user, db):
    owner, other = create_user(), create_user()
    file = signed_file(db, owner)
    file.owner_id = other.id
    db.commit()
    assert not sig.verify_manifest(db, file)


@pytest.mark.parametrize("corrupt", [
    lambda s: bytes([s[0] ^ 1]) + s[1:],
    lambda s: s[:-1],
    lambda s: s + b"\x00",
    lambda s: b"\x00" * len(s),
])
def test_corrupted_signature_is_rejected(corrupt, family, create_user, db):
    file = signed_file(db, create_user())
    file.signature = corrupt(file.signature)
    db.commit()
    assert sig.explain_verification(db, file) == "signature does not match the file manifest"


def test_missing_signature_is_rejected(ecc_keys, create_user, db):
    file = signed_file(db, create_user())
    for column in ("signature", "signature_algorithm", "signing_key_id"):
        saved = getattr(file, column)
        setattr(file, column, None)
        db.commit()
        assert sig.explain_verification(db, file) == "file has no signature"
        setattr(file, column, saved)
        db.commit()
    assert sig.verify_manifest(db, file)


def test_unknown_or_non_signing_key_is_rejected(ecc_keys, create_user, db):
    owner = create_user()
    file = signed_file(db, owner)
    encryption_key = keys_service.get_active_key(db, owner.id, "encryption")
    file.signing_key_id = encryption_key.id  # the owner's key, but not a signing key
    db.commit()
    assert sig.explain_verification(db, file) == "signing key not found"
    with db.no_autoflush:  # an unknown id would violate the foreign key if flushed
        file.signing_key_id = uuid.uuid4()
        assert sig.explain_verification(db, file) == "signing key not found"
    db.rollback()


def test_valid_signature_by_someone_else_is_not_accepted(ecc_keys, create_user, db):
    """Mallory re-signs Alice's tampered manifest with her OWN key: the signature is
    mathematically valid, but not by the owner."""
    alice, mallory = create_user(), create_user()
    file = signed_file(db, alice)
    file.original_filename = "malware.exe"
    forged = sig.sign_manifest(db, mallory.id, sig.build_manifest(file))
    file.signature, file.signing_key_id = forged.signature, forged.key_id
    db.commit()
    assert sig.explain_verification(db, file) == (
        "signed with a key that does not belong to the file owner")


def test_algorithm_confusion_is_rejected(family, create_user, db):
    file = signed_file(db, create_user())
    file.signature_algorithm = "Ed25519" if family == "rsa" else "RSA-PSS-SHA256"
    db.commit()
    assert sig.explain_verification(db, file) == (
        "signature algorithm does not match the signing key")


def test_label_written_by_earlier_m4_builds_still_verifies(rsa_keys, create_user, db):
    file = signed_file(db, create_user())
    file.signature_algorithm = "RSA-PSS-3072-SHA256"
    db.commit()
    assert sig.verify_manifest(db, file)


def test_old_signatures_still_verify_after_m3_key_rotation(rsa_keys, create_user, db):
    owner = create_user()
    old_file = signed_file(db, owner)
    keys_service.rotate_keys(db, owner.id, "signing", "ecc")  # RSA key -> inactive
    db.commit()
    new_file = signed_file(db, owner)
    assert old_file.signing_key_id != new_file.signing_key_id
    assert not db.get(UserKey, old_file.signing_key_id).is_active
    assert (old_file.signature_algorithm, new_file.signature_algorithm) == (
        "RSA-PSS-SHA256", "Ed25519")
    assert sig.verify_manifest(db, old_file) and sig.verify_manifest(db, new_file)


def test_signing_fails_closed_when_the_private_key_is_unavailable(ecc_keys, create_user, db,
                                                                  monkeypatch):
    owner = create_user()
    keys_service.get_active_key(db, owner.id, "signing")
    db.commit()
    other_master_key = SecretStr(base64.b64encode(os.urandom(32)).decode())
    monkeypatch.setattr(get_settings(), "master_key_encryption_key", other_master_key)
    with pytest.raises(AppError) as err:
        sig.sign_manifest(db, owner.id, b"manifest")
    assert err.value.status_code == 500


def test_unsupported_signing_key_fails_closed(ecc_keys, create_user, db):
    owner = create_user()
    key = keys_service.get_active_key(db, owner.id, "signing")
    key.algorithm = "DSA-1024"
    db.commit()
    with pytest.raises(AppError) as err:
        sig.sign_manifest(db, owner.id, b"manifest")
    assert err.value.status_code == 500


# --- API (real M2 upload, M5 access control, M6 audit chain) -----------------------------


def upload(client, data=DATA, name="results.txt"):
    r = client.post("/api/v1/files", files={"file": (name, data, "text/plain")})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def share(client, file_id, user):
    r = client.post("/api/v1/shares", json={"file_id": file_id, "recipient_email": user.email})
    assert r.status_code == 201, r.text


def people(create_user):
    return [create_user(email=f"{name}-{uuid.uuid4().hex[:6]}@example.com")
            for name in ("alice", "bob", "eve")]


def audit_rows(db, event_type):
    db.expire_all()
    return db.scalars(select(AuditLog).where(AuditLog.event_type == event_type)
                      .order_by(AuditLog.id)).all()


def test_upload_is_signed_and_signature_endpoint_returns_it(family, client_as, create_user, db):
    alice, *_ = people(create_user)
    file_id = upload(client_as(alice))
    body = client_as(alice).get(f"/api/v1/signatures/files/{file_id}").json()
    file = db.get(File, uuid.UUID(file_id))
    assert body["algorithm"] == file.signature_algorithm
    assert body["signer_id"] == str(alice.id)
    assert body["signing_key_id"] == str(file.signing_key_id)
    assert base64.b64decode(body["signature_b64"]) == file.signature
    assert json.dumps(body["manifest"], sort_keys=True, separators=(",", ":")).encode() == (
        sig.build_manifest(file))
    assert sig.verify_manifest(db, file)


def test_only_users_with_access_see_or_verify_signatures(ecc_keys, client_as, create_user, db):
    alice, bob, eve = people(create_user)
    file_id = upload(client_as(alice))
    paths = [("get", f"/api/v1/signatures/files/{file_id}"),
             ("post", f"/api/v1/signatures/files/{file_id}/verify")]
    missing = [("get", f"/api/v1/signatures/files/{uuid.uuid4()}"),
               ("post", f"/api/v1/signatures/files/{uuid.uuid4()}/verify")]

    # Not shared: the same 404 as for a file that does not exist, and the denial is audited.
    for method, path in paths + missing:
        r = client_as(bob).request(method.upper(), path)
        assert r.status_code == 404 and r.json()["error"]["code"] == "not_found"
    assert len(audit_rows(db, "share.access_denied")) == 4

    share(client_as(alice), file_id, bob)
    assert client_as(bob).get(paths[0][1]).status_code == 200
    assert client_as(bob).post(paths[1][1]).json()["valid"] is True
    assert client_as(eve).get(paths[0][1]).status_code == 404

    assert client_as(alice).delete(f"/api/v1/files/{file_id}").status_code == 204
    for method, path in paths:
        assert client_as(alice).request(method.upper(), path).status_code == 404


def test_signature_endpoints_require_authentication(client):
    for method, path in [("get", f"/api/v1/signatures/files/{uuid.uuid4()}"),
                         ("post", f"/api/v1/signatures/files/{uuid.uuid4()}/verify")]:
        r = client.request(method.upper(), path)
        assert r.status_code == 401


def test_verify_endpoint_separates_authorship_from_integrity(family, client_as, create_user,
                                                             db):
    alice, *_ = people(create_user)
    c = client_as(alice)
    file_id = upload(c)
    file = db.get(File, uuid.UUID(file_id))
    path = storage.resolve(file.storage_path)

    ok = c.post(f"/api/v1/signatures/files/{file_id}/verify").json()
    assert ok == ok | {"valid": True, "signature_valid": True, "ciphertext_intact": True,
                       "reason": None}

    blob = path.read_bytes()
    path.write_bytes(blob[:-1] + bytes([blob[-1] ^ 1]))  # ciphertext tampered on disk
    bad = c.post(f"/api/v1/signatures/files/{file_id}/verify").json()
    assert bad["signature_valid"] is True and bad["ciphertext_intact"] is False
    assert bad["valid"] is False and "ciphertext" in bad["reason"]

    path.unlink()  # blob gone
    gone = c.post(f"/api/v1/signatures/files/{file_id}/verify").json()
    assert gone["valid"] is False and gone["ciphertext_intact"] is False

    outcomes = [row.outcome for row in audit_rows(db, "file.signature_verify")]
    assert outcomes == ["success", "failure", "failure"]
    assert audit_service.verify_chain(db).valid


def test_tampered_metadata_fails_verification_and_blocks_download(family, client_as,
                                                                  create_user, db):
    alice, bob, _ = people(create_user)
    file_id = upload(client_as(alice))
    share(client_as(alice), file_id, bob)
    assert client_as(bob).get(f"/api/v1/files/{file_id}/download").content == DATA

    file = db.get(File, uuid.UUID(file_id))
    file.original_filename = "invoice-PAID.txt"  # metadata edited directly in the database
    db.commit()

    result = client_as(bob).post(f"/api/v1/signatures/files/{file_id}/verify").json()
    assert result["valid"] is False and result["signature_valid"] is False
    assert result["ciphertext_intact"] is True
    assert result["reason"] == "signature does not match the file manifest"

    r = client_as(bob).get(f"/api/v1/files/{file_id}/download")
    assert r.status_code == 502 and DATA[:20] not in r.content
    assert r.json()["error"]["details"] == {"check": "signature"}
    assert [e.outcome for e in audit_rows(db, "file.integrity_failure")] == ["failure"]

    report = client_as(bob).post(f"/api/v1/verification/files/{file_id}").json()
    checks = {c["name"]: c["passed"] for c in report["checks"]}
    assert report["passed"] is False and checks["signature"] is False
    assert checks["gcm_tag"] is True  # content itself untouched: only the metadata lied


def test_files_remain_verifiable_after_owner_rotates_signing_key(rsa_keys, client_as,
                                                                 create_user, db):
    alice, *_ = people(create_user)
    c = client_as(alice)
    old_id = upload(c)
    r = c.post("/api/v1/keys/rotate", json={"purpose": "signing", "algorithm": "ecc"})
    assert r.status_code in (200, 201), r.text
    new_id = upload(c)
    old = c.get(f"/api/v1/signatures/files/{old_id}").json()
    new = c.get(f"/api/v1/signatures/files/{new_id}").json()
    assert (old["algorithm"], new["algorithm"]) == ("RSA-PSS-SHA256", "Ed25519")
    for file_id in (old_id, new_id):
        assert c.post(f"/api/v1/signatures/files/{file_id}/verify").json()["valid"] is True
        assert c.get(f"/api/v1/files/{file_id}/download").content == DATA
