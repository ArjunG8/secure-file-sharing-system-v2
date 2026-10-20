
"""Attack and negative tests. Owner: M9."""

import uuid
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.modules.keys.schemas import RSA_PSS
from app.modules.signatures import service


@pytest.fixture
def signing_setup(monkeypatch):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    key_record = SimpleNamespace(
        id=uuid.uuid4(),
        purpose="signing",
        algorithm=RSA_PSS,
        public_key_pem=private_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode(),
    )
    monkeypatch.setattr(service, "get_active_key", lambda *args: key_record)
    monkeypatch.setattr(service, "load_private_key", lambda *args: private_key)

    file = SimpleNamespace(
        id=uuid.uuid4(),
        owner_id=uuid.uuid4(),
        original_filename="test.txt",
        size_bytes=5,
        content_type="text/plain",
        plaintext_sha256="abc123",
        ciphertext_sha256="def456",
        nonce=b"012345678901",
        encryption_algorithm="AES-256-GCM",
        signature=None,
        signing_key_id=None,
        signature_algorithm=RSA_PSS,
    )

    class FakeDB:
        def get(self, model, key_id):
            return key_record if key_id == key_record.id else None

    return private_key, key_record, file, FakeDB()


def test_modified_manifest_fails_signature(signing_setup):
    _, key, file, db = signing_setup
    result = service.sign_manifest(db, file.owner_id, service.build_manifest(file))
    file.signature = result.signature
    file.signing_key_id = result.key_id
    file.plaintext_sha256 = "tampered"
    assert service.verify_manifest(db, file) is False


def test_signature_from_other_user_key_is_rejected(signing_setup):
    _, key, file, db = signing_setup
    manifest = service.build_manifest(file)
    other_private = rsa.generate_private_key(public_exponent=65537, key_size=3072)

    file.signature = other_private.sign(
        manifest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.DIGEST_LENGTH,
        ),
        hashes.SHA256(),
    )
    file.signing_key_id = key.id
    assert service.verify_manifest(db, file) is False


@pytest.mark.skip(reason="M2 AES-256-GCM attack test not implemented")
def test_tampered_ciphertext_byte_fails_gcm_tag(): ...


@pytest.mark.skip(reason="M2 AES-256-GCM attack test not implemented")
def test_ciphertext_moved_to_other_file_fails_aad_check(): ...


@pytest.mark.skip(reason="M2 AES-256-GCM attack test not implemented")
def test_modified_nonce_fails_decryption(): ...


@pytest.mark.skip(reason="M3 RSA-OAEP attack test not implemented")
def test_wrong_private_key_cannot_unwrap_file_key(): ...


@pytest.mark.skip(reason="M5 access-control attack test not implemented")
def test_idor_on_other_users_file_returns_404(): ...


@pytest.mark.skip(reason="M5 share-access attack test not implemented")
def test_expired_or_revoked_share_denies_download(): ...


@pytest.mark.skip(reason="M6 audit-chain attack test not implemented")
def test_edited_audit_row_breaks_chain(): ...


@pytest.mark.skip(reason="M6 audit-chain attack test not implemented")
def test_deleted_audit_row_breaks_chain(): ...


@pytest.mark.skip(reason="M1 JWT attack test not implemented")
def test_jwt_alg_none_and_wrong_secret_rejected(): ...


@pytest.mark.skip(reason="M1 login attack test not implemented")
def test_sql_injection_strings_in_login_are_harmless(): ...


@pytest.mark.skip(reason="M1 lockout attack test not implemented")
def test_bruteforce_login_triggers_lockout(): ...


@pytest.mark.skip(reason="M2 upload-limit attack test not implemented")
def test_oversized_upload_returns_413(): ...
