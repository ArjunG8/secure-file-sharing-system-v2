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
        public_key_pem=private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode(),
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


def test_rsa_pss_sign_and_verify(signing_setup):
    _, key, file, db = signing_setup
    result = service.sign_manifest(db, file.owner_id, service.build_manifest(file))
    file.signature = result.signature
    file.signing_key_id = result.key_id
    assert result.algorithm == RSA_PSS
    assert service.verify_manifest(db, file) is True


def test_modified_manifest_fails_verification(signing_setup):
    _, key, file, db = signing_setup
    result = service.sign_manifest(db, file.owner_id, service.build_manifest(file))
    file.signature = result.signature
    file.signing_key_id = result.key_id
    file.plaintext_sha256 = "tampered"
    assert service.verify_manifest(db, file) is False


def test_missing_signature_fails(signing_setup):
    _, _, file, db = signing_setup
    assert service.verify_manifest(db, file) is False


def test_invalid_signature_fails(signing_setup):
    _, key, file, db = signing_setup
    file.signature = b"not a valid signature"
    file.signing_key_id = key.id
    assert service.verify_manifest(db, file) is False


def test_signature_from_another_key_fails(signing_setup):
    _, key, file, db = signing_setup
    result = service.sign_manifest(db, file.owner_id, service.build_manifest(file))
    other_private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    file.signature = result.signature
    file.signing_key_id = key.id
    wrong_key = SimpleNamespace(
        id=key.id,
        purpose="signing",
        algorithm=RSA_PSS,
        public_key_pem=other_private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode(),
    )
    db.get = lambda model, key_id: wrong_key
    assert service.verify_manifest(db, file) is False
