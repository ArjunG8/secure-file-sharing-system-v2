"""M3: key generation (RSA-3072 / X25519+Ed25519), KEK protection, wrapping, rotation."""

import os
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, x25519
from sqlalchemy import func, select

from app.core.config import get_settings
from app.core.errors import AppError
from app.models import AuditLog, UserKey
from app.modules.audit import service as audit_service
from app.modules.keys import crypto, service
from app.modules.keys.schemas import ED25519, RSA_OAEP, RSA_PSS, X25519_ECIES
from tests.helpers import fake_append_entries

EXPECTED = {"rsa": (RSA_OAEP, RSA_PSS), "ecc": (X25519_ECIES, ED25519)}


@pytest.fixture
def use_family(monkeypatch):
    def _use(family):
        monkeypatch.setattr(get_settings(), "default_key_algorithm", family)
    return _use


@pytest.fixture(params=["rsa", "ecc"])
def family(request, use_family):
    use_family(request.param)
    return request.param


def _keys(db, user_id):
    return db.scalars(select(UserKey).where(UserKey.user_id == user_id)).all()


def test_keys_are_created_on_first_use_with_the_family_algorithms(create_user, db, family):
    user = create_user()
    service.ensure_user_keys(db, user.id)
    keys = {k.purpose: k for k in _keys(db, user.id)}
    assert (keys["encryption"].algorithm, keys["signing"].algorithm) == EXPECTED[family]
    for key in keys.values():
        assert key.is_active and key.fingerprint == crypto.fingerprint(key.public_key_pem)
        assert "PRIVATE" not in key.public_key_pem
    service.ensure_user_keys(db, user.id)  # idempotent
    assert len(_keys(db, user.id)) == 2


def test_private_keys_are_stored_encrypted_under_the_master_key(create_user, db, family):
    user = create_user()
    key = service.get_active_key(db, user.id, "signing")
    private = service.load_private_key(db, key)
    der = private.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    assert der not in key.encrypted_private_key and len(key.private_key_nonce) == 12
    expected_type = rsa.RSAPrivateKey if family == "rsa" else ed25519.Ed25519PrivateKey
    assert isinstance(private, expected_type)


def test_wrap_and_unwrap_round_trip(create_user, db, family):
    user = create_user()
    file_key = os.urandom(32)
    wrapped = service.wrap_key_for_user(db, user.id, file_key)
    assert file_key not in wrapped.wrapped
    assert service.unwrap_key_for_user(db, user.id, wrapped.wrapped, wrapped.key_id) == file_key


def test_another_users_key_cannot_be_used(create_user, db, family):
    alice, mallory = create_user(), create_user()
    wrapped = service.wrap_key_for_user(db, alice.id, os.urandom(32))
    with pytest.raises(AppError) as err:
        service.unwrap_key_for_user(db, mallory.id, wrapped.wrapped, wrapped.key_id)
    assert err.value.status_code == 404


def test_tampered_wrapped_key_is_rejected(create_user, db, family):
    user = create_user()
    wrapped = service.wrap_key_for_user(db, user.id, os.urandom(32))
    tampered = bytearray(wrapped.wrapped)
    tampered[-1] ^= 0x01
    with pytest.raises(AppError) as err:
        service.unwrap_key_for_user(db, user.id, bytes(tampered), wrapped.key_id)
    assert err.value.status_code == 502


def test_signing_key_cannot_be_used_for_unwrapping(create_user, db, use_family):
    use_family("ecc")
    user = create_user()
    wrapped = service.wrap_key_for_user(db, user.id, os.urandom(32))
    signing = service.get_active_key(db, user.id, "signing")
    with pytest.raises(AppError) as err:
        service.unwrap_key_for_user(db, user.id, wrapped.wrapped, signing.id)
    assert err.value.status_code == 404


def test_ecies_ciphertext_is_bound_to_its_key_id():
    recipient = x25519.X25519PrivateKey.generate()
    pem = crypto.public_key_pem(recipient)
    key_id, other_id = uuid.uuid4(), uuid.uuid4()
    wrapped = crypto.wrap_file_key(X25519_ECIES, pem, b"k" * 32, key_id)
    assert crypto.unwrap_file_key(X25519_ECIES, recipient, wrapped, key_id) == b"k" * 32
    with pytest.raises(crypto.KeyCryptoError):
        crypto.unwrap_file_key(X25519_ECIES, recipient, wrapped, other_id)
    a = crypto.wrap_file_key(X25519_ECIES, pem, b"k" * 32, key_id)
    assert a != wrapped  # fresh ephemeral key and nonce every time


def test_encrypted_private_key_cannot_be_moved_to_another_user(create_user, db, use_family):
    use_family("ecc")
    alice, bob = create_user(), create_user()
    a_key = service.get_active_key(db, alice.id, "encryption")
    b_key = service.get_active_key(db, bob.id, "encryption")
    b_key.encrypted_private_key, b_key.private_key_nonce = (
        a_key.encrypted_private_key, a_key.private_key_nonce)
    with pytest.raises(AppError) as err:
        service.load_private_key(db, b_key)  # AAD binds it to (user, purpose, key id)
    assert err.value.status_code == 500


def test_wrong_master_key_fails_closed(create_user, db, use_family, monkeypatch):
    import base64

    from pydantic import SecretStr

    use_family("ecc")
    user = create_user()
    key = service.get_active_key(db, user.id, "encryption")
    monkeypatch.setattr(get_settings(), "master_key_encryption_key",
                        SecretStr(base64.b64encode(os.urandom(32)).decode()))
    with pytest.raises(AppError) as err:
        service.load_private_key(db, key)
    assert err.value.status_code == 500


def test_rotation_keeps_old_data_readable_and_one_key_active(create_user, db, use_family):
    use_family("rsa")
    user = create_user()
    file_key = os.urandom(32)
    old = service.wrap_key_for_user(db, user.id, file_key)
    new_key = service.rotate_keys(db, user.id, "encryption", "ecc")  # switch family too
    assert new_key.algorithm == X25519_ECIES
    active = db.scalar(select(func.count()).select_from(UserKey).where(
        UserKey.user_id == user.id, UserKey.purpose == "encryption", UserKey.is_active))
    assert active == 1
    assert service.unwrap_key_for_user(db, user.id, old.wrapped, old.key_id) == file_key
    fresh = service.wrap_key_for_user(db, user.id, file_key)
    assert fresh.key_id == new_key.id
    assert service.unwrap_key_for_user(db, user.id, fresh.wrapped, fresh.key_id) == file_key


def test_unknown_user_gets_404_not_new_keys(db):
    with pytest.raises(AppError) as err:
        service.get_active_key(db, uuid.uuid4(), "encryption")
    assert err.value.status_code == 404


def test_key_events_are_audited(create_user, db, use_family, monkeypatch):
    from app.core.database import session_scope

    use_family("ecc")
    monkeypatch.setattr(audit_service, "append_entries", fake_append_entries)
    user = create_user()
    with session_scope() as s:
        service.ensure_user_keys(s, user.id)
        service.rotate_keys(s, user.id, "signing")
    events = db.scalars(select(AuditLog.event_type).order_by(AuditLog.id)).all()
    assert events == ["key.generate", "key.generate", "key.generate", "key.rotate"]


# --- API ---------------------------------------------------------------------------------


def test_my_keys_endpoint_returns_public_material_only(client_as, create_user, use_family):
    use_family("ecc")
    user = create_user()
    r = client_as(user).get("/api/v1/keys/me")
    assert r.status_code == 200
    body = r.json()
    assert {k["purpose"] for k in body} == {"encryption", "signing"}
    assert "PRIVATE KEY" not in r.text and "encrypted_private_key" not in r.text


def test_other_users_public_keys_and_unknown_user(client_as, create_user, use_family):
    use_family("ecc")
    alice, bob = create_user(), create_user()
    r = client_as(alice).get(f"/api/v1/keys/users/{bob.id}/public")
    assert r.status_code == 200 and all(k["user_id"] == str(bob.id) for k in r.json())
    assert client_as(alice).get(f"/api/v1/keys/users/{uuid.uuid4()}/public").status_code == 404


def test_rotate_endpoint(client_as, create_user, use_family):
    use_family("ecc")
    user = create_user()
    client = client_as(user)
    first = {k["purpose"]: k for k in client.get("/api/v1/keys/me").json()}
    r = client.post("/api/v1/keys/rotate", json={"purpose": "signing", "algorithm": "rsa"})
    assert r.status_code == 200
    assert r.json()["algorithm"] == RSA_PSS and r.json()["id"] != first["signing"]["id"]
    bad = client.post("/api/v1/keys/rotate", json={"purpose": "signing", "algorithm": "dsa"})
    assert bad.status_code == 422
