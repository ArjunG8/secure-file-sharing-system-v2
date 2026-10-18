"""M3 cryptographic primitives (pure functions, no database).

RSA:  3072-bit, e=65537. Wrapping = RSA-OAEP (MGF1-SHA256, SHA-256, no label).
ECC:  wrapping = ECIES: ephemeral X25519 -> HKDF-SHA256 -> AES-256-GCM, with the
      recipient key id as associated data. Signing keys are Ed25519 (used by M4).
Private keys at rest: PKCS#8 DER encrypted with AES-256-GCM under the master KEK, with
associated data binding the ciphertext to (user id, purpose, key id).
"""

import base64
import hashlib
import os
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.modules.keys.schemas import ED25519, RSA_OAEP, RSA_PSS, X25519_ECIES

RSA_BITS = 3072
_ECIES_INFO = b"sfs-file-key-wrap-v1"
_KEK_CONTEXT = b"sfs-user-key-v1"

PrivateKey = rsa.RSAPrivateKey | x25519.X25519PrivateKey | ed25519.Ed25519PrivateKey
PublicKey = rsa.RSAPublicKey | x25519.X25519PublicKey | ed25519.Ed25519PublicKey


class KeyCryptoError(Exception):
    """Wrapping/unwrapping or private-key decryption failed (wrong key or tampered data)."""


def generate_private_key(algorithm: str) -> PrivateKey:
    if algorithm in (RSA_OAEP, RSA_PSS):
        return rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)
    if algorithm == X25519_ECIES:
        return x25519.X25519PrivateKey.generate()
    if algorithm == ED25519:
        return ed25519.Ed25519PrivateKey.generate()
    raise ValueError(f"unsupported key algorithm {algorithm!r}")


def public_key_pem(private_key: PrivateKey) -> str:
    return private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def load_public_key(pem: str) -> PublicKey:
    return serialization.load_pem_public_key(pem.encode())


def fingerprint(public_pem: str) -> str:
    """SHA-256 (hex) of the DER SubjectPublicKeyInfo."""
    der = load_public_key(public_pem).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest()


# --- private keys at rest ----------------------------------------------------------------


def _kek(master_key_b64: str) -> AESGCM:
    return AESGCM(base64.b64decode(master_key_b64))


def _kek_aad(user_id: uuid.UUID, purpose: str, key_id: uuid.UUID) -> bytes:
    return _KEK_CONTEXT + user_id.bytes + purpose.encode() + key_id.bytes


def encrypt_private_key(
    private_key: PrivateKey, master_key_b64: str, user_id: uuid.UUID, purpose: str,
    key_id: uuid.UUID,
) -> tuple[bytes, bytes]:
    """Return (ciphertext, nonce). The DER plaintext never leaves this function."""
    der = private_key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    nonce = os.urandom(12)
    return _kek(master_key_b64).encrypt(nonce, der, _kek_aad(user_id, purpose, key_id)), nonce


def decrypt_private_key(
    ciphertext: bytes, nonce: bytes, master_key_b64: str, user_id: uuid.UUID, purpose: str,
    key_id: uuid.UUID,
) -> PrivateKey:
    try:
        der = _kek(master_key_b64).decrypt(nonce, ciphertext, _kek_aad(user_id, purpose, key_id))
    except InvalidTag as exc:
        raise KeyCryptoError("private key could not be decrypted") from exc
    return serialization.load_der_private_key(der, password=None)


# --- file-key wrapping -------------------------------------------------------------------


def _oaep() -> padding.OAEP:
    return padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(), label=None)


def _ecies_key(shared: bytes, ephemeral_pub: bytes, recipient_pub: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=_ECIES_INFO + ephemeral_pub + recipient_pub).derive(shared)


def _raw(public_key: x25519.X25519PublicKey) -> bytes:
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def wrap_file_key(algorithm: str, public_pem: str, file_key: bytes, key_id: uuid.UUID) -> bytes:
    public_key = load_public_key(public_pem)
    if algorithm == RSA_OAEP:
        return public_key.encrypt(file_key, _oaep())
    if algorithm == X25519_ECIES:
        ephemeral = x25519.X25519PrivateKey.generate()
        ephemeral_pub = _raw(ephemeral.public_key())
        key = _ecies_key(ephemeral.exchange(public_key), ephemeral_pub, _raw(public_key))
        nonce = os.urandom(12)
        return ephemeral_pub + nonce + AESGCM(key).encrypt(nonce, file_key, key_id.bytes)
    raise ValueError(f"{algorithm!r} is not an encryption key algorithm")


def unwrap_file_key(
    algorithm: str, private_key: PrivateKey, wrapped: bytes, key_id: uuid.UUID
) -> bytes:
    try:
        if algorithm == RSA_OAEP:
            return private_key.decrypt(wrapped, _oaep())
        if algorithm == X25519_ECIES:
            if len(wrapped) < 32 + 12 + 16:
                raise KeyCryptoError("wrapped key too short")
            ephemeral_pub, nonce, ciphertext = wrapped[:32], wrapped[32:44], wrapped[44:]
            shared = private_key.exchange(x25519.X25519PublicKey.from_public_bytes(ephemeral_pub))
            key = _ecies_key(shared, ephemeral_pub, _raw(private_key.public_key()))
            return AESGCM(key).decrypt(nonce, ciphertext, key_id.bytes)
    except (InvalidTag, ValueError) as exc:
        raise KeyCryptoError("file key could not be unwrapped") from exc
    raise KeyCryptoError(f"{algorithm!r} is not an encryption key algorithm")
