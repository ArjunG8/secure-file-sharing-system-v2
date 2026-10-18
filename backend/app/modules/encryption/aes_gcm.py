"""AES-256-GCM primitives (cryptography's AESGCM). Pure functions, no I/O."""

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.modules.encryption.schemas import EncryptedPayload

KEY_BYTES = 32  # AES-256
NONCE_BYTES = 12  # 96-bit nonce, the GCM standard size
TAG_BYTES = 16


class DecryptionError(Exception):
    """GCM authentication failed: wrong key, nonce or AAD, or the ciphertext was modified."""


def encrypt(plaintext: bytes, aad: bytes) -> EncryptedPayload:
    """Encrypt under a FRESH random key and nonce, so a (key, nonce) pair is never reused."""
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(NONCE_BYTES)
    return EncryptedPayload(ciphertext=AESGCM(key).encrypt(nonce, plaintext, aad), nonce=nonce,
                            key=key)


def decrypt(ciphertext: bytes, nonce: bytes, key: bytes, aad: bytes) -> bytes:
    if len(key) != KEY_BYTES or len(nonce) != NONCE_BYTES or len(ciphertext) < TAG_BYTES:
        raise DecryptionError("malformed key, nonce or ciphertext")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise DecryptionError("authentication tag mismatch") from exc
