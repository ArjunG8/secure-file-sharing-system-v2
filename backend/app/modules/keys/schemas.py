import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from pydantic import BaseModel

from app.schemas.common import ORMModel

KeyPurpose = Literal["encryption", "signing"]
KeyFamily = Literal["rsa", "ecc"]

# Algorithm labels stored in user_keys.algorithm. A key is always used with exactly the
# algorithm on its label, so RSA and ECC keys can coexist (e.g. across a rotation).
RSA_OAEP = "RSA-OAEP-3072-SHA256"
RSA_PSS = "RSA-PSS-3072-SHA256"
X25519_ECIES = "ECIES-X25519-HKDF-SHA256-AES256GCM"
ED25519 = "Ed25519"

ALGORITHMS: dict[tuple[KeyFamily, KeyPurpose], str] = {
    ("rsa", "encryption"): RSA_OAEP,
    ("rsa", "signing"): RSA_PSS,
    ("ecc", "encryption"): X25519_ECIES,
    ("ecc", "signing"): ED25519,
}


@dataclass(frozen=True)
class WrappedKey:
    """A file key encrypted for the public key `key_id` (RSA-OAEP or X25519 ECIES)."""

    wrapped: bytes
    key_id: uuid.UUID


class PublicKeyOut(ORMModel):
    """Private keys are never part of any response model."""

    id: uuid.UUID
    user_id: uuid.UUID
    purpose: KeyPurpose
    algorithm: str
    public_key_pem: str
    fingerprint: str
    is_active: bool
    created_at: datetime


class RotateKeyRequest(BaseModel):
    purpose: KeyPurpose
    # None keeps the current key's family; "rsa"/"ecc" switches it.
    algorithm: KeyFamily | None = None
