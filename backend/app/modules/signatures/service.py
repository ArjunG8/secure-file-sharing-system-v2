"""M4: RSA-PSS digital signatures over canonical file manifests.

A signature proves WHO vouched for a file's metadata (authorship); hashes alone only show
that bytes are unchanged. Verification checks that a signature exists, the signing key
belongs to the file owner and is a signing key, the algorithm matches, and the
cryptographic signature is valid.

Implementation notes: docs/security-design.md, section M4.
"""

import base64
import json
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from sqlalchemy.orm import Session

from app.core.errors import AppError
from app.models import File, UserKey
from app.modules.keys import service as keys_service
from app.modules.keys.schemas import ED25519 as ED25519_KEY
from app.modules.keys.schemas import RSA_PSS as RSA_PSS_KEY
from app.modules.signatures import MODULE_INFO
from app.modules.signatures.schemas import SignatureResult

MANIFEST_VERSION = 1
RSA_PSS_SHA256 = "RSA-PSS-SHA256"
ED25519 = "Ed25519"
# M3 key label -> signature algorithm stored in files.signature_algorithm.
KEY_TO_SIGNATURE = {RSA_PSS_KEY: RSA_PSS_SHA256, ED25519_KEY: ED25519}
# Labels written by earlier builds of this module, read as their current equivalent.
_LEGACY_LABELS = {RSA_PSS_KEY: RSA_PSS_SHA256}


def _pss() -> padding.PSS:
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)


def manifest_dict(file: File) -> dict:
    """Every field that defines the file's identity and content (see security-design.md)."""
    return {
        "v": MANIFEST_VERSION,
        "file_id": str(file.id),
        "owner_id": str(file.owner_id),
        "original_filename": file.original_filename,
        "content_type": file.content_type,
        "size_bytes": file.size_bytes,
        "plaintext_sha256": file.plaintext_sha256,
        "ciphertext_sha256": file.ciphertext_sha256,
        "nonce_b64": base64.b64encode(file.nonce).decode("ascii"),
        "encryption_algorithm": file.encryption_algorithm,
    }


def build_manifest(file: File) -> bytes:
    """Canonical JSON bytes (sorted keys, no whitespace, ASCII) of manifest_dict(file)."""
    return json.dumps(manifest_dict(file), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def sign_manifest(db: Session, user_id: uuid.UUID, manifest: bytes) -> SignatureResult:
    """Sign with the user's active signing key: RSA-PSS (MGF1-SHA256, salt = digest
    length, SHA-256) for RSA keys, Ed25519 for ECC keys."""
    key = keys_service.get_active_key(db, user_id, "signing")
    algorithm = KEY_TO_SIGNATURE.get(key.algorithm)
    private_key = keys_service.load_private_key(db, key)
    if algorithm == RSA_PSS_SHA256 and isinstance(private_key, rsa.RSAPrivateKey):
        signature = private_key.sign(manifest, _pss(), hashes.SHA256())
    elif algorithm == ED25519 and isinstance(private_key, ed25519.Ed25519PrivateKey):
        signature = private_key.sign(manifest)
    else:
        raise AppError(500, "The signing key has an unsupported algorithm.",
                       module=MODULE_INFO.code)
    return SignatureResult(signature=signature, key_id=key.id, algorithm=algorithm)


def verify_signature(algorithm: str, public_pem: str, signature: bytes, message: bytes) -> bool:
    try:
        public_key = serialization.load_pem_public_key(public_pem.encode("ascii"))
        if algorithm == RSA_PSS_SHA256 and isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, message, _pss(), hashes.SHA256())
            return True
        if algorithm == ED25519 and isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, message)
            return True
    except (InvalidSignature, ValueError, TypeError):
        return False
    return False  # algorithm / key type mismatch


def explain_verification(db: Session, file: File) -> str | None:
    """None if the signature is valid, otherwise a short reason."""
    if not file.signature or not file.signature_algorithm or file.signing_key_id is None:
        return "file has no signature"
    key = db.get(UserKey, file.signing_key_id)  # rotated-out keys still verify
    if key is None or key.purpose != "signing":
        return "signing key not found"
    if key.user_id != file.owner_id:
        return "signed with a key that does not belong to the file owner"
    algorithm = _LEGACY_LABELS.get(file.signature_algorithm, file.signature_algorithm)
    if KEY_TO_SIGNATURE.get(key.algorithm) != algorithm:
        return "signature algorithm does not match the signing key"
    if not verify_signature(algorithm, key.public_key_pem, file.signature,
                            build_manifest(file)):
        return "signature does not match the file manifest"
    return None


def verify_manifest(db: Session, file: File) -> bool:
    """Verify files.signature over build_manifest(file) using files.signing_key_id."""
    return explain_verification(db, file) is None
