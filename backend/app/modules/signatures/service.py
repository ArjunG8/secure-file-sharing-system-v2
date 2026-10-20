
"""M4: RSA-PSS digital signatures over canonical file manifests."""
from cryptography.hazmat.primitives.asymmetric import rsa
from app.modules.keys.schemas import RSA_PSS
import base64
import json
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from sqlalchemy.orm import Session

from app.models import File, UserKey
from app.modules.keys.service import get_active_key, load_private_key
from app.modules.signatures.schemas import SignatureResult

ALGORITHM = "RSA-PSS-3072-SHA256"


def build_manifest(file: File) -> bytes:
    """Build canonical JSON bytes for the file's signed metadata."""

    manifest = {
        "v": 1,
        "file_id": str(file.id),
        "owner_id": str(file.owner_id),
        "original_filename": file.original_filename,
        "size_bytes": file.size_bytes,
        "content_type": file.content_type,
        "plaintext_sha256": file.plaintext_sha256,
        "ciphertext_sha256": file.ciphertext_sha256,
        "nonce_b64": base64.b64encode(file.nonce).decode("ascii"),
        "encryption_algorithm": file.encryption_algorithm,
    }

    return json.dumps(
        manifest,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sign_manifest(
    db: Session,
    user_id: uuid.UUID,
    manifest: bytes,
) -> SignatureResult:
    """Sign manifest bytes using the user's active RSA signing key."""

    key_record = get_active_key(db, user_id, "signing")
    private_key = load_private_key(db, key_record)

    signature = private_key.sign(
        manifest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.DIGEST_LENGTH,
        ),
        hashes.SHA256(),
    )

    return SignatureResult(
        signature=signature,
        key_id=key_record.id,
        algorithm=ALGORITHM,
    )


def verify_manifest(db: Session, file: File) -> bool:
    """Verify the signature using the exact key recorded for the file."""

    if not file.signature or not file.signing_key_id:
        return False

    key_record = db.get(UserKey, file.signing_key_id)

    if key_record is None or key_record.purpose != "signing":
        return False

    try:
        public_key = serialization.load_pem_public_key(
            key_record.public_key_pem.encode("utf-8")
        )

        public_key.verify(
            file.signature,
            build_manifest(file),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.DIGEST_LENGTH,
            ),
            hashes.SHA256(),
        )

        return True

    except (InvalidSignature, ValueError, TypeError):
        return False
