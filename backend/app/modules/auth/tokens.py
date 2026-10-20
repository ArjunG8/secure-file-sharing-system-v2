"""JWT access tokens (HS256) and opaque refresh/CSRF tokens."""

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt

from app.core.config import get_settings
from app.core.errors import AppError
from app.modules.auth import MODULE_INFO

ALGORITHM = "HS256"
ISSUER = "secure-file-sharing"
_UNAUTHENTICATED = {"WWW-Authenticate": "Bearer"}


@dataclass(frozen=True)
class AccessTokenClaims:
    user_id: uuid.UUID
    session_id: uuid.UUID
    expires_at: datetime


def create_access_token(user_id: uuid.UUID, session_id: uuid.UUID) -> tuple[str, int]:
    """Return (token, lifetime in seconds)."""
    settings = get_settings()
    lifetime = settings.jwt_access_token_minutes * 60
    now = datetime.now(UTC)
    claims = {
        "sub": str(user_id),
        "sid": str(session_id),
        "type": "access",
        "iss": ISSUER,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(seconds=lifetime),
        "jti": secrets.token_hex(16),
    }
    token = jwt.encode(claims, settings.jwt_secret_key.get_secret_value(), algorithm=ALGORITHM)
    return token, lifetime


def decode_access_token(token: str) -> AccessTokenClaims:
    """Validate signature, algorithm, expiry, issuer and claim types; 401 on any problem."""
    try:
        claims = jwt.decode(
            token,
            get_settings().jwt_secret_key.get_secret_value(),
            algorithms=[ALGORITHM],  # pins HS256: "alg=none" and algorithm swaps are rejected
            issuer=ISSUER,
            options={"require": ["exp", "iat", "sub", "sid", "type", "iss"]},
        )
        if claims["type"] != "access":
            raise jwt.InvalidTokenError("wrong token type")
        return AccessTokenClaims(
            user_id=uuid.UUID(claims["sub"]),
            session_id=uuid.UUID(claims["sid"]),
            expires_at=datetime.fromtimestamp(claims["exp"], UTC),
        )
    except (jwt.InvalidTokenError, ValueError, KeyError) as exc:
        raise AppError(
            401, "Invalid or expired access token.", module=MODULE_INFO.code,
            headers=_UNAUTHENTICATED,
        ) from exc


def new_opaque_token() -> str:
    return secrets.token_urlsafe(32)  # 256 bits


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
