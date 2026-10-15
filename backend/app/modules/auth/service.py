"""M1 public interface. Other modules may import these functions.

Implementation notes: docs/security-design.md, section M1.
"""

import uuid

from sqlalchemy.orm import Session

from app.core.errors import NotImplementedFeature
from app.models import User
from app.modules.auth import MODULE_INFO
from app.modules.auth.schemas import RegisterRequest, TokenPair


def hash_password(password: str) -> str:
    """Return an Argon2id PHC string for `password`."""
    raise NotImplementedFeature(MODULE_INFO, "Argon2id password hashing")


def verify_password(password: str, password_hash: str) -> bool:
    """Constant-time verification of `password` against an Argon2id PHC string."""
    raise NotImplementedFeature(MODULE_INFO, "Argon2id password verification")


def password_needs_rehash(password_hash: str) -> bool:
    """True if the stored hash uses weaker parameters than the current settings."""
    raise NotImplementedFeature(MODULE_INFO, "Argon2id rehash check")


def register_user(db: Session, data: RegisterRequest) -> User:
    """Create a user (and their key pairs via keys.service.ensure_user_keys)."""
    raise NotImplementedFeature(MODULE_INFO, "User registration")


def authenticate(
    db: Session, email: str, password: str, ip: str | None, user_agent: str | None
) -> TokenPair:
    """Check credentials, apply lockout, create an AuthSession and issue tokens."""
    raise NotImplementedFeature(MODULE_INFO, "Login")


def refresh_session(db: Session, refresh_token: str) -> TokenPair:
    """Rotate a refresh token and issue a new access token."""
    raise NotImplementedFeature(MODULE_INFO, "Token refresh")


def revoke_session(db: Session, user_id: uuid.UUID, refresh_token: str | None) -> None:
    raise NotImplementedFeature(MODULE_INFO, "Logout")


def change_password(db: Session, user: User, current_password: str, new_password: str) -> None:
    raise NotImplementedFeature(MODULE_INFO, "Password change")


def decode_access_token(token: str) -> uuid.UUID:
    """Validate a JWT access token and return the user id (`sub`)."""
    raise NotImplementedFeature(MODULE_INFO, "JWT access-token validation")
