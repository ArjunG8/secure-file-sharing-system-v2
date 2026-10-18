"""Argon2id password hashing (argon2-cffi). Parameters come from settings."""

from functools import lru_cache

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.core.config import get_settings


@lru_cache
def _hasher() -> PasswordHasher:
    s = get_settings()
    return PasswordHasher(
        time_cost=s.argon2_time_cost,
        memory_cost=s.argon2_memory_cost_kib,
        parallelism=s.argon2_parallelism,
        hash_len=32,
        salt_len=16,
        type=Type.ID,
    )


def hash_password(password: str) -> str:
    """Return a PHC string: $argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>."""
    return _hasher().hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Constant-time check. Any malformed or non-Argon2 hash simply fails."""
    try:
        return _hasher().verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    try:
        return _hasher().check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


@lru_cache
def dummy_hash() -> str:
    """A real Argon2id hash used to spend the same time when an account doesn't exist."""
    return hash_password("dummy-password-for-timing-equalization")
