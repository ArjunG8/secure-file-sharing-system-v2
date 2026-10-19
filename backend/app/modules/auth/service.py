"""M1 public interface. Implementation notes: docs/security-design.md, section M1."""

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import session_scope
from app.core.errors import AppError
from app.models import AuthSession, User
from app.modules.audit import service as audit_service
from app.modules.audit.schemas import AuditEventIn
from app.modules.auth import MODULE_INFO, tokens
from app.modules.auth import password as passwords
from app.modules.auth.schemas import RegisterRequest, TokenPair, TokenResponse

# Re-exported so other modules use one import (see docs/architecture.md section 4).
hash_password = passwords.hash_password
verify_password = passwords.verify_password
password_needs_rehash = passwords.password_needs_rehash
decode_access_token = tokens.decode_access_token

_INVALID_CREDENTIALS = "Invalid email or password."
_UNAUTHENTICATED = {"WWW-Authenticate": "Bearer"}


def _now() -> datetime:
    return datetime.now(UTC)


def as_utc(value: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes; every stored datetime is UTC."""
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=UTC)


def is_locked(user: User, now: datetime | None = None) -> bool:
    locked_until = as_utc(user.locked_until)
    return locked_until is not None and locked_until > (now or _now())


def _audit(db: Session, event_type: str, outcome: str = "success", **fields) -> None:
    audit_service.record_event(db, AuditEventIn(event_type=event_type, outcome=outcome, **fields))


def _check_password_policy(password: str, email: str, username: str) -> None:
    lowered = password.lower()
    local_part = email.split("@", 1)[0].lower()
    contains_identity = (
        lowered in (email.lower(), username.lower())
        or (len(local_part) >= 4 and local_part in lowered)
        or (len(username) >= 4 and username.lower() in lowered)
    )
    if contains_identity:
        raise AppError(
            422,
            "The password must not contain your email address or username.",
            module=MODULE_INFO.code,
        )


def _conflict() -> AppError:
    return AppError(
        409, "This email address or username is already registered.", module=MODULE_INFO.code
    )


# --- registration ------------------------------------------------------------------------


def register_user(db: Session, data: RegisterRequest) -> User:
    """Create a user. Key pairs are created by M3 on first use (keys.service)."""
    _check_password_policy(data.password, data.email, data.username)
    taken = db.scalar(
        select(User.id).where(
            or_(User.email == data.email, func.lower(User.username) == data.username.lower())
        )
    )
    if taken is not None:
        raise _conflict()
    user = User(
        email=data.email,
        username=data.username,
        password_hash=hash_password(data.password),
        role="user",
    )
    db.add(user)
    try:
        db.flush()
    except IntegrityError as exc:  # lost a race with a concurrent registration
        raise _conflict() from exc
    _audit(
        db, "auth.register", actor_user_id=user.id, resource_type="user", resource_id=str(user.id)
    )
    return user


# --- login -------------------------------------------------------------------------------


def _record_failed_attempt(user_id: uuid.UUID) -> bool:
    """Count a failed password in its OWN transaction (the request is about to roll back,
    which would otherwise undo the counter). Returns True if this attempt locked the account.
    """
    settings = get_settings()
    with session_scope() as s:
        count = s.execute(
            update(User)
            .where(User.id == user_id)
            .values(failed_login_count=User.failed_login_count + 1)
            .returning(User.failed_login_count)
        ).scalar_one()
        if count >= settings.max_failed_logins:
            s.execute(
                update(User)
                .where(User.id == user_id)
                .values(
                    failed_login_count=0,
                    locked_until=_now() + timedelta(minutes=settings.lockout_minutes),
                )
            )
            return True
    return False


def _new_session(
    db: Session, user_id: uuid.UUID, ip: str | None, user_agent: str | None
) -> tuple[AuthSession, str]:
    refresh_token = tokens.new_opaque_token()
    session = AuthSession(
        user_id=user_id,
        refresh_token_hash=tokens.hash_token(refresh_token),
        expires_at=_now() + timedelta(days=get_settings().refresh_token_days),
        ip_address=ip,
        user_agent=(user_agent or "")[:512] or None,
    )
    db.add(session)
    db.flush()
    return session, refresh_token


def _token_pair(user_id: uuid.UUID, session: AuthSession, refresh_token: str) -> TokenPair:
    access, lifetime = tokens.create_access_token(user_id, session.id)
    return TokenPair(
        access=TokenResponse(access_token=access, expires_in=lifetime),
        refresh_token=refresh_token,
        csrf_token=tokens.new_opaque_token(),
    )


def authenticate(
    db: Session, email: str, password: str, ip: str | None, user_agent: str | None
) -> TokenPair:
    """Check credentials, apply lockout, create an AuthSession and issue tokens.

    The same 401 message is used for an unknown email, a wrong password and an inactive
    account, and an unknown email still costs one Argon2id verification (no timing oracle).
    """
    now = _now()
    user = db.scalar(select(User).where(User.email == email))
    if user is None:
        verify_password(password, passwords.dummy_hash())
        _audit(db, "auth.login_failed", "failure", ip_address=ip,
               details={"reason": "invalid_credentials"})
        raise AppError(401, _INVALID_CREDENTIALS, module=MODULE_INFO.code)

    if is_locked(user, now):
        _audit(db, "auth.login_failed", "denied", actor_user_id=user.id, ip_address=ip,
               details={"reason": "account_locked"})
        raise AppError(
            423, "Too many failed attempts. The account is temporarily locked.",
            module=MODULE_INFO.code,
        )

    if not verify_password(password, user.password_hash):
        locked_now = _record_failed_attempt(user.id)
        _audit(db, "auth.login_failed", "failure", actor_user_id=user.id, ip_address=ip,
               details={"reason": "invalid_credentials"})
        if locked_now:
            _audit(db, "auth.locked", "denied", actor_user_id=user.id, ip_address=ip,
                   resource_type="user", resource_id=str(user.id))
        raise AppError(401, _INVALID_CREDENTIALS, module=MODULE_INFO.code)

    if not user.is_active:
        _audit(db, "auth.login_failed", "denied", actor_user_id=user.id, ip_address=ip,
               details={"reason": "inactive"})
        raise AppError(401, _INVALID_CREDENTIALS, module=MODULE_INFO.code)

    if password_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now
    session, refresh_token = _new_session(db, user.id, ip, user_agent)
    _audit(db, "auth.login", actor_user_id=user.id, ip_address=ip,
           resource_type="session", resource_id=str(session.id))
    return _token_pair(user.id, session, refresh_token)


# --- sessions ----------------------------------------------------------------------------


def _revoke_all_sessions_separately(user_id: uuid.UUID) -> None:
    with session_scope() as s:
        s.execute(
            update(AuthSession)
            .where(AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None))
            .values(revoked_at=_now())
        )


def refresh_session(
    db: Session, refresh_token: str, ip: str | None = None, user_agent: str | None = None
) -> TokenPair:
    """Rotate a refresh token. Re-use of an already rotated token revokes every session."""
    if not refresh_token:
        raise AppError(401, "Missing refresh token.", module=MODULE_INFO.code)
    session = db.scalar(
        select(AuthSession)
        .where(AuthSession.refresh_token_hash == tokens.hash_token(refresh_token))
        .with_for_update()
    )
    if session is None:
        raise AppError(401, "Invalid refresh token.", module=MODULE_INFO.code)
    if session.revoked_at is not None:
        # A rotated (or logged-out) token was presented again: assume it was stolen.
        _revoke_all_sessions_separately(session.user_id)
        _audit(db, "auth.refresh_reuse", "denied", actor_user_id=session.user_id,
               ip_address=ip, resource_type="session", resource_id=str(session.id))
        raise AppError(401, "Invalid refresh token.", module=MODULE_INFO.code)
    now = _now()
    user = db.get(User, session.user_id)
    if as_utc(session.expires_at) <= now or user is None or not user.is_active:
        raise AppError(401, "Refresh token expired.", module=MODULE_INFO.code)

    session.revoked_at = now
    new_session, new_token = _new_session(db, user.id, ip, user_agent)
    _audit(db, "auth.refresh", actor_user_id=user.id, ip_address=ip,
           resource_type="session", resource_id=str(new_session.id))
    return _token_pair(user.id, new_session, new_token)


def revoke_session(db: Session, user_id: uuid.UUID, session_id: uuid.UUID | None) -> None:
    """Logout: revoke the session the access token belongs to."""
    if session_id is not None:
        db.execute(
            update(AuthSession)
            .where(
                AuthSession.id == session_id,
                AuthSession.user_id == user_id,
                AuthSession.revoked_at.is_(None),
            )
            .values(revoked_at=_now())
        )
    _audit(db, "auth.logout", actor_user_id=user_id, resource_type="session",
           resource_id=str(session_id) if session_id else None)


def change_password(db: Session, user: User, current_password: str, new_password: str) -> None:
    """Verify the current password, store a new Argon2id hash, end every session."""
    if not verify_password(current_password, user.password_hash):
        _audit(db, "auth.password_change", "failure", actor_user_id=user.id,
               details={"reason": "wrong_current_password"})
        raise AppError(403, "The current password is incorrect.", module=MODULE_INFO.code)
    if current_password == new_password:
        raise AppError(
            422, "The new password must differ from the current one.", module=MODULE_INFO.code
        )
    _check_password_policy(new_password, user.email, user.username)
    db_user = db.get(User, user.id)
    db_user.password_hash = hash_password(new_password)
    db.execute(
        update(AuthSession)
        .where(AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None))
        .values(revoked_at=_now())
    )
    _audit(db, "auth.password_change", actor_user_id=user.id, resource_type="user",
           resource_id=str(user.id))


def resolve_access_token(db: Session, token: str) -> tuple[User, AuthSession]:
    """Validate an access token AND its server-side session (so logout takes effect)."""
    claims = decode_access_token(token)
    session = db.get(AuthSession, claims.session_id)
    if (
        session is None
        or session.user_id != claims.user_id
        or session.revoked_at is not None
        or as_utc(session.expires_at) <= _now()
    ):
        raise AppError(
            401, "Session ended. Please sign in again.", module=MODULE_INFO.code,
            headers=_UNAUTHENTICATED,
        )
    user = db.get(User, claims.user_id)
    if user is None or not user.is_active:
        raise AppError(
            401, "Account unavailable.", module=MODULE_INFO.code, headers=_UNAUTHENTICATED
        )
    return user, session
