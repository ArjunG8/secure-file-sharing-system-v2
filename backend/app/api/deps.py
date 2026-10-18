"""Authentication dependencies used by every router. Owner: M1."""

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.database import DbSession
from app.core.errors import AppError
from app.models import User
from app.modules.auth import MODULE_INFO
from app.modules.auth import service as auth_service

bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    db: DbSession,
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> User:
    """Resolve the bearer token to an active User, or 401.

    Checks the JWT (signature, HS256 only, expiry, issuer, type) and that its session
    has not been revoked (logout, password change, refresh-token reuse).
    The session id is kept on request.state for logout.
    """
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise AppError(
            401, "Not authenticated.", module=MODULE_INFO.code,
            headers={"WWW-Authenticate": "Bearer"},
        )
    user, session = auth_service.resolve_access_token(db, credentials.credentials)
    request.state.auth_session_id = session.id
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise AppError(403, "Administrator role required.")
    return user
