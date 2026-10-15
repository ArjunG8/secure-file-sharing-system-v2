"""Authentication dependencies used by every router. Owner: M1."""

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.database import DbSession
from app.core.errors import AppError, NotImplementedFeature
from app.models import User
from app.modules.auth import MODULE_INFO

bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    db: DbSession,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> User:
    """Resolve the bearer token to an active User.

    TODO(M1): 401 if credentials are missing/invalid/expired, use
    auth.service.decode_access_token, load the user, reject inactive or locked users.
    """
    raise NotImplementedFeature(MODULE_INFO, "Bearer-token authentication")


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise AppError(403, "Administrator role required.")
    return user
