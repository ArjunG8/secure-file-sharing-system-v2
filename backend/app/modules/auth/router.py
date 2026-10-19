import hmac

from fastapi import APIRouter, Depends, Request, Response, status

from app.api.deps import get_current_user
from app.core.config import get_settings
from app.core.database import DbSession
from app.core.errors import AppError
from app.models import User
from app.modules.auth import MODULE_INFO, service
from app.modules.auth.rate_limit import limit_login, limit_refresh, limit_register
from app.modules.auth.schemas import (
    ChangePasswordRequest,
    LoginRequest,
    RegisterRequest,
    TokenPair,
    TokenResponse,
    UserOut,
)

router = APIRouter()

REFRESH_COOKIE = "sfs_refresh"
CSRF_COOKIE = "sfs_csrf"
CSRF_HEADER = "X-CSRF-Token"
_REFRESH_PATH = "/api/v1/auth"


def _client(request: Request) -> tuple[str | None, str | None]:
    return (request.client.host if request.client else None), request.headers.get("user-agent")


def _set_session_cookies(response: Response, pair: TokenPair) -> None:
    settings = get_settings()
    max_age = settings.refresh_token_days * 86400
    # Refresh token: never readable by JavaScript, only sent to the auth endpoints.
    response.set_cookie(
        REFRESH_COOKIE, pair.refresh_token, max_age=max_age, path=_REFRESH_PATH,
        httponly=True, secure=settings.auth_cookie_secure, samesite="strict",
    )
    # CSRF token (double-submit): readable by our JavaScript, echoed in X-CSRF-Token.
    response.set_cookie(
        CSRF_COOKIE, pair.csrf_token, max_age=max_age, path="/",
        httponly=False, secure=settings.auth_cookie_secure, samesite="strict",
    )


def _clear_session_cookies(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(REFRESH_COOKIE, path=_REFRESH_PATH, httponly=True,
                           secure=settings.auth_cookie_secure, samesite="strict")
    response.delete_cookie(CSRF_COOKIE, path="/", secure=settings.auth_cookie_secure,
                           samesite="strict")


def _require_csrf(request: Request) -> None:
    cookie = request.cookies.get(CSRF_COOKIE, "")
    header = request.headers.get(CSRF_HEADER, "")
    if not cookie or not header or not hmac.compare_digest(cookie, header):
        raise AppError(403, "Missing or invalid CSRF token.", module=MODULE_INFO.code)


@router.post(
    "/register",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(limit_register)],
)
def register(db: DbSession, data: RegisterRequest) -> UserOut:
    return UserOut.model_validate(service.register_user(db, data))


@router.post("/login", response_model=TokenResponse, dependencies=[Depends(limit_login)])
def login(db: DbSession, data: LoginRequest, request: Request, response: Response) -> TokenResponse:
    ip, user_agent = _client(request)
    pair = service.authenticate(db, data.email, data.password, ip, user_agent)
    _set_session_cookies(response, pair)
    return pair.access


@router.post("/refresh", response_model=TokenResponse, dependencies=[Depends(limit_refresh)])
def refresh(db: DbSession, request: Request, response: Response) -> TokenResponse:
    """Cookie-authenticated, so it requires the CSRF header (double-submit)."""
    _require_csrf(request)
    ip, user_agent = _client(request)
    pair = service.refresh_session(db, request.cookies.get(REFRESH_COOKIE, ""), ip, user_agent)
    _set_session_cookies(response, pair)
    return pair.access


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    db: DbSession,
    request: Request,
    response: Response,
    user: User = Depends(get_current_user),
) -> None:
    service.revoke_session(db, user.id, getattr(request.state, "auth_session_id", None))
    _clear_session_cookies(response)


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> UserOut:
    return UserOut.model_validate(user)


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    db: DbSession,
    data: ChangePasswordRequest,
    response: Response,
    user: User = Depends(get_current_user),
) -> None:
    service.change_password(db, user, data.current_password, data.new_password)
    _clear_session_cookies(response)  # every session ended; sign in again
