from fastapi import APIRouter, Depends, Request, Response, status

from app.api.deps import get_current_user
from app.core.database import DbSession
from app.models import User
from app.modules.auth import service
from app.modules.auth.schemas import (
    ChangePasswordRequest,
    LoginRequest,
    RegisterRequest,
    TokenResponse,
    UserOut,
)

router = APIRouter()


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(db: DbSession, data: RegisterRequest) -> UserOut:
    user = service.register_user(db, data)
    return UserOut.model_validate(user)


@router.post("/login", response_model=TokenResponse)
def login(
    db: DbSession,
    data: LoginRequest,
    request: Request,
    response: Response,
) -> TokenResponse:
    pair = service.authenticate(
        db,
        data.email,
        data.password,
        request.client.host if request.client else None,
        request.headers.get("user-agent"),
    )
    # TODO(M1): response.set_cookie("refresh_token", pair.refresh_token, httponly=True,
    #           secure=True, samesite="strict", path="/api/v1/auth")
    return pair.access


@router.post("/refresh", response_model=TokenResponse)
def refresh(db: DbSession, request: Request, response: Response) -> TokenResponse:
    pair = service.refresh_session(db, request.cookies.get("refresh_token", ""))
    return pair.access


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    db: DbSession,
    request: Request,
    user: User = Depends(get_current_user),
) -> None:
    service.revoke_session(db, user.id, request.cookies.get("refresh_token"))


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> UserOut:
    return UserOut.model_validate(user)


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    db: DbSession,
    data: ChangePasswordRequest,
    user: User = Depends(get_current_user),
) -> None:
    service.change_password(db, user, data.current_password, data.new_password)
