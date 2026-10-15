"""Uniform error envelope: {"error": {"code", "message", "module", "details"}}."""

import logging
from typing import TYPE_CHECKING, Any

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

if TYPE_CHECKING:
    from app.core.modules import ModuleInfo

logger = logging.getLogger(__name__)

STATUS_CODES = {
    400: "bad_request",
    401: "unauthenticated",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    413: "payload_too_large",
    422: "validation_error",
    423: "account_locked",
    429: "rate_limited",
    501: "not_implemented",
    502: "integrity_failure",
    503: "service_unavailable",
}


class AppError(Exception):
    """Raise from services/routers to return a structured error."""

    def __init__(
        self,
        status_code: int,
        message: str,
        *,
        code: str | None = None,
        module: str | None = None,
        details: Any = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code or STATUS_CODES.get(status_code, "error")
        self.message = message
        self.module = module
        self.details = details


class NotImplementedFeature(AppError):
    """Honest placeholder for functionality a module owner has not built yet."""

    def __init__(self, module: "ModuleInfo", feature: str) -> None:
        super().__init__(
            501,
            f"{feature} is not implemented yet ({module.code}: {module.name}).",
            module=module.code,
        )


def error_response(
    status_code: int,
    code: str,
    message: str,
    module: str | None = None,
    details: Any = None,
) -> JSONResponse:
    body = {"error": {"code": code, "message": message, "module": module, "details": details}}
    return JSONResponse(status_code=status_code, content=jsonable_encoder(body))


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(_: Request, exc: AppError) -> JSONResponse:
        return error_response(exc.status_code, exc.code, exc.message, exc.module, exc.details)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = STATUS_CODES.get(exc.status_code, "error")
        return error_response(exc.status_code, code, str(exc.detail))

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        return error_response(
            422, "validation_error", "Request validation failed.", None, exc.errors()
        )

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled error", exc_info=exc)
        return error_response(500, "internal_error", "An unexpected error occurred.")
