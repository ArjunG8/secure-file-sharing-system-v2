"""FastAPI application factory. Run with: uvicorn --factory app.main:create_app"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.core.config import APP_VERSION, get_settings
from app.core.errors import register_exception_handlers
from app.modules.transport.service import install_transport_security


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Secure File Sharing System",
        version=APP_VERSION,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    register_exception_handlers(app)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )
    install_transport_security(app, settings)
    app.include_router(api_router, prefix="/api/v1")
    return app
