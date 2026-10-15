"""Aggregates every module router under /api/v1. Owned by the integration lead."""

from fastapi import APIRouter

from app.core.config import APP_VERSION
from app.core.database import DbSession, database_is_reachable
from app.core.modules import all_modules
from app.modules.anomaly.router import router as anomaly_router
from app.modules.audit.router import router as audit_router
from app.modules.auth.router import router as auth_router
from app.modules.encryption.router import router as files_router
from app.modules.keys.router import router as keys_router
from app.modules.llm_analysis.router import router as analysis_router
from app.modules.sharing.router import router as shares_router
from app.modules.signatures.router import router as signatures_router
from app.modules.transport.router import router as transport_router
from app.modules.verification.router import router as verification_router
from app.schemas.common import ErrorResponse, HealthOut, ModuleOut

_errors = {
    code: {"model": ErrorResponse} for code in (400, 401, 403, 404, 409, 422, 500, 501)
}

api_router = APIRouter(responses=_errors)


@api_router.get("/health", response_model=HealthOut, tags=["core"])
def health(db: DbSession) -> HealthOut:
    return HealthOut(
        status="ok",
        version=APP_VERSION,
        database="ok" if database_is_reachable(db) else "unavailable",
    )


@api_router.get("/modules", response_model=list[ModuleOut], tags=["core"])
def modules() -> list[ModuleOut]:
    return [
        ModuleOut(number=m.number, code=m.code, key=m.key, name=m.name, implemented=m.implemented)
        for m in all_modules()
    ]


api_router.include_router(auth_router, prefix="/auth", tags=["M1 auth"])
api_router.include_router(files_router, prefix="/files", tags=["M2 files"])
api_router.include_router(keys_router, prefix="/keys", tags=["M3 keys"])
api_router.include_router(signatures_router, prefix="/signatures", tags=["M4 signatures"])
api_router.include_router(shares_router, prefix="/shares", tags=["M5 sharing"])
api_router.include_router(audit_router, prefix="/audit", tags=["M6 audit"])
api_router.include_router(anomaly_router, prefix="/anomaly", tags=["M7 anomaly"])
api_router.include_router(analysis_router, prefix="/analysis", tags=["M8 analysis"])
api_router.include_router(verification_router, prefix="/verification", tags=["M9 verification"])
api_router.include_router(transport_router, prefix="/transport", tags=["M10 transport"])
