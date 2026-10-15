import uuid

from fastapi import APIRouter, Depends

from app.api.deps import get_current_user, require_admin
from app.core.database import DbSession
from app.core.errors import NotImplementedFeature
from app.models import User
from app.modules.verification import MODULE_INFO, service
from app.modules.verification.schemas import VerificationReport
from app.schemas.common import Page, PageParams, page_params

router = APIRouter()


@router.post("/files/{file_id}", response_model=VerificationReport)
def verify_file(
    db: DbSession,
    file_id: uuid.UUID,
    user: User = Depends(get_current_user),
) -> VerificationReport:
    return VerificationReport.model_validate(service.verify_file(db, user.id, file_id))


@router.post("/audit-chain", response_model=VerificationReport)
def verify_audit_chain(
    db: DbSession,
    admin: User = Depends(require_admin),
) -> VerificationReport:
    return VerificationReport.model_validate(service.verify_audit_chain(db, admin.id))


@router.get("/runs", response_model=Page[VerificationReport])
def list_runs(
    db: DbSession,
    page: PageParams = Depends(page_params),
    admin: User = Depends(require_admin),
) -> Page[VerificationReport]:
    raise NotImplementedFeature(MODULE_INFO, "Verification run listing")
