import uuid

from fastapi import APIRouter, Depends, status

from app.api.deps import require_admin
from app.core.database import DbSession
from app.models import User
from app.modules.llm_analysis import service
from app.modules.llm_analysis.schemas import AnalysisOut, AnalysisRequest
from app.schemas.common import Page, PageParams, page_params

router = APIRouter()


@router.post("", response_model=AnalysisOut, status_code=status.HTTP_201_CREATED)
def run_analysis(
    db: DbSession,
    data: AnalysisRequest,
    admin: User = Depends(require_admin),
) -> AnalysisOut:
    return AnalysisOut.model_validate(service.analyze(db, admin.id, data))


@router.get("", response_model=Page[AnalysisOut])
def list_analyses(
    db: DbSession,
    page: PageParams = Depends(page_params),
    admin: User = Depends(require_admin),
) -> Page[AnalysisOut]:
    rows, total = service.list_analyses(db, page.limit, page.offset)
    return Page[AnalysisOut](items=[AnalysisOut.model_validate(r) for r in rows], total=total,
                             limit=page.limit, offset=page.offset)


@router.get("/{analysis_id}", response_model=AnalysisOut)
def get_analysis(
    db: DbSession,
    analysis_id: uuid.UUID,
    admin: User = Depends(require_admin),
) -> AnalysisOut:
    return AnalysisOut.model_validate(service.get_analysis(db, analysis_id))
