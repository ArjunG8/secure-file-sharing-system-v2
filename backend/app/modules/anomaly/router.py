from fastapi import APIRouter, Depends

from app.api.deps import require_admin
from app.core.database import DbSession
from app.core.errors import NotImplementedFeature
from app.models import User
from app.modules.anomaly import MODULE_INFO, service
from app.modules.anomaly.schemas import AnomalyOut, ModelInfoOut, ScoreRequest, TrainRequest
from app.schemas.common import Page, PageParams, page_params

router = APIRouter()


@router.post("/train", response_model=ModelInfoOut)
def train(
    db: DbSession,
    data: TrainRequest,
    admin: User = Depends(require_admin),
) -> ModelInfoOut:
    return service.train_model(db, data.since)


@router.post("/score", response_model=list[AnomalyOut])
def score(
    db: DbSession,
    data: ScoreRequest,
    admin: User = Depends(require_admin),
) -> list[AnomalyOut]:
    return [AnomalyOut.model_validate(d) for d in service.score_recent(db, data.since)]


@router.get("/detections", response_model=Page[AnomalyOut])
def detections(
    db: DbSession,
    only_anomalies: bool = True,
    page: PageParams = Depends(page_params),
    admin: User = Depends(require_admin),
) -> Page[AnomalyOut]:
    raise NotImplementedFeature(MODULE_INFO, "Detection listing")
