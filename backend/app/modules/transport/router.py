from fastapi import APIRouter, Depends, Request

from app.core.config import Settings, get_settings
from app.modules.transport import service
from app.modules.transport.schemas import TransportStatus

router = APIRouter()


@router.get("/status", response_model=TransportStatus)
def status(request: Request, settings: Settings = Depends(get_settings)) -> TransportStatus:
    return service.transport_status(request, settings)
