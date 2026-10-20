import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query

from app.api.deps import get_current_user, require_admin
from app.core.database import DbSession
from app.core.errors import AppError
from app.models import User
from app.modules.audit import MODULE_INFO, service
from app.modules.audit.schemas import AuditEventIn, AuditLogOut, ChainVerification
from app.schemas.common import Page, PageParams, page_params

router = APIRouter()


@router.get("/logs", response_model=Page[AuditLogOut])
def list_logs(
    db: DbSession,
    event_type: str | None = Query(None, max_length=64),
    actor_id: uuid.UUID | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    page: PageParams = Depends(page_params),
    user: User = Depends(get_current_user),
) -> Page[AuditLogOut]:
    """Admins see all events; other users only events where they are the actor."""
    if user.role != "admin":
        if actor_id is not None and actor_id != user.id:
            raise AppError(403, "You can only view your own audit events.",
                           module=MODULE_INFO.code)
        actor_id = user.id
    rows, total = service.list_events(
        db, actor_id=actor_id, event_type=event_type, since=since, until=until,
        limit=page.limit, offset=page.offset,
    )
    return Page[AuditLogOut](
        items=[AuditLogOut.model_validate(r) for r in rows],
        total=total, limit=page.limit, offset=page.offset,
    )


@router.get("/verify", response_model=ChainVerification)
def verify(
    db: DbSession,
    admin: User = Depends(require_admin),
) -> ChainVerification:
    result = service.verify_chain(db)
    service.record_event(db, AuditEventIn(
        event_type="audit.verify", actor_user_id=admin.id,
        outcome="success" if result.valid else "failure",
        details={"valid": result.valid, "checked_entries": result.checked_entries,
                 "first_broken_id": result.first_broken_id},
    ))
    return result
