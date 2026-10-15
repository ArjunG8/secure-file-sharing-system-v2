"""Database engine, sessions and the transaction rule (synchronous SQLAlchemy 2.x).

Transaction rule (docs/integration-guide.md "Database transactions"):
- One session and one transaction per request (or per script via session_scope()).
- Services and routers never call db.commit(); they call db.flush() when they need
  generated values. Reject a request by raising (e.g. AppError): everything is undone.
- Audit events are queued with audit.service.record_event() and written by this
  module at the transaction boundary:
    * on success, ALL queued events are appended in the same transaction, just before
      COMMIT (atomic with the business change; the audit-chain lock is held only for
      that final insert + commit);
    * on failure, the business transaction is rolled back FIRST, then only the
      "failure"/"denied" events are appended in a new, separate transaction. Nothing
      from the rolled-back request can be committed with them, and the request no
      longer holds any lock, so the audit write cannot deadlock against it.
"""

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache
from typing import TYPE_CHECKING, Annotated

from fastapi import Depends
from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import get_settings

if TYPE_CHECKING:
    from app.modules.audit.schemas import AuditEventIn

logger = logging.getLogger(__name__)

_AUDIT_QUEUE_KEY = "pending_audit_events"


def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record) -> None:
    # SQLite ignores FOREIGN KEY / ON DELETE clauses unless enabled per connection.
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


@lru_cache
def get_engine() -> Engine:
    url = get_settings().database_url
    kwargs: dict = {"pool_pre_ping": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if ":memory:" in url:
            kwargs["poolclass"] = StaticPool
    engine = create_engine(url, **kwargs)
    if engine.dialect.name == "sqlite":
        event.listen(engine, "connect", _enable_sqlite_foreign_keys)
    return engine


@lru_cache
def get_sessionmaker() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), autoflush=False, expire_on_commit=False)


# --- audit queue (filled by app.modules.audit.service.record_event) ---------------------


def queue_audit_event(db: Session, audit_event: "AuditEventIn") -> None:
    db.info.setdefault(_AUDIT_QUEUE_KEY, []).append(audit_event)


def _write_failure_events_after_rollback(events: list["AuditEventIn"]) -> None:
    from app.modules.audit import service as audit_service  # lazy: avoids import cycle

    audit_db = get_sessionmaker()()
    try:
        audit_service.append_entries(audit_db, events)
        audit_db.commit()
    except Exception:
        audit_db.rollback()
        # Never mask the original error; make the lost audit write loud instead.
        logger.exception("Could not write %d failure/denied audit event(s)", len(events))
    finally:
        audit_db.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    """One transaction with the audit rule above. Use it in scripts and background work."""
    from app.modules.audit import service as audit_service  # lazy: avoids import cycle

    db = get_sessionmaker()()
    try:
        yield db
        queued = db.info.get(_AUDIT_QUEUE_KEY, [])
        if queued:
            audit_service.append_entries(db, list(queued))
        db.commit()
    except Exception:
        db.rollback()
        failures = [e for e in db.info.get(_AUDIT_QUEUE_KEY, []) if e.outcome != "success"]
        if failures:
            _write_failure_events_after_rollback(failures)
        raise
    finally:
        db.info.pop(_AUDIT_QUEUE_KEY, None)
        db.close()


def get_db() -> Iterator[Session]:
    """FastAPI dependency. Always use it through DbSession (function scope)."""
    with session_scope() as db:
        yield db


# scope="function": the commit finishes BEFORE the response is sent, so a failed commit
# becomes an error response instead of a false success. Every route must use this alias
# (tests/test_database.py checks it). Consequence: the session is closed before the
# response body is sent - build the full response (e.g. download bytes) before returning,
# and never use the session inside a StreamingResponse generator or background task.
DbSession = Annotated[Session, Depends(get_db, scope="function")]


def database_is_reachable(db: Session) -> bool:
    try:
        db.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
