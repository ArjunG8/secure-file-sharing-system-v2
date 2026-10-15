"""The per-request transaction rule, foreign-key enforcement and the shared DB fixtures."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import FastAPI
from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import DbSession, get_db
from app.core.errors import AppError, register_exception_handlers
from app.models import AuditLog, AuthSession, User
from tests.helpers import make_user


def _probe_app() -> FastAPI:
    app = FastAPI()
    register_exception_handlers(app)

    @app.post("/ok")
    def ok(db: DbSession) -> dict:
        db.add(make_user(email="committed@example.test"))
        return {"ok": True}

    @app.post("/fails")
    def fails(db: DbSession) -> dict:
        db.add(make_user(email="rolled-back@example.test"))
        db.flush()
        raise AppError(403, "denied after writing")

    return app


def _count(db: Session, email: str) -> int:
    return db.scalar(select(func.count()).select_from(User).where(User.email == email))


def test_successful_request_commits(db):
    with TestClient(_probe_app()) as c:
        assert c.post("/ok").status_code == 200
    assert _count(db, "committed@example.test") == 1


def test_failed_request_rolls_back(db):
    with TestClient(_probe_app()) as c:
        r = c.post("/fails")
        assert r.status_code == 403
        assert r.json()["error"]["code"] == "forbidden"
        # A later request on the same connection must not commit the leftover write.
        assert c.post("/ok").status_code == 200
    assert _count(db, "rolled-back@example.test") == 0


def _db_dependencies(dependant: Dependant):
    for sub in dependant.dependencies:
        if sub.call is get_db:
            yield sub
        yield from _db_dependencies(sub)


def _api_routes(routes):
    for route in routes:
        if isinstance(route, APIRoute):
            yield route
        # FastAPI 0.14x keeps included routers nested instead of copying their routes.
        inner = getattr(route, "original_router", None)
        if inner is not None:
            yield from _api_routes(inner.routes)


def test_every_route_commits_before_the_response_is_sent(app):
    """get_db must be function-scoped everywhere (use DbSession), or a failed COMMIT
    happens after a 2xx response was already sent (see test_audit_transactions)."""
    checked = 0
    for route in _api_routes(app.routes):
        for dep in _db_dependencies(route.dependant):
            assert dep.scope == "function", f"{route.path} uses get_db without DbSession"
            checked += 1
    assert checked >= 30  # sanity: the walk really found the database dependencies


# --- foreign keys (SQLite enforces them only with PRAGMA foreign_keys=ON) -------------


def test_invalid_foreign_key_is_rejected(db):
    db.add(
        AuthSession(
            user_id=uuid.uuid4(),  # no such user
            refresh_token_hash="0" * 64,
            expires_at=datetime.now(UTC) + timedelta(days=1),
        )
    )
    with pytest.raises(IntegrityError):
        db.commit()


def test_on_delete_cascade_and_set_null(create_user, db):
    user = create_user()
    db.add(
        AuthSession(
            user_id=user.id,
            refresh_token_hash="1" * 64,
            expires_at=datetime.now(UTC) + timedelta(days=1),
        )
    )
    db.add(
        AuditLog(
            actor_user_id=user.id,
            event_type="probe",
            outcome="success",
            details={},
            prev_hash="0" * 64,
            entry_hash="2" * 64,
        )
    )
    db.commit()

    db.execute(delete(User).where(User.id == user.id))  # database-level delete, not ORM
    db.commit()
    db.expire_all()
    assert db.scalar(select(func.count()).select_from(AuthSession)) == 0  # CASCADE
    log = db.scalar(select(AuditLog))
    assert log is not None and log.actor_user_id is None  # SET NULL keeps the audit row


# --- fixtures ----------------------------------------------------------------------------


def test_create_user_persists(create_user, db):
    admin = create_user(role="admin", email="admin@example.test")
    stored = db.get(User, admin.id)
    assert stored is not None and stored.role == "admin"


def test_tables_are_empty_at_start_of_each_test(db):
    # test_create_user_persists stored a user; the autouse cleanup must have removed it.
    assert db.scalar(select(func.count()).select_from(User)) == 0


def test_client_as_overrides_current_user(client_as, create_user):
    alice = create_user()
    r = client_as(alice).get("/api/v1/keys/me")
    # Reaches M3's own stub, proving M1's dependency was replaced by `alice`.
    assert r.status_code == 501
    assert r.json()["error"]["module"] == "M3"
