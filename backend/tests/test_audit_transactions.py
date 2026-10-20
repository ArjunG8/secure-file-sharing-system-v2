"""Audit events vs. the request transaction (app.core.database).

append_entries is replaced by a TEST DOUBLE (tests.helpers.fake_append_entries) so these
tests exercise the transaction plumbing, not M6's HMAC chain, which is still unimplemented.
"""


import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.core.database import DbSession, session_scope
from app.core.errors import AppError, register_exception_handlers
from app.models import AuditLog, User
from app.modules.audit import service as audit_service
from app.modules.audit.schemas import AuditEventIn
from tests.helpers import GENESIS, chain_digest, fake_append_entries, make_user


def _event(event_type: str, outcome: str = "success") -> AuditEventIn:
    return AuditEventIn(event_type=event_type, outcome=outcome, details={"probe": event_type})


def _app() -> FastAPI:
    app = FastAPI()
    register_exception_handlers(app)

    @app.post("/success", status_code=201)
    def success(db: DbSession) -> dict:
        db.add(make_user(email="ok@example.test"))
        audit_service.record_event(db, _event("probe.success"))
        return {"ok": True}

    @app.post("/denied")
    def denied(db: DbSession) -> dict:
        db.add(make_user(email="denied-business@example.test"))
        db.flush()
        audit_service.record_event(db, _event("probe.success_before_denial"))
        audit_service.record_event(db, _event("probe.denied", "denied"))
        raise AppError(404, "Not found.")

    @app.post("/crash")
    def crash(db: DbSession) -> dict:
        db.add(make_user(email="crash-business@example.test"))
        audit_service.record_event(db, _event("probe.failure", "failure"))
        raise RuntimeError("unexpected bug")

    @app.post("/commit-fails", status_code=201)
    def commit_fails(db: DbSession) -> dict:
        # Duplicate unique emails, unflushed: the error only appears at COMMIT time.
        db.add(make_user(email="dup@example.test"))
        db.add(make_user(email="dup@example.test"))
        audit_service.record_event(db, _event("probe.would_succeed"))
        audit_service.record_event(db, _event("probe.attempt_failed", "failure"))
        return {"created": True}

    return app


@pytest.fixture
def audit_client(monkeypatch):
    monkeypatch.setattr(audit_service, "append_entries", fake_append_entries)
    with TestClient(_app(), raise_server_exceptions=False) as c:
        yield c


def _users(db, email: str) -> int:
    return db.scalar(select(func.count()).select_from(User).where(User.email == email))


def _audit_types(db) -> list[tuple[str, str]]:
    rows = db.scalars(select(AuditLog).order_by(AuditLog.id)).all()
    return [(r.event_type, r.outcome) for r in rows]


def test_success_commits_business_change_and_audit_together(audit_client, db):
    assert audit_client.post("/success").status_code == 201
    assert _users(db, "ok@example.test") == 1
    assert _audit_types(db) == [("probe.success", "success")]


def test_denied_event_survives_rollback_without_business_data(audit_client, db):
    r = audit_client.post("/denied")
    assert r.status_code == 404
    assert _users(db, "denied-business@example.test") == 0  # business change undone
    # Only the denial is kept; the success event described something that was rolled back.
    assert _audit_types(db) == [("probe.denied", "denied")]


def test_unexpected_error_keeps_failure_event_only(audit_client, db):
    r = audit_client.post("/crash")
    assert r.status_code == 500
    assert _users(db, "crash-business@example.test") == 0
    assert _audit_types(db) == [("probe.failure", "failure")]


def test_commit_failure_never_reports_success(audit_client, db):
    r = audit_client.post("/commit-fails")
    assert r.status_code == 500  # regression: used to answer 201 after a failed commit
    assert r.json()["error"]["code"] == "internal_error"
    assert _users(db, "dup@example.test") == 0
    assert _audit_types(db) == [("probe.attempt_failed", "failure")]


def test_chain_stays_consistent_across_successes_and_rollbacks(audit_client, db):
    for path in ("/success", "/denied", "/crash", "/denied"):
        audit_client.post(path)
        db.execute(User.__table__.delete().where(User.email == "ok@example.test"))
        db.commit()
    rows = db.scalars(select(AuditLog).order_by(AuditLog.id)).all()
    assert [r.outcome for r in rows] == ["success", "denied", "failure", "denied"]
    prev = GENESIS
    for row in rows:
        assert row.prev_hash == prev
        event = AuditEventIn(
            event_type=row.event_type,
            outcome=row.outcome,
            actor_user_id=row.actor_user_id,
            resource_type=row.resource_type,
            resource_id=row.resource_id,
            ip_address=row.ip_address,
            user_agent=row.user_agent,
            details=row.details,
        )
        assert row.entry_hash == chain_digest(prev, event)
        prev = row.entry_hash


def test_audit_write_failure_rolls_back_the_business_change(monkeypatch, db):
    def broken_append(db_, events):
        raise RuntimeError("audit store unavailable")

    monkeypatch.setattr(audit_service, "append_entries", broken_append)
    with TestClient(_app(), raise_server_exceptions=False) as c:
        assert c.post("/success").status_code == 500
    assert _users(db, "ok@example.test") == 0  # no action without its audit record


def test_session_scope_outside_requests(monkeypatch, db):
    monkeypatch.setattr(audit_service, "append_entries", fake_append_entries)
    with session_scope() as s:
        s.add(make_user(email="script@example.test"))
        audit_service.record_event(s, _event("script.ok"))
    with pytest.raises(ValueError), session_scope() as s:
        s.add(make_user(email="script-fail@example.test"))
        audit_service.record_event(s, _event("script.denied", "denied"))
        raise ValueError("abort")
    assert _users(db, "script@example.test") == 1
    assert _users(db, "script-fail@example.test") == 0
    assert _audit_types(db) == [("script.ok", "success"), ("script.denied", "denied")]


def test_success_event_is_recorded(audit_client, db):
    """A successful request persists its audit event."""
    assert audit_client.post("/success").status_code == 201
    assert _users(db, "ok@example.test") == 1
    assert _audit_types(db) == [("probe.success", "success")]


def test_concurrent_transactions_keep_one_chain_without_deadlock(monkeypatch, db):
    """PostgreSQL only (SQLite tests share one connection): parallel successes and
    denials, each with a success event queued before the denial, must neither deadlock
    nor fork the chain."""
    if db.get_bind().dialect.name != "postgresql":
        pytest.skip("needs PostgreSQL (TEST_DATABASE_URL); runs in CI")
    import uuid
    from concurrent.futures import ThreadPoolExecutor

    monkeypatch.setattr(audit_service, "append_entries", fake_append_entries)

    def work(i: int) -> None:
        try:
            with session_scope() as s:
                s.add(make_user(email=f"worker{i}-{uuid.uuid4().hex[:6]}@example.test"))
                s.flush()
                audit_service.record_event(s, _event(f"worker.{i}.success"))
                if i % 2:
                    audit_service.record_event(s, _event(f"worker.{i}.denied", "denied"))
                    raise AppError(403, "denied")
        except AppError:
            pass

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(work, range(40)))

    rows = db.scalars(select(AuditLog).order_by(AuditLog.id)).all()
    assert len(rows) == 40  # 20 successes + 20 denials; rolled-back successes dropped
    assert sum(r.outcome == "denied" for r in rows) == 20
    prev = GENESIS
    for row in rows:
        assert row.prev_hash == prev, "chain forked: two entries share a predecessor"
        prev = row.entry_hash
    assert db.scalar(select(func.count()).select_from(User)) == 20
