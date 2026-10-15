"""Test helpers (import as `from tests.helpers import ...`)."""

import hashlib
import json
import uuid

from sqlalchemy import select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from app.models import AuditLog, User
from app.modules.audit.schemas import AuditEventIn

GENESIS = "0" * 64


def unsafe_test_database_reason(url: str, protected_urls: tuple[str, ...] = ()) -> str | None:
    """Why `url` must not be used by the test suite (which deletes every row), or None.

    Allowed: SQLite, or a server database whose NAME contains "test" and which is not
    one of `protected_urls` (e.g. the developer's DATABASE_URL).
    """
    parsed = make_url(url)
    if parsed.get_backend_name() == "sqlite":
        return None
    if any(url == p for p in protected_urls if p):
        return "it is the same database as DATABASE_URL"
    if "test" not in (parsed.database or "").lower():
        return f"database name {parsed.database!r} does not contain 'test'"
    return None


def chain_digest(prev_hash: str, event: AuditEventIn) -> str:
    payload = json.dumps(event.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + payload).encode()).hexdigest()


def fake_append_entries(db: Session, events: list[AuditEventIn]) -> None:
    """TEST DOUBLE for audit.service.append_entries - NOT M6's design.

    A plain SHA-256 chain, used only to test the transaction plumbing in
    app.core.database. M6 must implement the real HMAC chain and locking.
    """
    if db.get_bind().dialect.name == "postgresql":
        # Same locking contract M6 must follow: a transaction-scoped chain lock taken at
        # the end of the transaction. lock_timeout turns a deadlock into a test failure.
        db.execute(text("SET LOCAL lock_timeout = '5s'"))
        db.execute(text("SELECT pg_advisory_xact_lock(424242)"))
    last = db.scalar(select(AuditLog).order_by(AuditLog.id.desc()).limit(1))
    prev = last.entry_hash if last else GENESIS
    for event in events:
        entry_hash = chain_digest(prev, event)
        db.add(AuditLog(**event.model_dump(), prev_hash=prev, entry_hash=entry_hash))
        prev = entry_hash
    db.flush()


def make_user(role: str = "user", email: str | None = None) -> User:
    """An unsaved User object. Use the `create_user` fixture to persist one.

    password_hash is a placeholder, not an Argon2id hash: these users cannot log in.
    M1 tests that need real logins should register users through the API instead.
    """
    return User(
        id=uuid.uuid4(),
        email=email or f"{uuid.uuid4().hex[:8]}@example.test",
        username=f"user_{uuid.uuid4().hex[:8]}",
        password_hash="placeholder-not-an-argon2-hash",
        role=role,
        is_active=True,
        failed_login_count=0,
    )
