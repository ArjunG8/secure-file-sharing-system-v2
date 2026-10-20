"""M6 public interface. Implementation notes: docs/security-design.md, section M6.

How audit writes reach the database (implemented in app.core.database, owned by Lead):
  record_event(db, event)  -> only QUEUES the event on the session; never writes.
  end of the transaction   -> app.core.database calls append_entries():
      success path: append_entries(request_session, all queued events), then COMMIT
      failure path: ROLLBACK the request, then append_entries(new_session, only the
                    "failure"/"denied" events), then COMMIT that new session.
M6 implements append_entries() and the hash chain; it never commits itself.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import queue_audit_event
from app.models import AuditLog
from app.modules.audit import hashchain
from app.modules.audit.schemas import AuditEventIn, ChainVerification

GENESIS_HASH = hashchain.GENESIS_HASH
# Arbitrary constant identifying "the audit chain" for pg_advisory_xact_lock.
_CHAIN_LOCK_ID = 0x5F5_A0D17


def _key() -> str:
    return get_settings().audit_hmac_key.get_secret_value()


def record_event(db: Session, event: AuditEventIn) -> None:
    """Queue a security event for the current transaction (see module docstring).

    Call it from any module, in any outcome. Raise your error AFTER calling it: a
    "failure"/"denied" event is still written when the request then rolls back; a
    "success" event is written only if the request commits.
    """
    queue_audit_event(db, event)


def compute_entry_hash(prev_hash: str, payload: dict) -> str:
    """HMAC-SHA256(AUDIT_HMAC_KEY, bytes.fromhex(prev_hash) || canonical_json(payload)), hex."""
    return hashchain.entry_hash(_key(), prev_hash, payload)


def _lock_chain(db: Session) -> None:
    # PostgreSQL: one appender at a time, released by the caller's COMMIT/ROLLBACK.
    # SQLite: the database lock taken by the first INSERT serializes writers; the tests'
    # in-memory database has a single connection.
    if db.get_bind().dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(:id)"), {"id": _CHAIN_LOCK_ID})


def append_entries(db: Session, events: list[AuditEventIn]) -> None:
    """Append `events`, in order, to the HMAC hash chain inside `db`'s transaction.

    Called only by app.core.database at the very end of a transaction. Takes the chain
    lock, reads the latest entry_hash, inserts the rows and flushes. Never commits or rolls
    back; raises on error (on the success path that also undoes the business change).
    """
    if not events:
        return
    _lock_chain(db)
    prev = db.scalar(select(AuditLog.entry_hash).order_by(AuditLog.id.desc()).limit(1))
    prev = prev or GENESIS_HASH
    key = _key()
    for event in events:
        row = AuditLog(**event.model_dump(), occurred_at=datetime.now(UTC), prev_hash=prev)
        row.entry_hash = hashchain.entry_hash(key, prev, hashchain.payload_of(row))
        db.add(row)
        prev = row.entry_hash
    db.flush()


def verify_chain(db: Session) -> ChainVerification:
    """Recompute every entry_hash in id order and report the first mismatch.

    Detects edited rows, deleted rows (the next row's prev_hash no longer matches),
    inserted or reordered rows and rows forged without AUDIT_HMAC_KEY. It cannot detect
    truncation of the newest entries on its own: compare `last_hash` with a value
    recorded elsewhere (e.g. in the report) to cover that.
    """
    key = _key()
    expected_prev = GENESIS_HASH
    checked = 0
    for row in db.scalars(select(AuditLog).order_by(AuditLog.id).execution_options(
            yield_per=500)):
        checked += 1
        if not hashchain.hashes_equal(row.prev_hash, expected_prev):
            return ChainVerification(valid=False, checked_entries=checked,
                                     first_broken_id=row.id,
                                     reason="prev_hash does not match the previous entry")
        recomputed = hashchain.entry_hash(key, row.prev_hash, hashchain.payload_of(row))
        if not hashchain.hashes_equal(row.entry_hash, recomputed):
            return ChainVerification(valid=False, checked_entries=checked,
                                     first_broken_id=row.id,
                                     reason="entry content or entry_hash was modified")
        expected_prev = row.entry_hash
    return ChainVerification(valid=True, checked_entries=checked,
                             last_hash=None if checked == 0 else expected_prev)


def list_events(
    db: Session,
    *,
    actor_id: uuid.UUID | None,
    event_type: str | None,
    since: datetime | None,
    until: datetime | None,
    limit: int,
    offset: int,
) -> tuple[list[AuditLog], int]:
    conditions = []
    if actor_id is not None:
        conditions.append(AuditLog.actor_user_id == actor_id)
    if event_type:
        conditions.append(AuditLog.event_type == event_type)
    if since is not None:
        conditions.append(AuditLog.occurred_at >= since)
    if until is not None:
        conditions.append(AuditLog.occurred_at < until)
    total = db.scalar(select(func.count()).select_from(AuditLog).where(*conditions))
    rows = db.scalars(
        select(AuditLog).where(*conditions).order_by(AuditLog.id.desc())
        .limit(limit).offset(offset)
    ).all()
    return list(rows), total
