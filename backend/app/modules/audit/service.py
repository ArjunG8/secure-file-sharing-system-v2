"""M6 public interface. Implementation notes: docs/security-design.md, section M6.

How audit writes reach the database (implemented in app.core.database, owned by Lead):
  record_event(db, event)  -> only QUEUES the event on the session; never writes.
  end of the transaction   -> app.core.database calls append_entries():
      success path: append_entries(request_session, all queued events), then COMMIT
      failure path: ROLLBACK the request, then append_entries(new_session, only the
                    "failure"/"denied" events), then COMMIT that new session.
M6 implements append_entries() and the hash chain; it never commits itself.
"""

import logging

from sqlalchemy.orm import Session

from app.core.database import queue_audit_event
from app.core.errors import NotImplementedFeature
from app.modules.audit import MODULE_INFO
from app.modules.audit.schemas import AuditEventIn, ChainVerification

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64


def record_event(db: Session, event: AuditEventIn) -> None:
    """Queue a security event for the current transaction (see module docstring).

    Call it from any module, in any outcome. Raise your error AFTER calling it: a
    "failure"/"denied" event is still written when the request then rolls back; a
    "success" event is written only if the request commits.
    """
    queue_audit_event(db, event)


def append_entries(db: Session, events: list[AuditEventIn]) -> None:
    """Append `events`, in order, to the HMAC hash chain inside `db`'s transaction.

    Contract for M6 (called only by app.core.database, at the very end of a transaction):
    - First take the chain lock for this transaction only, e.g. on PostgreSQL
      `SELECT pg_advisory_xact_lock(<constant>)`; it is released by the caller's
      COMMIT/ROLLBACK a moment later. Then read the latest entry_hash (GENESIS_HASH if
      the table is empty), compute each entry_hash with compute_entry_hash, add rows,
      and db.flush(). Never call db.commit() or db.rollback().
    - Raise on any error: on the success path that rolls the business change back too
      (no action without its audit record).

    STUB BEHAVIOUR (until M6 implements it): nothing is persisted; a warning is logged.
    """
    for event in events:
        logger.warning(
            "Audit logging not implemented (M6): event %r was NOT recorded.", event.event_type
        )


def compute_entry_hash(prev_hash: str, payload: dict) -> str:
    """HMAC-SHA256(AUDIT_HMAC_KEY, bytes.fromhex(prev_hash) || canonical_json(payload)), hex."""
    raise NotImplementedFeature(MODULE_INFO, "Audit hash computation")


def verify_chain(db: Session) -> ChainVerification:
    """Recompute every entry_hash in id order and report the first mismatch."""
    raise NotImplementedFeature(MODULE_INFO, "Audit chain verification")
