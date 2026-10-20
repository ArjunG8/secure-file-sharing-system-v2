"""HMAC-SHA256 hash chain primitives (pure functions, no database).

entry_hash = HMAC-SHA256(AUDIT_HMAC_KEY, bytes.fromhex(prev_hash) || canonical_json(payload))
The payload covers every stored field except `id` (assigned by the database; gaps are
normal) and the two hash columns themselves.
"""

import base64
import hashlib
import hmac
import json
import uuid
from datetime import UTC, datetime
from typing import Any

GENESIS_HASH = "0" * 64

HASHED_FIELDS = (
    "occurred_at", "actor_user_id", "event_type", "outcome", "resource_type",
    "resource_id", "ip_address", "user_agent", "details",
)


def canonical_time(value: datetime) -> str:
    """UTC, microsecond precision, 'Z' suffix. SQLite returns naive values (stored as UTC)."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def payload_of(row: Any) -> dict[str, Any]:
    """The hashed payload of an AuditLog row (or any object with the same attributes)."""
    actor = row.actor_user_id
    return {
        "occurred_at": canonical_time(row.occurred_at),
        "actor_user_id": str(actor) if isinstance(actor, uuid.UUID) else actor,
        "event_type": row.event_type,
        "outcome": row.outcome,
        "resource_type": row.resource_type,
        "resource_id": row.resource_id,
        "ip_address": row.ip_address,
        "user_agent": row.user_agent,
        "details": row.details or {},
    }


def canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      default=str).encode()


def entry_hash(key_b64: str, prev_hash: str, payload: dict[str, Any]) -> str:
    key = base64.b64decode(key_b64)
    return hmac.new(key, bytes.fromhex(prev_hash) + canonical_json(payload),
                    hashlib.sha256).hexdigest()


def hashes_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())
