"""M6: HMAC hash chain, tamper detection, transactional behaviour, access control."""

import base64
import hashlib
import json
import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import SecretStr
from sqlalchemy import delete, select, update

from app.core.config import get_settings
from app.core.database import session_scope
from app.models import AuditLog
from app.modules.audit import hashchain, service
from app.modules.audit.schemas import AuditEventIn


def record(event_type, outcome="success", actor=None, **details):
    with session_scope() as s:
        service.record_event(s, AuditEventIn(event_type=event_type, outcome=outcome,
                                             actor_user_id=actor, details=details))


def rows(db):
    db.expire_all()
    return db.scalars(select(AuditLog).order_by(AuditLog.id)).all()


@pytest.fixture
def chain(db):
    for i in range(5):
        record(f"event.{i}", n=i, note="ünïcode ✓")
    return rows(db)


# --- chain construction ------------------------------------------------------------------


def test_entries_form_an_hmac_chain(chain, db):
    assert chain[0].prev_hash == hashchain.GENESIS_HASH
    for prev, row in zip(chain, chain[1:], strict=False):
        assert row.prev_hash == prev.entry_hash
    key = base64.b64decode(get_settings().audit_hmac_key.get_secret_value())
    import hmac

    expected = hmac.new(key, bytes.fromhex(chain[0].prev_hash)
                        + hashchain.canonical_json(hashchain.payload_of(chain[0])),
                        hashlib.sha256).hexdigest()
    assert chain[0].entry_hash == expected
    result = service.verify_chain(db)
    assert result.valid and result.checked_entries == 5 and result.last_hash == chain[-1].entry_hash


def test_empty_chain_is_valid(db):
    result = service.verify_chain(db)
    assert result.valid and result.checked_entries == 0 and result.last_hash is None


def test_failure_event_survives_rollback_and_success_event_does_not(db):
    with pytest.raises(RuntimeError), session_scope() as s:
        service.record_event(s, AuditEventIn(event_type="x.success"))
        service.record_event(s, AuditEventIn(event_type="x.denied", outcome="denied"))
        raise RuntimeError("business failure")
    assert [(r.event_type, r.outcome) for r in rows(db)] == [("x.denied", "denied")]
    assert service.verify_chain(db).valid


# --- tamper detection --------------------------------------------------------------------


def test_edited_details_are_detected(chain, db):
    db.execute(update(AuditLog).where(AuditLog.id == chain[2].id)
               .values(details={"n": 999}))
    db.commit()
    result = service.verify_chain(db)
    assert not result.valid and result.first_broken_id == chain[2].id
    assert "modified" in result.reason


def test_edited_outcome_or_actor_is_detected(chain, db):
    db.execute(update(AuditLog).where(AuditLog.id == chain[1].id).values(outcome="denied"))
    db.commit()
    assert service.verify_chain(db).first_broken_id == chain[1].id


def test_deleted_entry_is_detected(chain, db):
    db.execute(delete(AuditLog).where(AuditLog.id == chain[2].id))
    db.commit()
    result = service.verify_chain(db)
    assert not result.valid and result.first_broken_id == chain[3].id
    assert "prev_hash" in result.reason


def test_recomputed_plain_sha256_does_not_pass(chain, db):
    """An attacker without AUDIT_HMAC_KEY rewrites a row and 'fixes' its hash."""
    row = chain[4]
    forged_details = {"n": 4, "note": "nothing happened"}
    payload = hashchain.payload_of(row) | {"details": forged_details}
    forged_hash = hashlib.sha256(bytes.fromhex(row.prev_hash)
                                 + hashchain.canonical_json(payload)).hexdigest()
    db.execute(update(AuditLog).where(AuditLog.id == row.id)
               .values(details=forged_details, entry_hash=forged_hash))
    db.commit()
    assert service.verify_chain(db).first_broken_id == row.id


def test_inserted_forged_entry_is_detected(chain, db):
    db.add(AuditLog(event_type="forged", outcome="success", details={},
                    occurred_at=datetime.now(UTC), prev_hash=chain[-1].entry_hash,
                    entry_hash="ab" * 32))
    db.commit()
    assert not service.verify_chain(db).valid


def test_verification_with_a_different_key_fails(chain, db, monkeypatch):
    monkeypatch.setattr(get_settings(), "audit_hmac_key",
                        SecretStr(base64.b64encode(os.urandom(32)).decode()))
    assert service.verify_chain(db).first_broken_id == chain[0].id


def test_canonical_time_is_stable_for_naive_and_aware_values():
    aware = datetime(2026, 1, 2, 3, 4, 5, 678901, tzinfo=UTC)
    assert hashchain.canonical_time(aware) == "2026-01-02T03:04:05.678901Z"
    assert hashchain.canonical_time(aware.replace(tzinfo=None)) == "2026-01-02T03:04:05.678901Z"
    ist = aware.astimezone(__import__("zoneinfo").ZoneInfo("Asia/Kolkata"))
    assert hashchain.canonical_time(ist) == "2026-01-02T03:04:05.678901Z"


def test_canonical_json_is_key_order_independent():
    a = hashchain.canonical_json({"b": 1, "a": {"y": 2, "x": 1}})
    b = hashchain.canonical_json({"a": {"x": 1, "y": 2}, "b": 1})
    assert a == b == json.dumps({"a": {"x": 1, "y": 2}, "b": 1}, separators=(",", ":")).encode()


# --- API ---------------------------------------------------------------------------------


def test_users_see_only_their_own_events(client_as, create_user):
    alice, bob = create_user(), create_user()
    record("mine", actor=alice.id)
    record("theirs", actor=bob.id)
    record("system")
    r = client_as(alice).get("/api/v1/audit/logs")
    assert r.status_code == 200
    assert [e["event_type"] for e in r.json()["items"]] == ["mine"]
    assert r.json()["total"] == 1
    assert client_as(alice).get(f"/api/v1/audit/logs?actor_id={bob.id}").status_code == 403


def test_admin_sees_all_events_and_can_filter(client_as, create_user):
    admin, alice = create_user(role="admin"), create_user()
    record("auth.login", actor=alice.id)
    record("auth.login_failed", "failure", actor=alice.id)
    record("file.upload", actor=admin.id)
    c = client_as(admin)
    assert c.get("/api/v1/audit/logs").json()["total"] == 3
    only = c.get("/api/v1/audit/logs?event_type=auth.login_failed").json()
    assert [e["outcome"] for e in only["items"]] == ["failure"]
    assert c.get(f"/api/v1/audit/logs?actor_id={alice.id}").json()["total"] == 2
    future = (datetime.now(UTC) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    assert c.get("/api/v1/audit/logs", params={"since": future}).json()["total"] == 0
    page = c.get("/api/v1/audit/logs?limit=1&offset=1").json()
    assert len(page["items"]) == 1 and page["total"] == 3


def test_verify_endpoint_is_admin_only_and_reports_tampering(client_as, create_user, db):
    admin, alice = create_user(role="admin"), create_user()
    record("a")
    record("b")
    assert client_as(alice).get("/api/v1/audit/verify").status_code == 403
    ok = client_as(admin).get("/api/v1/audit/verify")
    assert ok.status_code == 200 and ok.json()["valid"] is True
    first = rows(db)[0]
    db.execute(update(AuditLog).where(AuditLog.id == first.id).values(event_type="edited"))
    db.commit()
    bad = client_as(admin).get("/api/v1/audit/verify").json()
    assert bad["valid"] is False and bad["first_broken_id"] == first.id
    # The verification run itself is audited.
    assert rows(db)[-1].event_type == "audit.verify"


def test_concurrent_appends_on_postgresql_keep_one_valid_chain(db):
    if db.get_bind().dialect.name != "postgresql":
        pytest.skip("needs PostgreSQL (TEST_DATABASE_URL); runs in CI")
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda i: record(f"concurrent.{i}", actor=None, i=i), range(40)))
    assert len(rows(db)) == 40
    assert service.verify_chain(db).valid


def test_event_ids_are_not_part_of_the_hash(chain):
    payload = hashchain.payload_of(chain[0])
    assert "id" not in payload and set(payload) == set(hashchain.HASHED_FIELDS)
    assert uuid.UUID  # imported for symmetry with other tests
