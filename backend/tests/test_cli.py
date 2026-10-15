import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.exc import IntegrityError

from app.cli import main
from app.models import User
from app.modules.auth.schemas import LoginRequest, RegisterRequest
from app.modules.sharing.schemas import ShareCreate


def _role(db, user) -> str:
    db.expire_all()
    return db.get(User, user.id).role


# --- email normalization -----------------------------------------------------------------


def test_emails_are_normalized_by_model_and_schemas(create_user):
    assert create_user(email="  Mixed.Case@Example.TEST ").email == "mixed.case@example.test"
    reg = RegisterRequest(email=" Alice@Uni.EDU ", username="alice", password="x" * 12)
    assert reg.email == "alice@uni.edu"
    assert LoginRequest(email="ALICE@uni.edu", password="x").email == "alice@uni.edu"
    share = ShareCreate(file_id="00000000-0000-0000-0000-000000000000", recipient_email="B@X.org")
    assert share.recipient_email == "b@x.org"


def test_case_only_duplicate_accounts_are_impossible(create_user):
    create_user(email="dup@example.test")
    with pytest.raises(IntegrityError):  # normalized by the model -> unique violation
        create_user(email="DUP@Example.test")


def test_database_rejects_unnormalized_email_written_directly(db):
    # A Core insert bypasses the ORM normalizer; the CHECK constraint must still refuse it.
    now = datetime.now(UTC)
    with pytest.raises(IntegrityError):  # CHECK ck_users_email_normalized
        db.execute(
            User.__table__.insert().values(
                id=uuid.uuid4(),
                email="Raw@Example.test",
                username="raw",
                password_hash="placeholder-not-an-argon2-hash",
                role="user",
                is_active=True,
                failed_login_count=0,
                created_at=now,
                updated_at=now,
            )
        )


# --- promote / demote ----------------------------------------------------------------


def test_promote_requires_explicit_confirmation(create_user, db, capsys):
    user = create_user(email="lead@example.test")
    assert main(["promote-admin", "  Lead@Example.TEST "]) == 2  # mixed case finds it
    out = capsys.readouterr().out
    assert str(user.id) in out and user.username in out  # the target is shown
    assert "--yes" in out
    assert _role(db, user) == "user"  # dry run changed nothing


def test_promote_and_demote_with_yes(create_user, db):
    user = create_user(email="lead@example.test")
    other_admin = create_user(role="admin")
    password_hash = user.password_hash

    assert main(["promote-admin", "lead@example.test", "--yes"]) == 0
    assert _role(db, user) == "admin"
    assert main(["demote-admin", "lead@example.test", "--yes"]) == 0
    assert _role(db, user) == "user"
    assert db.get(User, user.id).password_hash == password_hash  # never touched
    assert _role(db, other_admin) == "admin"


def test_unknown_account_is_refused(capsys):
    assert main(["promote-admin", "nobody@example.test", "--yes"]) == 1
    assert "Register it through the application first" in capsys.readouterr().err


def test_inactive_account_cannot_be_promoted(create_user, db, capsys):
    user = create_user(email="gone@example.test")
    user.is_active = False
    db.commit()
    assert main(["promote-admin", "gone@example.test", "--yes"]) == 1
    assert "inactive" in capsys.readouterr().err
    assert _role(db, user) == "user"


def test_locked_account_cannot_be_promoted(create_user, db, capsys):
    user = create_user(email="locked@example.test")
    user.locked_until = datetime.now(UTC) + timedelta(minutes=10)
    db.commit()
    assert main(["promote-admin", "locked@example.test", "--yes"]) == 1
    assert "locked" in capsys.readouterr().err
    assert _role(db, user) == "user"


def test_expired_lock_does_not_block_promotion(create_user, db):
    user = create_user(email="unlocked@example.test")
    user.locked_until = datetime.now(UTC) - timedelta(minutes=1)
    db.commit()
    assert main(["promote-admin", "unlocked@example.test", "--yes"]) == 0
    assert _role(db, user) == "admin"


def test_last_active_admin_cannot_be_demoted(create_user, db, capsys):
    admin = create_user(role="admin", email="only-admin@example.test")
    assert main(["demote-admin", "only-admin@example.test", "--yes"]) == 1
    assert "last active admin" in capsys.readouterr().err
    assert _role(db, admin) == "admin"


def test_already_admin_is_a_no_op(create_user, capsys):
    create_user(role="admin", email="already@example.test")
    assert main(["promote-admin", "already@example.test"]) == 0
    assert "already has role" in capsys.readouterr().out
