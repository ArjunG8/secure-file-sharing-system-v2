"""Alembic history must be linear and match the SQLAlchemy models exactly."""

from pathlib import Path

import pytest
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError

from alembic import command
from app.models import Base

BACKEND_DIR = Path(__file__).resolve().parents[1]


@pytest.fixture
def alembic_cfg(tmp_path):
    db_url = f"sqlite:///{(tmp_path / 'migrations.db').as_posix()}"
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    cfg.attributes["configure_logger"] = False
    return cfg, db_url


def test_single_migration_head(alembic_cfg):
    cfg, _ = alembic_cfg
    heads = ScriptDirectory.from_config(cfg).get_heads()
    assert len(heads) == 1, f"Multiple Alembic heads {heads}: rebase and fix down_revision"


def test_upgrade_matches_models_and_downgrade_cleans_up(alembic_cfg):
    cfg, db_url = alembic_cfg
    command.upgrade(cfg, "head")

    engine = create_engine(db_url)
    with engine.connect() as conn:
        ctx = MigrationContext.configure(conn, opts={"compare_type": True})
        diff = compare_metadata(ctx, Base.metadata)
    assert diff == [], f"Models and migrations differ; add a migration: {diff}"

    command.downgrade(cfg, "base")
    assert set(inspect(engine).get_table_names()) <= {"alembic_version"}
    engine.dispose()


def _insert_raw_users(db_url: str, emails: list[str]) -> None:
    # Core insert: bypasses the ORM normalizer, like data written before migration 0002.
    from datetime import UTC, datetime
    from uuid import uuid4

    from app.models import User

    now = datetime.now(UTC)
    rows = [
        {
            "id": uuid4(),
            "email": email,
            "username": f"user{i}",
            "password_hash": "placeholder-not-an-argon2-hash",
            "role": "user",
            "is_active": True,
            "failed_login_count": 0,
            "created_at": now,
            "updated_at": now,
        }
        for i, email in enumerate(emails)
    ]
    engine = create_engine(db_url)
    with engine.begin() as conn:
        conn.execute(User.__table__.insert(), rows)
    engine.dispose()


def _emails(db_url: str) -> list[str]:
    engine = create_engine(db_url)
    with engine.connect() as conn:
        result = sorted(r[0] for r in conn.execute(text("SELECT email FROM users")))
    engine.dispose()
    return result


def test_0002_normalizes_existing_emails_and_enforces_it(alembic_cfg):
    cfg, db_url = alembic_cfg
    command.upgrade(cfg, "0001")
    _insert_raw_users(db_url, ["  Alice@Example.TEST", "bob@example.test"])

    command.upgrade(cfg, "0002")
    assert _emails(db_url) == ["alice@example.test", "bob@example.test"]

    with pytest.raises(IntegrityError):  # CHECK ck_users_email_normalized
        _insert_raw_users(db_url, ["Carol@Example.test"])

    command.downgrade(cfg, "0001")  # reversible; emails stay normalized
    assert _emails(db_url) == ["alice@example.test", "bob@example.test"]


def test_0002_refuses_case_only_duplicates_without_changing_data(alembic_cfg):
    cfg, db_url = alembic_cfg
    command.upgrade(cfg, "0001")
    _insert_raw_users(db_url, ["Dup@Example.test", "dup@example.test"])

    with pytest.raises(RuntimeError, match="differ only by case"):
        command.upgrade(cfg, "0002")
    assert _emails(db_url) == ["Dup@Example.test", "dup@example.test"]
    assert ScriptDirectory.from_config(cfg).get_current_head() == "0002"
    engine = create_engine(db_url)
    with engine.connect() as conn:
        assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar() == "0001"
    engine.dispose()
