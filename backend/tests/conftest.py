"""Shared fixtures. Secrets are generated randomly per test run - never hardcoded.

By default tests use in-memory SQLite. Set TEST_DATABASE_URL to run against PostgreSQL;
the database NAME must contain "test", because every row is deleted after each test.
Personal .env files are ignored in tests (ENVIRONMENT=test), and files go to a temporary
directory that is removed at the end of the run.
"""

import base64
import os
import secrets
import shutil
import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path

# Configure the environment BEFORE any app module reads settings.
_PERSONAL_DATABASE_URL = os.environ.get("DATABASE_URL", "")
_TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "sqlite+pysqlite:///:memory:")
_TMP_ROOT = Path(tempfile.mkdtemp(prefix="sfs-tests-"))

os.environ["ENVIRONMENT"] = "test"
os.environ["DATABASE_URL"] = _TEST_DATABASE_URL
os.environ["STORAGE_DIR"] = str(_TMP_ROOT / "files")
os.environ["MODEL_DIR"] = str(_TMP_ROOT / "models")
os.environ["JWT_SECRET_KEY"] = secrets.token_urlsafe(48)
os.environ["MASTER_KEY_ENCRYPTION_KEY"] = base64.b64encode(os.urandom(32)).decode()
os.environ["AUDIT_HMAC_KEY"] = base64.b64encode(os.urandom(32)).decode()
os.environ["LLM_PROVIDER"] = "disabled"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.api.deps import get_current_user  # noqa: E402
from app.core.config import get_settings  # noqa: E402
from app.core.database import get_engine, get_sessionmaker  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import Base, User  # noqa: E402
from tests.helpers import make_user, unsafe_test_database_reason  # noqa: E402

_unsafe = unsafe_test_database_reason(_TEST_DATABASE_URL, (_PERSONAL_DATABASE_URL,))
if _unsafe:
    shutil.rmtree(_TMP_ROOT, ignore_errors=True)
    raise pytest.UsageError(
        f"Refusing to run: TEST_DATABASE_URL is unsafe ({_unsafe}). The test suite deletes "
        "every row; point it at a dedicated database such as securefiles_test."
    )

get_settings.cache_clear()
get_engine.cache_clear()
get_sessionmaker.cache_clear()


@pytest.fixture(scope="session", autouse=True)
def _schema() -> Iterator[None]:
    engine = get_engine()
    Base.metadata.create_all(engine)
    yield
    Base.metadata.drop_all(engine)
    shutil.rmtree(_TMP_ROOT, ignore_errors=True)


@pytest.fixture(autouse=True)
def _clean_tables() -> Iterator[None]:
    """Empty every table after each test so tests never depend on each other's data."""
    yield
    with get_engine().begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            conn.execute(table.delete())


@pytest.fixture
def db() -> Iterator[Session]:
    session = get_sessionmaker()()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def app():
    return create_app()


@pytest.fixture
def client(app) -> Iterator[TestClient]:
    with TestClient(app) as c:
        yield c


@pytest.fixture
def create_user(db: Session) -> Callable[..., User]:
    """Persist a user: `alice = create_user()`, `admin = create_user(role="admin")`."""

    def _create(role: str = "user", email: str | None = None) -> User:
        user = make_user(role=role, email=email)
        db.add(user)
        db.commit()
        return user

    return _create


@pytest.fixture
def client_as(app, client) -> Iterator[Callable[[User], TestClient]]:
    """Act as a given user without M1: `client_as(alice).get("/api/v1/files")`.

    Overrides get_current_user, so it skips token checks entirely. Use real tokens
    (once M1 exists) for tests that are about authentication itself.
    """

    def _as(user: User) -> TestClient:
        app.dependency_overrides[get_current_user] = lambda: user
        return client

    yield _as
    app.dependency_overrides.pop(get_current_user, None)
