"""The test suite itself must be safe: no personal .env, no real directories, no real DBs."""

import tempfile
from pathlib import Path

import pytest

from app.core import config
from app.core.config import Settings, get_settings
from tests.helpers import unsafe_test_database_reason


def test_personal_env_file_is_ignored_in_tests(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("ENFORCE_HTTPS=true\nCORS_ORIGINS=https://evil.example\n")
    monkeypatch.setitem(Settings.model_config, "env_file", (str(env_file),))

    # Control: outside test mode the same file WOULD be read.
    assert Settings().enforce_https is True

    config.get_settings.cache_clear()
    try:
        settings = get_settings()
        assert settings.enforce_https is False
        assert "evil" not in settings.cors_origins
    finally:
        config.get_settings.cache_clear()


def test_storage_and_model_dirs_are_temporary():
    settings = get_settings()
    tmp = Path(tempfile.gettempdir()).resolve()
    for directory in (settings.storage_dir, settings.model_dir):
        assert tmp in directory.resolve().parents, directory
        assert "sfs-tests-" in str(directory)


@pytest.mark.parametrize(
    "url",
    [
        "sqlite+pysqlite:///:memory:",
        "sqlite:///some/file.db",
        "postgresql+psycopg://ci@localhost:5432/securefiles_test",
        "postgresql+psycopg://u:p@db:5432/test_sfs",
    ],
)
def test_safe_test_databases_are_allowed(url):
    assert unsafe_test_database_reason(url) is None


@pytest.mark.parametrize(
    "url",
    [
        "postgresql+psycopg://u:p@localhost:5432/securefiles",
        "postgresql+psycopg://u:p@localhost:5432/postgres",
        "postgresql+psycopg://u:p@localhost:5432/",
    ],
)
def test_databases_without_test_in_the_name_are_refused(url):
    assert "does not contain 'test'" in unsafe_test_database_reason(url)


def test_the_development_database_is_refused_even_if_named_test():
    url = "postgresql+psycopg://u:p@localhost:5432/my_test_db"
    assert unsafe_test_database_reason(url, (url,)) == "it is the same database as DATABASE_URL"
