import base64
import os
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.config import Settings

REPO_ROOT = Path(__file__).resolve().parents[2]
SECRET_VARS = (
    "POSTGRES_PASSWORD",
    "JWT_SECRET_KEY",
    "MASTER_KEY_ENCRYPTION_KEY",
    "AUDIT_HMAC_KEY",
    "LLM_API_KEY",
)


def _valid_kwargs() -> dict:
    return {
        "database_url": "sqlite://",
        "jwt_secret_key": "a" * 48,
        "master_key_encryption_key": base64.b64encode(os.urandom(32)).decode(),
        "audit_hmac_key": base64.b64encode(os.urandom(32)).decode(),
    }


def _settings(monkeypatch, **overrides) -> Settings:
    for var in ("JWT_SECRET_KEY", "MASTER_KEY_ENCRYPTION_KEY", "AUDIT_HMAC_KEY", "DATABASE_URL"):
        monkeypatch.delenv(var, raising=False)
    return Settings(_env_file=None, **{**_valid_kwargs(), **overrides})


def test_valid_settings_load(monkeypatch):
    s = _settings(monkeypatch)
    assert s.llm_enabled is False


@pytest.mark.parametrize("missing", ["jwt_secret_key", "master_key_encryption_key", "audit_hmac_key"])
def test_missing_secret_is_rejected(monkeypatch, missing):
    for var in ("JWT_SECRET_KEY", "MASTER_KEY_ENCRYPTION_KEY", "AUDIT_HMAC_KEY", "DATABASE_URL"):
        monkeypatch.delenv(var, raising=False)
    kwargs = _valid_kwargs()
    del kwargs[missing]
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **kwargs)


def test_short_jwt_secret_is_rejected(monkeypatch):
    with pytest.raises(ValidationError):
        _settings(monkeypatch, jwt_secret_key="short")


@pytest.mark.parametrize("bad", ["not base64!!", base64.b64encode(b"16-bytes-only!!!").decode()])
def test_master_key_must_be_32_bytes_base64(monkeypatch, bad):
    with pytest.raises(ValidationError):
        _settings(monkeypatch, master_key_encryption_key=bad)


def test_env_example_contains_no_secret_values():
    text = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
    for var in SECRET_VARS:
        match = re.search(rf"^{var}=(.*)$", text, re.MULTILINE)
        assert match, f"{var} should be documented in .env.example"
        assert match.group(1).strip() == "", f"{var} must be empty in .env.example"
