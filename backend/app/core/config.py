"""Application settings, loaded from environment variables (and an optional .env file).

Secrets have no defaults: the backend refuses to start without them.
"""

import base64
import binascii
import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

APP_VERSION = "0.1.0"

BACKEND_DIR = Path(__file__).resolve().parents[2]
# Looked up relative to this file, so it works from any working directory.
# Real environment variables always take precedence over these files.
ENV_FILES = (BACKEND_DIR.parent / ".env", BACKEND_DIR / ".env")


def _require_32_byte_key(value: SecretStr, name: str) -> SecretStr:
    try:
        raw = base64.b64decode(value.get_secret_value(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{name} must be base64-encoded") from exc
    if len(raw) != 32:
        raise ValueError(f"{name} must decode to exactly 32 bytes (got {len(raw)})")
    return value


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=ENV_FILES,
        env_file_encoding="utf-8",
        extra="ignore",
    )

    environment: Literal["development", "test", "production"] = "development"

    # Database
    database_url: str

    # M1 - authentication
    jwt_secret_key: SecretStr = Field(min_length=32)
    jwt_access_token_minutes: int = Field(default=15, ge=1, le=60)
    refresh_token_days: int = Field(default=7, ge=1, le=30)
    argon2_time_cost: int = Field(default=3, ge=1)
    argon2_memory_cost_kib: int = Field(default=65536, ge=8192)
    argon2_parallelism: int = Field(default=4, ge=1)
    max_failed_logins: int = Field(default=5, ge=1)
    lockout_minutes: int = Field(default=15, ge=1)
    # Refresh/CSRF cookies are Secure by default. Browsers accept Secure cookies on
    # http://localhost; set false only for other plain-HTTP development hosts.
    auth_cookie_secure: bool = True
    # Per-client-IP sliding-window limits (in-memory, per process).
    rate_limit_enabled: bool = True
    rate_limit_login_per_minute: int = Field(default=10, ge=1)
    rate_limit_register_per_hour: int = Field(default=20, ge=1)
    rate_limit_refresh_per_minute: int = Field(default=30, ge=1)

    # M2 / M3 - encryption and key management
    master_key_encryption_key: SecretStr
    # Algorithm family for newly created user key pairs (existing keys keep their own):
    # "rsa" = RSA-3072 OAEP/PSS (default), "ecc" = X25519 ECIES + Ed25519.
    default_key_algorithm: Literal["rsa", "ecc"] = "rsa"
    storage_dir: Path = Path("/data/files")
    max_upload_bytes: int = Field(default=25 * 1024 * 1024, ge=1)

    # M6 - audit log
    audit_hmac_key: SecretStr

    # M7 - anomaly detection
    model_dir: Path = Path("/data/models")
    anomaly_contamination: float = Field(default=0.05, gt=0, le=0.5)

    # M8 - LLM analysis (disabled unless explicitly configured)
    # disabled: /analysis returns 503 | fake: deterministic local rules, no network |
    # openai_compatible: POST {llm_base_url}/chat/completions with llm_api_key
    llm_provider: Literal["disabled", "fake", "openai_compatible"] = "disabled"
    llm_api_key: SecretStr | None = None
    llm_model: str = ""
    llm_base_url: str = ""
    llm_timeout_seconds: float = Field(default=20, gt=0, le=120)

    # M10 - transport
    cors_origins: str = "http://localhost:5173"
    # Reject plain-HTTP requests. Always on when ENVIRONMENT=production (https_required).
    # "HTTPS" means uvicorn saw https - directly, or via X-Forwarded-Proto from a proxy
    # listed in uvicorn's --forwarded-allow-ips (FORWARDED_ALLOW_IPS). Never from a client.
    enforce_https: bool = False
    hsts_max_age_seconds: int = Field(default=31536000, ge=0)

    @property
    def https_required(self) -> bool:
        return self.enforce_https or self.environment == "production"

    @field_validator("master_key_encryption_key")
    @classmethod
    def _check_master_key(cls, v: SecretStr) -> SecretStr:
        return _require_32_byte_key(v, "MASTER_KEY_ENCRYPTION_KEY")

    @field_validator("audit_hmac_key")
    @classmethod
    def _check_audit_key(cls, v: SecretStr) -> SecretStr:
        return _require_32_byte_key(v, "AUDIT_HMAC_KEY")

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def llm_enabled(self) -> bool:
        if self.llm_provider == "fake":
            return True
        has_key = self.llm_api_key is not None and bool(self.llm_api_key.get_secret_value())
        return self.llm_provider == "openai_compatible" and has_key and bool(self.llm_base_url)


@lru_cache
def get_settings() -> Settings:
    if os.environ.get("ENVIRONMENT") == "test":
        # Tests must not depend on anyone's personal .env file: environment only.
        return Settings(_env_file=None)  # type: ignore[call-arg]
    return Settings()  # type: ignore[call-arg]  # values come from the environment
