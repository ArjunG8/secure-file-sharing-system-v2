"""Initial schema: tables for all ten modules.

Revision ID: 0001
Revises:
Create Date: 2026-10-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSONType = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
BigIntPK = sa.BigInteger().with_variant(sa.Integer(), "sqlite")
TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    # --- M1 ---------------------------------------------------------------
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("failed_login_count", sa.Integer(), nullable=False),
        sa.Column("locked_until", TS, nullable=True),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.Column("last_login_at", TS, nullable=True),
        sa.CheckConstraint("role IN ('user', 'admin')", name=op.f("ck_users_role")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("email", name=op.f("uq_users_email")),
        sa.UniqueConstraint("username", name=op.f("uq_users_username")),
    )
    op.create_table(
        "auth_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("refresh_token_hash", sa.String(64), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("revoked_at", TS, nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.String(512), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"],
            name=op.f("fk_auth_sessions_user_id_users"), ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_auth_sessions")),
        sa.UniqueConstraint("refresh_token_hash", name=op.f("uq_auth_sessions_refresh_token_hash")),
    )
    op.create_index(op.f("ix_auth_sessions_user_id"), "auth_sessions", ["user_id"])

    # --- M3 ---------------------------------------------------------------
    op.create_table(
        "user_keys",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("purpose", sa.String(16), nullable=False),
        sa.Column("algorithm", sa.String(64), nullable=False),
        sa.Column("public_key_pem", sa.Text(), nullable=False),
        sa.Column("encrypted_private_key", sa.LargeBinary(), nullable=False),
        sa.Column("private_key_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("revoked_at", TS, nullable=True),
        sa.CheckConstraint("purpose IN ('encryption', 'signing')", name=op.f("ck_user_keys_purpose")),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_user_keys_user_id_users"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user_keys")),
        sa.UniqueConstraint("fingerprint", name=op.f("uq_user_keys_fingerprint")),
    )
    op.create_index(op.f("ix_user_keys_user_id"), "user_keys", ["user_id"])
    op.create_index(
        "uq_user_keys_active_purpose",
        "user_keys",
        ["user_id", "purpose"],
        unique=True,
        postgresql_where=sa.text("is_active"),
        sqlite_where=sa.text("is_active = 1"),
    )

    # --- M2 / M4 ----------------------------------------------------------
    op.create_table(
        "files",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("owner_id", sa.Uuid(), nullable=False),
        sa.Column("original_filename", sa.String(255), nullable=False),
        sa.Column("content_type", sa.String(255), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("storage_path", sa.String(512), nullable=False),
        sa.Column("encryption_algorithm", sa.String(32), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        sa.Column("plaintext_sha256", sa.String(64), nullable=False),
        sa.Column("ciphertext_sha256", sa.String(64), nullable=False),
        sa.Column("signature", sa.LargeBinary(), nullable=True),
        sa.Column("signature_algorithm", sa.String(32), nullable=True),
        sa.Column("signing_key_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("deleted_at", TS, nullable=True),
        sa.ForeignKeyConstraint(
            ["owner_id"], ["users.id"], name=op.f("fk_files_owner_id_users"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["signing_key_id"], ["user_keys.id"], name=op.f("fk_files_signing_key_id_user_keys")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_files")),
    )
    op.create_index(op.f("ix_files_owner_id"), "files", ["owner_id"])

    # --- M5 ---------------------------------------------------------------
    op.create_table(
        "file_access_grants",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("file_id", sa.Uuid(), nullable=False),
        sa.Column("grantee_id", sa.Uuid(), nullable=False),
        sa.Column("granted_by_id", sa.Uuid(), nullable=False),
        sa.Column("permission", sa.String(16), nullable=False),
        sa.Column("wrapped_file_key", sa.LargeBinary(), nullable=False),
        sa.Column("wrapping_key_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("expires_at", TS, nullable=True),
        sa.Column("revoked_at", TS, nullable=True),
        sa.Column("max_downloads", sa.Integer(), nullable=True),
        sa.Column("download_count", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "permission IN ('owner', 'read')", name=op.f("ck_file_access_grants_permission")
        ),
        sa.CheckConstraint(
            "max_downloads IS NULL OR max_downloads > 0",
            name=op.f("ck_file_access_grants_max_downloads_positive"),
        ),
        sa.ForeignKeyConstraint(
            ["file_id"], ["files.id"],
            name=op.f("fk_file_access_grants_file_id_files"), ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["grantee_id"], ["users.id"],
            name=op.f("fk_file_access_grants_grantee_id_users"), ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["granted_by_id"], ["users.id"], name=op.f("fk_file_access_grants_granted_by_id_users")
        ),
        sa.ForeignKeyConstraint(
            ["wrapping_key_id"], ["user_keys.id"],
            name=op.f("fk_file_access_grants_wrapping_key_id_user_keys"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_file_access_grants")),
        sa.UniqueConstraint("file_id", "grantee_id", name="uq_file_access_grants_file_grantee"),
    )
    op.create_index(
        op.f("ix_file_access_grants_grantee_id"), "file_access_grants", ["grantee_id"]
    )

    # --- M6 ---------------------------------------------------------------
    op.create_table(
        "audit_logs",
        sa.Column("id", BigIntPK, autoincrement=True, nullable=False),
        sa.Column("occurred_at", TS, nullable=False),
        sa.Column("actor_user_id", sa.Uuid(), nullable=True),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("resource_type", sa.String(32), nullable=True),
        sa.Column("resource_id", sa.String(64), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.String(512), nullable=True),
        sa.Column("details", JSONType, nullable=False),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("entry_hash", sa.String(64), nullable=False),
        sa.CheckConstraint(
            "outcome IN ('success', 'failure', 'denied')", name=op.f("ck_audit_logs_outcome")
        ),
        sa.ForeignKeyConstraint(
            ["actor_user_id"], ["users.id"],
            name=op.f("fk_audit_logs_actor_user_id_users"), ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_logs")),
        sa.UniqueConstraint("entry_hash", name=op.f("uq_audit_logs_entry_hash")),
    )
    op.create_index(op.f("ix_audit_logs_actor_user_id"), "audit_logs", ["actor_user_id"])
    op.create_index(op.f("ix_audit_logs_event_type"), "audit_logs", ["event_type"])

    # --- M7 ---------------------------------------------------------------
    op.create_table(
        "anomaly_detections",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("audit_log_id", sa.BigInteger(), nullable=True),
        sa.Column("window_start", TS, nullable=False),
        sa.Column("window_end", TS, nullable=False),
        sa.Column("features", JSONType, nullable=False),
        sa.Column("score", sa.Double(), nullable=False),
        sa.Column("is_anomaly", sa.Boolean(), nullable=False),
        sa.Column("model_version", sa.String(64), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"],
            name=op.f("fk_anomaly_detections_user_id_users"), ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["audit_log_id"], ["audit_logs.id"],
            name=op.f("fk_anomaly_detections_audit_log_id_audit_logs"), ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_anomaly_detections")),
    )
    op.create_index(op.f("ix_anomaly_detections_user_id"), "anomaly_detections", ["user_id"])

    # --- M8 ---------------------------------------------------------------
    op.create_table(
        "security_analyses",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("requested_by_id", sa.Uuid(), nullable=True),
        sa.Column("scope", JSONType, nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("model", sa.String(128), nullable=False),
        sa.Column("prompt_sha256", sa.String(64), nullable=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("findings", JSONType, nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("completed_at", TS, nullable=True),
        sa.CheckConstraint(
            "status IN ('pending', 'completed', 'failed')", name=op.f("ck_security_analyses_status")
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_id"], ["users.id"],
            name=op.f("fk_security_analyses_requested_by_id_users"), ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_security_analyses")),
    )

    # --- M9 ---------------------------------------------------------------
    op.create_table(
        "verification_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("requested_by_id", sa.Uuid(), nullable=True),
        sa.Column("target_type", sa.String(16), nullable=False),
        sa.Column("target_id", sa.String(64), nullable=True),
        sa.Column("passed", sa.Boolean(), nullable=False),
        sa.Column("checks", JSONType, nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.CheckConstraint(
            "target_type IN ('file', 'audit_chain', 'system')",
            name=op.f("ck_verification_runs_target_type"),
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_id"], ["users.id"],
            name=op.f("fk_verification_runs_requested_by_id_users"), ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_verification_runs")),
    )


def downgrade() -> None:
    op.drop_table("verification_runs")
    op.drop_table("security_analyses")
    op.drop_index(op.f("ix_anomaly_detections_user_id"), table_name="anomaly_detections")
    op.drop_table("anomaly_detections")
    op.drop_index(op.f("ix_audit_logs_event_type"), table_name="audit_logs")
    op.drop_index(op.f("ix_audit_logs_actor_user_id"), table_name="audit_logs")
    op.drop_table("audit_logs")
    op.drop_index(op.f("ix_file_access_grants_grantee_id"), table_name="file_access_grants")
    op.drop_table("file_access_grants")
    op.drop_index(op.f("ix_files_owner_id"), table_name="files")
    op.drop_table("files")
    op.drop_index("uq_user_keys_active_purpose", table_name="user_keys")
    op.drop_index(op.f("ix_user_keys_user_id"), table_name="user_keys")
    op.drop_table("user_keys")
    op.drop_index(op.f("ix_auth_sessions_user_id"), table_name="auth_sessions")
    op.drop_table("auth_sessions")
    op.drop_table("users")
