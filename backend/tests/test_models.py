from app.models import Base

EXPECTED_TABLES = {
    "users",
    "auth_sessions",
    "user_keys",
    "files",
    "file_access_grants",
    "audit_logs",
    "anomaly_detections",
    "security_analyses",
    "verification_runs",
}


def _fk_targets(table_name: str) -> set[str]:
    table = Base.metadata.tables[table_name]
    return {f"{fk.column.table.name}.{fk.column.name}" for fk in table.foreign_keys}


def test_single_shared_schema_has_all_tables():
    assert set(Base.metadata.tables) == EXPECTED_TABLES


def test_relationships():
    assert _fk_targets("auth_sessions") == {"users.id"}
    assert _fk_targets("user_keys") == {"users.id"}
    assert _fk_targets("files") == {"users.id", "user_keys.id"}
    assert _fk_targets("file_access_grants") == {"files.id", "users.id", "user_keys.id"}
    assert _fk_targets("audit_logs") == {"users.id"}
    assert _fk_targets("anomaly_detections") == {"users.id", "audit_logs.id"}


def test_secrets_are_never_stored_in_plaintext_columns():
    users = Base.metadata.tables["users"].columns
    assert "password" not in users and "password_hash" in users
    keys = Base.metadata.tables["user_keys"].columns
    assert "private_key" not in keys and "encrypted_private_key" in keys
    files = Base.metadata.tables["files"].columns
    assert "file_key" not in files and "content" not in files
    sessions = Base.metadata.tables["auth_sessions"].columns
    assert "refresh_token" not in sessions and "refresh_token_hash" in sessions


def test_one_grant_per_user_per_file():
    table = Base.metadata.tables["file_access_grants"]
    uniques = [
        {c.name for c in con.columns}
        for con in table.constraints
        if con.__class__.__name__ == "UniqueConstraint"
    ]
    assert {"file_id", "grantee_id"} in uniques


def test_audit_entry_hashes_are_unique():
    assert Base.metadata.tables["audit_logs"].c.entry_hash.unique
