"""Attack and negative tests. Owner: M9.

Each test is skipped until the modules it exercises exist. Replace the skip with a
real test as features land; a skipped test is NOT a passing security control.
"""

import pytest

pending = pytest.mark.skip


@pending(reason="M9 pending: needs M2 (AES-256-GCM)")
def test_tampered_ciphertext_byte_fails_gcm_tag(): ...


@pending(reason="M9 pending: needs M2 (AES-256-GCM)")
def test_ciphertext_moved_to_other_file_fails_aad_check(): ...


@pending(reason="M9 pending: needs M2 (AES-256-GCM)")
def test_modified_nonce_fails_decryption(): ...


@pending(reason="M9 pending: needs M4 (RSA-PSS)")
def test_modified_manifest_fails_signature(): ...


@pending(reason="M9 pending: needs M4 (RSA-PSS)")
def test_signature_from_other_user_key_is_rejected(): ...


@pending(reason="M9 pending: needs M3 (RSA-OAEP)")
def test_wrong_private_key_cannot_unwrap_file_key(): ...


@pending(reason="M9 pending: needs M5 (access control)")
def test_idor_on_other_users_file_returns_404(): ...


@pending(reason="M9 pending: needs M5 (access control)")
def test_expired_or_revoked_share_denies_download(): ...


@pending(reason="M9 pending: needs M6 (audit chain)")
def test_edited_audit_row_breaks_chain(): ...


@pending(reason="M9 pending: needs M6 (audit chain)")
def test_deleted_audit_row_breaks_chain(): ...


@pending(reason="M9 pending: needs M1 (JWT)")
def test_jwt_alg_none_and_wrong_secret_rejected(): ...


@pending(reason="M9 pending: needs M1 (login)")
def test_sql_injection_strings_in_login_are_harmless(): ...


@pending(reason="M9 pending: needs M1 (lockout)")
def test_bruteforce_login_triggers_lockout(): ...


@pending(reason="M9 pending: needs M2 (upload limits)")
def test_oversized_upload_returns_413(): ...
