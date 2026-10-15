# Module Ownership

Fill in the **Member** column with real names and GitHub usernames, then
update `.github/CODEOWNERS` to match (replace every `@TODO-mN`). Don't guess
usernames: a wrong CODEOWNERS entry silently stops review requests. The **Lead**
(repository owner) owns the shared files and reviews every PR that touches them.

| # | Module | Member | GitHub | Branch prefix |
|---|---|---|---|---|
| L | Integration lead (shared files) | _TBD_ (repo owner) | @ArjunG8 | `chore/` |
| 1 | Authentication & Argon2id | _TBD_ | | `m1/` |
| 2 | AES-256-GCM file encryption | _TBD_ | | `m2/` |
| 3 | RSA-OAEP key management | _TBD_ | | `m3/` |
| 4 | RSA-PSS digital signatures | _TBD_ | | `m4/` |
| 5 | Secure sharing & access control | _TBD_ | | `m5/` |
| 6 | Tamper-evident audit logging | _TBD_ | | `m6/` |
| 7 | Isolation Forest anomaly detection | _TBD_ | | `m7/` |
| 8 | LLM security event analysis | _TBD_ | | `m8/` |
| 9 | Crypto verification & attack testing | _TBD_ | | `m9/` |
| 10 | HTTPS/TLS & transport security | _TBD_ | | `m10/` |

(The Lead can also be one of the ten module members.)

## Exact file ownership

A member may freely edit files they own. Editing someone else's file requires
their approving review. **Lead files are shared integration points, and every
change to them needs the Lead's approval.** Change them in small PRs.

### Shared (Lead approval required)
```
backend/app/main.py, backend/app/cli.py
backend/app/core/*         (config.py, database.py [DbSession, session_scope, audit queue],
                            errors.py, modules.py)
backend/app/api/router.py
backend/app/schemas/common.py              (incl. NormalizedEmail / normalize_email)
backend/app/models/__init__.py, backend/app/models/base.py
backend/alembic/env.py, backend/alembic.ini,
  backend/alembic/versions/0001_initial_schema.py, 0002_normalize_user_emails.py
backend/tests/conftest.py, helpers.py, test_health.py, test_api_contract.py,
  test_migrations.py, test_models.py, test_config.py, test_database.py, test_cli.py,
  test_audit_transactions.py, test_test_safety.py, test_not_implemented.py
backend/requirements*.txt, backend/pyproject.toml, backend/Dockerfile
frontend/src/main.jsx, App.jsx, routes.jsx, index.css, api/client.js, components/**,
  features/status/**
frontend/package.json, vite.config.js, frontend/Dockerfile
docker-compose.yml, .env.example, .gitignore, .gitattributes, README.md, docs/**, .github/**
```

### Shared files everyone edits: rules

| File | Rule |
|---|---|
| `backend/tests/test_not_implemented.py` | Each member edits **only their own `STUBBED["Mn"]` block**. Separate blocks merge without conflicts |
| `backend/alembic/versions/` | One linear chain. Rebase on `develop` and check `alembic heads` before every PR |
| `backend/app/models/file.py` | M2 owns it; M4 owns the signature columns. Both approve every change |
| `backend/app/core/config.py` + `.env.example` | A new setting goes in both files in the same small PR; Lead reviews |
| `docs/api-contracts.md` + `tests/test_api_contract.py` | Change both in the same PR as the endpoint |
| `requirements.txt`, `package.json`, `package-lock.json` | Any member may add a dependency: a one-line PR plus the lockfile. On a lockfile conflict, re-run `npm install` instead of hand-merging |
| `frontend/src/api/client.js` | Lead owns it. M1 proposes the token-refresh change and the Lead reviews it |
| Any public `service.py` signature | The owner may change it only with the Lead's approval and every consumer named on the module card |
| `app/modules/audit/service.py` `record_event` | M6 owns the file, but `record_event`'s queueing behaviour is part of the transaction rule: changing it needs Lead approval |

### Per module

| # | Backend | Model file(s) | Frontend | Tests |
|---|---|---|---|---|
| 1 | `app/modules/auth/**`, `app/api/deps.py` | `models/user.py` (`User`, `AuthSession`) | `features/auth/**`, `context/AuthContext.jsx` | `tests/modules/test_auth.py` |
| 2 | `app/modules/encryption/**` | `models/file.py` (except signature columns) | `features/files/**` | `tests/modules/test_encryption.py` |
| 3 | `app/modules/keys/**` | `models/key.py` (`UserKey`) | `features/keys/**` | `tests/modules/test_keys.py` |
| 4 | `app/modules/signatures/**` | `models/file.py` columns `signature`, `signature_algorithm`, `signing_key_id` | `features/signatures/**` | `tests/modules/test_signatures.py` |
| 5 | `app/modules/sharing/**` | `models/share.py` (`FileAccessGrant`) | `features/sharing/**` | `tests/modules/test_sharing.py` |
| 6 | `app/modules/audit/**` | `models/audit.py` (`AuditLog`) | `features/audit/**` | `tests/modules/test_audit.py` |
| 7 | `app/modules/anomaly/**` | `models/anomaly.py` (`AnomalyDetection`) | `features/anomaly/**` | `tests/modules/test_anomaly.py` |
| 8 | `app/modules/llm_analysis/**` | `models/analysis.py` (`SecurityAnalysis`) | `features/analysis/**` | `tests/modules/test_llm_analysis.py` |
| 9 | `app/modules/verification/**` | `models/verification.py` (`VerificationRun`) | `features/verification/**` | `tests/security/**`, `tests/modules/test_verification.py` |
| 10 | `app/modules/transport/**`, `infra/nginx/**`, `scripts/gen-dev-certs.sh` | – | `features/transport/**` | `tests/modules/test_transport.py` |

Each member also owns any Alembic migration they add for their tables
(`alembic/versions/NNNN_mX_<description>.py`).

## Module cards

Each card lists what the module **owns**, what it **provides** to others (inputs →
outputs), what it **depends on**, what it **must test**, and when it is **done**.
Exact signatures are in each `service.py`, and endpoints in `api-contracts.md`. All
modules also follow the general definition of done in
[team-start-guide.md §6](team-start-guide.md#6-definition-of-done).

**M1 — Authentication & Argon2id**
- Owns: `modules/auth/**`, `api/deps.py`, `models/user.py`, `features/auth/**`, `context/AuthContext.jsx`.
- Provides: `hash_password(pw)→PHC str`, `verify_password(pw, hash)→bool`,
  `register_user(db, RegisterRequest)→User`, `authenticate(...)→TokenPair`, and the
  `get_current_user` / `require_admin` dependencies every router uses.
- Depends on: M3 `ensure_user_keys` at registration (mock it until M3 merges); M6 events.
- Must test: Argon2id parameters and rehash, lockout after N failures (423),
  no user enumeration, expired JWT / wrong secret / `alg=none` rejected, refresh rotation,
  registration and login with mixed-case emails.
- Done when: all `/auth/*` endpoints work, `get_current_user` returns 401 (not 501), and the M1 block in `test_not_implemented.py` is removed.

**M2 — AES-256-GCM files (owns the upload/download flow)**
- Owns: `modules/encryption/**`, `models/file.py` (except the signature columns), `features/files/**`.
- Provides: `encrypt_bytes(plaintext, aad)→EncryptedPayload`,
  `decrypt_bytes(ct, nonce, key, aad)→bytes` (502 on tag failure), blob storage, and the
  `/files` endpoints.
- Depends on: M1 auth; M3 wrap/unwrap; M4 sign/verify; M5 owner grant and `require_access`; M6 events.
- Transaction duty: upload and download each run as **one** request transaction
  (`DbSession`). Write the blob before the DB commit, and delete it if the request fails.
  Download returns the full decrypted bytes (`Response`), never a stream that uses the session.
- Must test: round trip, a tampered ciphertext byte, a wrong nonce, AAD swap
  (blob moved to another file id), 413 for oversized files, path traversal in filenames.
- Done when: upload → download round-trips through M3, M4 and M5, and integrity failures return 502 and are audited.

**M3 — RSA-OAEP key management**
- Owns: `modules/keys/**`, `models/key.py`, `features/keys/**`.
- Provides: `ensure_user_keys`, `get_active_key`, `wrap_key_for_user(db, user_id, file_key)→WrappedKey`,
  `unwrap_key_for_user(...)→bytes`, `load_private_key`, `rotate_keys`, and the `/keys` endpoints.
- Depends on: M1 (current user), the master KEK from config, M6 events.
- Must test: wrap/unwrap round trip, another user's key fails, rotation keeps old
  grants readable, private keys never appear in any response, private keys stored encrypted under the KEK.
- Done when: M2, M4 and M5 can use these functions without mocks.

**M4 — RSA-PSS signatures**
- Owns: `modules/signatures/**`, the signature columns of `models/file.py`, `features/signatures/**`.
- Provides: `build_manifest(file)→bytes`, `sign_manifest(db, user_id, manifest)→SignatureResult`,
  `verify_manifest(db, file)→bool`, and the `/signatures` endpoints.
- Depends on: M3 signing keys, M2 file metadata, M5 access checks for its endpoints.
- Must test: a valid signature passes; changing any manifest field fails; a signature from another key fails; verification still works after key rotation.
- Done when: M2 signs on upload and verifies on download.

**M5 — Sharing & access control**
- Owns: `modules/sharing/**`, `models/share.py`, `features/sharing/**`.
- Provides: `create_owner_grant`, `require_access(db, user_id, file_id, permission)→grant`
  (default deny, 404), `share_file`, `revoke_share`, `record_download`, and the `/shares` endpoints.
- Depends on: M1, M3 (re-wrapping for the recipient), M2 file metadata, M6 events.
- Transaction duty: record `share.access_denied` (outcome `denied`) **before** raising
  404. The download counter changes only inside the download's request transaction.
- Must test: IDOR (another user's file id → 404), expired, revoked and max-downloads grants,
  recipients can't re-share, cascade on file delete.
- Done when: share → recipient download → revoke works end to end.

**M6 — Tamper-evident audit log**
- Owns: `modules/audit/**` (but see the `record_event` rule above), `models/audit.py`, `features/audit/**`.
- Provides: `record_event(db, AuditEventIn)` (queues; already implemented),
  `append_entries(db, events)` (to implement), `verify_chain(db)→ChainVerification`, and the `/audit` endpoints.
- Depends on: `AUDIT_HMAC_KEY`; it is called by `app.core.database` at the end of each transaction.
- Transaction duty: `append_entries` takes the chain lock first, never commits or rolls back, and raises on error.
- Must test: the HMAC chain; an edited row breaks verification; a deleted row breaks it;
  concurrent appends on PostgreSQL (extend `tests/test_audit_transactions.py`);
  admins see all events while users see only their own.
- Done when: the "NOT recorded" warning is gone and `/audit/verify` detects tampering.

**M7 — Isolation Forest anomaly detection**
- Owns: `modules/anomaly/**`, `models/anomaly.py`, `features/anomaly/**`.
- Provides: `extract_features(events)→list[dict]`, `train_model`, `score_recent`, and the `/anomaly` endpoints.
- Depends on: M6 audit data (use synthetic events until then), `MODEL_DIR`.
- Must test: feature extraction on known events; anomalies flagged on a labelled
  synthetic set (report precision and recall honestly); the model is saved and reloaded.
- Done when: train and score work on real audit data and detections are stored.

**M8 — LLM security analysis**
- Owns: `modules/llm_analysis/**`, `models/analysis.py`, `features/analysis/**`.
- Provides: `redact(event)→dict`, `analyze(db, user_id, AnalysisRequest)→SecurityAnalysis`, and the `/analysis` endpoints.
- Depends on: M6 events, M7 detections, `LLM_PROVIDER` / `LLM_API_KEY` / `LLM_MODEL`.
- Must test: redaction removes emails, IPs, user agents and ids; 503 when the provider is
  disabled; prompt-injection text inside events is treated as data; the response is
  schema-validated. **Tests use a fake provider**: CI needs no API key, and no LLM SDK is added by default.
- Done when: analysis works with a configured provider and returns an honest 503 without one.

**M9 — Verification & attack testing**
- Owns: `modules/verification/**`, `models/verification.py`, `tests/security/**`, `features/verification/**`.
- Provides: `verify_file`, `verify_audit_chain`, the `/verification` endpoints, and the attack-test suite.
- Depends on: M2, M3, M4 and M6 functions (call them; don't reimplement them).
- Must test: every scenario in `tests/security/test_attacks.py`, each enabled as its feature lands.
- Done when: no attack test is skipped and the results are written up for the report.

**M10 — HTTPS/TLS & transport security**
- Owns: `modules/transport/**`, `infra/nginx/**`, `scripts/gen-dev-certs.sh`, `features/transport/**`.
- Provides: `install_transport_security(app, settings)` (security headers and HTTPS
  enforcement), `/transport/status`, and the TLS proxy.
- Depends on: nothing at the start; the full stack for the end-to-end check.
- Must test: security headers present, HTTP→HTTPS redirect, HSTS, a production request
  without `X-Forwarded-Proto: https` rejected, TLS 1.0/1.1 refused (documented manual check).
- Done when: `docker compose --profile tls up` has been verified on a machine with Docker, and the missing-middleware warning is gone.

## Dependencies between tasks

```
            ┌──────────── M10 (independent; integrate last) ───────────┐
            │                                                          │
 M6 audit ──┼──▶ everyone calls record_event (stub-safe from day 1)    │
            │                                                          │
 M1 auth ───┼──▶ get_current_user ──▶ M2, M3, M4, M5, M6, M7, M8, M9   │
            │                                                          │
 M3 keys ───┼──▶ wrap/unwrap ──▶ M2 upload/download, M5 sharing        │
            │      └─▶ signing keys ──▶ M4                             │
 M2 enc ────┼──▶ encrypt/decrypt ──▶ M5, M9                            │
 M4 sig ────┼──▶ sign/verify ──▶ M2 download, M9                       │
 M5 share ──┼──▶ require_access ──▶ M2 download/list, M4, M9           │
 M6 audit ──┴──▶ events ──▶ M7 features ──▶ M8 analysis                │
                                     M9 tests everything ◀─────────────┘
```

### Suggested schedule (adjust to your deadline)

| Phase | Work | Can start immediately? |
|---|---|---|
| Week 1 | **M1** hashing + register/login; **M3** keygen/wrap/unwrap (pure functions + unit tests); **M2** `encrypt_bytes`/`decrypt_bytes` (pure); **M4** sign/verify (pure); **M6** `append_entries` (HMAC chain + lock) + `verify_chain`; **M10** nginx + certs + headers middleware; **M7** feature extraction on synthetic data; **M8** redaction + prompt builder (provider disabled); **M9** write failing/`skip` attack tests from the spec | Yes — all pure-crypto work needs no other module |
| Week 2 | M1 `get_current_user` merged ⇒ M2 upload/download endpoints using M3+M4; M5 grants + `require_access`; M6 `/audit` endpoints | After M1 + M3 |
| Week 3 | M5 sharing endpoints; M7 trains on real audit data; M8 analysis over audit + anomalies; M9 enables attack tests as features land | After M2, M5, M6 |
| Week 4 | Frontend pages for every module, end-to-end run via `docker compose --profile tls up`, report | — |

**Unblocking rule:** if you need another module's function before it is
merged, code against its `service.py` signature and mock it in your tests
(`monkeypatch.setattr(...)`). Do not write your own copy of their logic.
