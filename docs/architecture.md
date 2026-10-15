# Architecture

Secure File Sharing System is **one** web application: one React frontend,
one FastAPI backend, one PostgreSQL database. The ten security modules are
packages *inside* that application, not separate services.

```
                 ┌────────────────────────────────────────────┐
  Browser ──TLS──▶  nginx reverse proxy (M10, infra/nginx)    │
                 └───────┬───────────────────────┬────────────┘
                         │ /                     │ /api
                 ┌───────▼────────┐      ┌───────▼──────────────────────────┐
                 │ React + Vite   │      │ FastAPI  (backend/app)           │
                 │ (frontend/)    │      │  core/   config, db, errors      │
                 │  features/<m>  │      │  api/    router, auth deps       │
                 └────────────────┘      │  modules/<m>/ router+service     │
                                         │  models/ SQLAlchemy tables       │
                                         └───────┬───────────────┬──────────┘
                                                 │               │
                                         ┌───────▼──────┐ ┌──────▼─────────┐
                                         │ PostgreSQL   │ │ Encrypted blob │
                                         │ (metadata,   │ │ storage volume │
                                         │ keys, audit) │ │ (STORAGE_DIR)  │
                                         └──────────────┘ └────────────────┘
```

## 1. Repository structure

```
secure-file-sharing-system-v2/
├── backend/
│   ├── app/
│   │   ├── main.py                 # create_app(): mounts all module routers   [Lead]
│   │   ├── core/
│   │   │   ├── config.py           # Settings (env vars, secrets)              [Lead]
│   │   │   ├── database.py         # engine, SessionLocal, get_db              [Lead]
│   │   │   ├── errors.py           # error envelope, NotImplementedFeature     [Lead]
│   │   │   └── modules.py          # ModuleInfo + registry                     [Lead]
│   │   ├── api/
│   │   │   ├── router.py           # /api/v1 aggregation, /health, /modules    [Lead]
│   │   │   └── deps.py             # get_current_user, require_admin           [M1]
│   │   ├── schemas/common.py       # shared Pydantic schemas                   [Lead]
│   │   ├── models/                 # one file per owning module                [see ownership]
│   │   └── modules/
│   │       ├── auth/               # M1  Argon2id, JWT sessions
│   │       ├── encryption/         # M2  AES-256-GCM, file upload/download
│   │       ├── keys/               # M3  RSA-OAEP key management
│   │       ├── signatures/         # M4  RSA-PSS signatures
│   │       ├── sharing/            # M5  shares and access control
│   │       ├── audit/              # M6  HMAC hash-chained audit log
│   │       ├── anomaly/            # M7  Isolation Forest
│   │       ├── llm_analysis/       # M8  LLM security event analysis
│   │       ├── verification/       # M9  crypto verification endpoints
│   │       └── transport/          # M10 security headers, HTTPS enforcement
│   ├── alembic/                    # ONE linear migration history
│   ├── tests/                      # pytest + httpx; tests/security/ is M9's
│   ├── requirements.txt / requirements-dev.txt / pyproject.toml / Dockerfile
├── frontend/
│   ├── src/
│   │   ├── main.jsx, App.jsx       # router + layout                           [Lead]
│   │   ├── api/client.js           # fetch wrapper, error envelope             [Lead]
│   │   ├── components/             # shared UI + layout                        [Lead]
│   │   ├── context/AuthContext.jsx # token storage, current user               [M1]
│   │   └── features/<module>/      # one folder per module                     [owner]
│   └── package.json, vite.config.js, Dockerfile
├── infra/nginx/                    # TLS reverse proxy                         [M10]
├── scripts/                        # dev helpers (cert generation, keys)       [M10/Lead]
├── docs/                           # this documentation                        [Lead]
├── .github/                        # CI, PR template, CODEOWNERS               [Lead]
├── docker-compose.yml, .env.example, .gitignore, README.md                     [Lead]
```

Every module package under `backend/app/modules/<name>/` has the same shape:

| File          | Purpose                                                                  |
|---------------|--------------------------------------------------------------------------|
| `__init__.py` | `MODULE_INFO` — number, name, owner, `implemented` flag                  |
| `router.py`   | FastAPI `APIRouter` with the module's HTTP endpoints                     |
| `service.py`  | Python functions other modules call (the module's public interface)      |
| `schemas.py`  | Pydantic request/response models for this module                         |
| other files   | private helpers (e.g. `password.py`, `aes_gcm.py`, `hashchain.py`)       |

**Rule:** a module may import another module's `service.py` and `schemas.py`
only. Never import another module's private helpers or router.

## 2. Layers and request flow

1. **Transport (M10)** — nginx terminates TLS, adds HSTS; FastAPI middleware
   adds security headers and (in production) rejects non-HTTPS requests.
2. **Router** — validates input with Pydantic, resolves `get_current_user`
   (M1) and `db: DbSession` (one transaction per request, committed **before**
   the response is sent).
3. **Service** — the business logic; calls other modules' services; never commits.
4. **Models** — SQLAlchemy ORM; one shared `Base`.
5. **Audit (M6)** — every security-relevant action calls
   `audit.service.record_event(...)`, which queues the event. `app.core.database`
   writes it at the transaction boundary: atomically with the change on success,
   or (failure/denied events only) in a separate transaction after the rollback.
   See `security-design.md` M6 and `integration-guide.md` §4.3.

### Upload pipeline (`POST /api/v1/files`)

```
M1 get_current_user
 → M2 encryption.service.encrypt_bytes(plaintext, aad=file_id)   → ciphertext, nonce, file_key
 → M4 signatures.service.sign_manifest(owner, manifest)         → signature, signing_key_id
 → M3 keys.service.wrap_key_for_user(owner_id, file_key)         → wrapped_key, key_id
 → M5 sharing.service.create_owner_grant(file, wrapped_key, key_id)
 → M6 audit.service.record_event("file.upload", ...)
```

### Download pipeline (`GET /api/v1/files/{id}/download`)

```
M1 get_current_user
 → M5 sharing.service.require_access(user, file_id, "read")      → grant
 → M3 keys.service.unwrap_key_for_user(user_id, grant.wrapped_file_key, grant.wrapping_key_id)
 → M4 signatures.service.verify_manifest(file)                   → raises on failure
 → M2 encryption.service.decrypt_bytes(ciphertext, nonce, key, aad) → raises on GCM tag failure
 → M6 audit.service.record_event("file.download", ...)
 → return Response(content=plaintext)   # whole body built before returning; the session
                                        # closes before the response is sent (no streaming)
```

### Share pipeline (`POST /api/v1/shares`)

```
M5 require_access(owner, file_id, "owner")
 → M3 unwrap_key_for_user(owner, ...) → file_key
 → M3 wrap_key_for_user(recipient, file_key) → wrapped_key
 → M5 insert FileAccessGrant(recipient, wrapped_key, expires_at)
 → M6 record_event("share.create", ...)
```

### Analysis pipeline

```
M6 audit_logs ──▶ M7 anomaly.service.score_events() ──▶ anomaly_detections
                                     │
M6 audit_logs + M7 detections ──▶ M8 llm_analysis.service.analyze() ──▶ security_analyses
M9 verification.service.verify_file()/verify_audit_chain() ──▶ verification_runs
```

## 3. Database design

One schema, managed by one Alembic history (`backend/alembic/versions`).
Primary keys are UUIDs except `audit_logs.id` which is a monotonically
increasing integer (the hash chain order).

```
users 1───* auth_sessions
users 1───* user_keys            (purpose: encryption | signing)
users 1───* files                (owner)
files 1───* file_access_grants *───1 users   (grantee)
file_access_grants *───1 user_keys            (wrapping key)
files *───1 user_keys                          (signing key)
users 1───* audit_logs           (actor, nullable for anonymous events)
audit_logs 1───* anomaly_detections (optional link)
users 1───* security_analyses    (requested_by)
users 1───* verification_runs    (requested_by)
```

| Table                | Owner | Key columns |
|----------------------|-------|-------------|
| `users`              | M1 | `id`, `email` (unique; always trimmed and lowercased, enforced by CHECK `ck_users_email_normalized`), `username` (unique), `password_hash` (Argon2id PHC string), `role` (`user`/`admin`), `is_active`, `failed_login_count`, `locked_until`, `created_at`, `updated_at`, `last_login_at` |
| `auth_sessions`      | M1 | `id`, `user_id`→users, `refresh_token_hash` (SHA-256, unique), `created_at`, `expires_at`, `revoked_at`, `ip_address`, `user_agent` |
| `user_keys`          | M3 | `id`, `user_id`→users, `purpose` (`encryption`/`signing`), `algorithm`, `public_key_pem`, `encrypted_private_key`, `private_key_nonce`, `fingerprint` (unique SHA-256 of SPKI), `is_active`, `created_at`, `revoked_at`. At most one active key per (user, purpose). |
| `files`              | M2 (signature cols: M4) | `id`, `owner_id`→users, `original_filename`, `content_type`, `size_bytes`, `storage_path`, `encryption_algorithm`, `nonce`, `plaintext_sha256`, `ciphertext_sha256`, `signature`, `signature_algorithm`, `signing_key_id`→user_keys, `created_at`, `deleted_at` |
| `file_access_grants` | M5 | `id`, `file_id`→files, `grantee_id`→users, `granted_by_id`→users, `permission` (`owner`/`read`), `wrapped_file_key`, `wrapping_key_id`→user_keys, `created_at`, `expires_at`, `revoked_at`, `max_downloads`, `download_count`. Unique (`file_id`, `grantee_id`). |
| `audit_logs`         | M6 | `id` (bigint), `occurred_at`, `actor_user_id`→users, `event_type`, `outcome` (`success`/`failure`/`denied`), `resource_type`, `resource_id`, `ip_address`, `user_agent`, `details` (JSON), `prev_hash`, `entry_hash` (unique) |
| `anomaly_detections` | M7 | `id`, `user_id`→users, `audit_log_id`→audit_logs, `window_start`, `window_end`, `features` (JSON), `score`, `is_anomaly`, `model_version`, `created_at` |
| `security_analyses`  | M8 | `id`, `requested_by_id`→users, `scope` (JSON), `provider`, `model`, `prompt_sha256`, `status` (`pending`/`completed`/`failed`), `summary`, `findings` (JSON), `created_at`, `completed_at` |
| `verification_runs`  | M9 | `id`, `requested_by_id`→users, `target_type` (`file`/`audit_chain`/`system`), `target_id`, `passed`, `checks` (JSON), `created_at` |

Encrypted file bytes are **not** stored in PostgreSQL; they are stored on the
`file_storage` volume at `STORAGE_DIR/<file_id>.bin`. The database stores only
metadata, wrapped keys and hashes.

## 4. Module interfaces (Python)

The authoritative signatures live in each `service.py` (currently stubs that
raise `NotImplementedFeature`). Summary:

| Module | Public functions (in `service.py`) | Used by |
|---|---|---|
| M1 auth | `hash_password(pw) -> str`, `verify_password(pw, hash) -> bool`, `password_needs_rehash(hash) -> bool`, `register_user(db, data) -> User`, `authenticate(db, email, pw, ip, ua) -> TokenPair`, `decode_access_token(token) -> UUID`; `api/deps.py: get_current_user`, `require_admin` | all routers |
| M2 encryption | `encrypt_bytes(plaintext, aad) -> EncryptedPayload(ciphertext, nonce, key)`, `decrypt_bytes(ciphertext, nonce, key, aad) -> bytes`, `store_ciphertext(file_id, data) -> path`, `load_ciphertext(path) -> bytes` | M9 |
| M3 keys | `ensure_user_keys(db, user_id) -> None`, `get_active_key(db, user_id, purpose) -> UserKey`, `wrap_key_for_user(db, user_id, file_key) -> WrappedKey(wrapped, key_id)`, `unwrap_key_for_user(db, user_id, wrapped, key_id) -> bytes`, `load_private_key(db, key) -> RSAPrivateKey`, `rotate_keys(db, user_id, purpose)` | M1 (on register), M2, M4, M5 |
| M4 signatures | `build_manifest(file) -> bytes`, `sign_manifest(db, user_id, manifest) -> SignatureResult(signature, key_id, algorithm)`, `verify_manifest(db, file) -> bool` | M2, M9 |
| M5 sharing | `create_owner_grant(db, file, wrapped)`, `require_access(db, user_id, file_id, permission) -> FileAccessGrant`, `share_file(db, owner_id, file_id, recipient_email, expires_at, max_downloads)`, `revoke_share(db, owner_id, grant_id)` | M2 |
| M6 audit | `record_event(db, AuditEventIn) -> None` (queues), `append_entries(db, events)` (called by `app.core.database` only), `verify_chain(db) -> ChainVerification`, `compute_entry_hash(prev_hash, payload) -> str` | **every** module |
| M7 anomaly | `extract_features(events) -> list[FeatureVector]`, `train_model(db) -> ModelInfo`, `score_recent(db, since) -> list[AnomalyDetection]` | M8 |
| M8 llm_analysis | `redact(event_dict) -> dict`, `analyze(db, requested_by, scope) -> SecurityAnalysis` | — |
| M9 verification | `verify_file(db, user_id, file_id) -> VerificationReport`, `verify_audit_chain(db) -> VerificationReport` | — |
| M10 transport | `SecurityHeadersMiddleware`, `HTTPSRedirectGuard`, `transport_status(request) -> TransportStatus` | `main.py` |

Shared data contracts (dataclasses / Pydantic) used between modules are
defined in the *provider's* `schemas.py` and imported by consumers.

## 5. Frontend architecture

- **Vite + React 19 + React Router**, styled with **Tailwind CSS v4**.
- `src/api/client.js` is the single HTTP layer: prefixes `VITE_API_BASE_URL`,
  attaches the bearer token from `AuthContext`, and converts the backend error
  envelope into an `ApiError` (`status`, `code`, `message`, `module`).
- `src/features/<module>/` contains that module's `api.js` (calls only that
  module's endpoints), page component(s), and tests.
- `src/App.jsx` owns the route table; each module adds exactly one route line
  for its page (see `integration-guide.md`).
- `src/features/status/ModuleStatusPage.jsx` reads `GET /api/v1/modules` and
  shows which modules are implemented — this is the honest project dashboard.
- Auth state: access token held in memory (React context); refresh token is an
  `HttpOnly; Secure; SameSite=Strict` cookie set by the backend (M1 decision,
  documented in `security-design.md`).

## 6. Testing strategy

| Level | Tool | Location | Owner |
|---|---|---|---|
| Unit (crypto primitives) | pytest | `backend/tests/modules/test_<module>.py` | each member |
| API / integration | pytest + httpx `TestClient` | `backend/tests/` | each member + Lead |
| Migration ⇄ model drift | pytest + Alembic `compare_metadata` | `backend/tests/test_migrations.py` | Lead |
| Contract (all routes exist) | pytest on OpenAPI | `backend/tests/test_api_contract.py` | Lead |
| Attack / negative tests | pytest | `backend/tests/security/` | M9 |
| Frontend unit | Vitest + Testing Library | `frontend/src/**/*.test.jsx` | each member |
| End-to-end smoke | `docker compose up` + manual script | README | M10 + Lead |

Tests run against SQLite in-memory by default for speed (models use portable
types). CI also runs them against PostgreSQL by setting `TEST_DATABASE_URL`.
Every module must ship: (a) happy-path test, (b) at least one negative test
(wrong key, tampered data, unauthorized user, etc.).

## 7. Deployment

`docker-compose.yml` services: `db` (postgres:16), `backend` (runs
`alembic upgrade head` then uvicorn), `frontend` (Vite dev server), and `proxy`
(nginx TLS, Compose profile `tls`, owned by M10). All secrets come from `.env`
(never committed); `.env.example` documents each variable.
