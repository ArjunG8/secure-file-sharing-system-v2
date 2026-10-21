# Security Design

This document fixes the cryptographic choices so the ten modules interoperate.
Deviations require a PR that updates this file and is approved by every
affected module owner.

> **Status honesty rule:** a feature is "implemented" only when its code and
> tests are merged. Until then its `MODULE_INFO.implemented` stays `False`,
> its endpoints return `501 not_implemented`, and the UI shows it as pending.

## 1. Threat model (summary)

| Asset | Threats | Primary controls |
|---|---|---|
| User passwords | DB leak + offline cracking, credential stuffing | Argon2id (M1), lockout + rate limits (M1), anomaly detection (M7) |
| File contents | DB/storage theft, malicious admin reading disk | AES-256-GCM per file (M2), keys wrapped with RSA-OAEP (M3) |
| File integrity | Tampered ciphertext or metadata on disk | GCM tag (M2), RSA-PSS signed manifest (M4), verification (M9) |
| Authorization | IDOR, privilege escalation, expired shares | Grant table checks on every access (M5), 404-on-deny |
| Audit trail | Deletion / editing of logs to hide activity | HMAC-SHA256 hash chain (M6), chain verification (M6/M9) |
| Network | Eavesdropping, downgrade, cookie theft | TLS 1.2+/1.3, HSTS, secure cookies, security headers (M10) |
| Secrets | Hardcoded keys leaked through Git | All secrets from env; `.env` git-ignored; tests generate random keys |

**Trust model (be explicit in the report):** cryptography is performed
server-side. The server stores private keys encrypted under
`MASTER_KEY_ENCRYPTION_KEY`, which is supplied via environment at runtime. This
protects against database/storage theft, **not** against a fully compromised
running server. True end-to-end encryption (browser-side keys) is out of
scope and may be discussed as future work.

## 2. Module-by-module decisions

### M1 — Authentication & Argon2id
- Library: `argon2-cffi` (`PasswordHasher`). Store the full PHC string
  (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`) in `users.password_hash`.
- Parameters (configurable via env, defaults per RFC 9106 / OWASP):
  `ARGON2_TIME_COST=3`, `ARGON2_MEMORY_COST_KIB=65536`, `ARGON2_PARALLELISM=4`.
- On successful login, call `check_needs_rehash` and upgrade the hash.
- Password policy: min 12 chars, max 128; reject if it equals or contains the
  email local part or the username (when those are at least 4 characters).
- Emails are stripped and lowercased before storage and lookup (the admin CLI
  relies on this).
- Lockout: after `MAX_FAILED_LOGINS` (5) wrong passwords, set
  `locked_until = now + LOCKOUT_MINUTES` (15) and return 423 while it lasts, without
  checking the password. The counter is written in its own transaction, because the
  failed request rolls back.
- No user enumeration at login: an unknown email, a wrong password and an inactive
  account all return the same 401 message, and an unknown email still costs one
  Argon2id verification. Registration necessarily answers 409 for a taken
  email/username; the rate limit below bounds probing.
- Tokens: access JWT (HS256 only, `JWT_SECRET_KEY`, 15 min, claims `sub`, `sid`
  (session id), `iat`, `nbf`, `exp`, `jti`, `iss`, `type="access"`). Every request
  also checks that the `sid` session is still active, so logout, password change and
  refresh-token reuse take effect immediately.
- Refresh token: 32 random bytes, stored only as SHA-256 in `auth_sessions`, sent as
  the `sfs_refresh` cookie (`HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth`).
  It is rotated on every refresh. Presenting an already-rotated token revokes **all**
  of that user's sessions (theft detection) and logs `auth.refresh_reuse`.
- CSRF: `/auth/refresh` is the only cookie-authenticated endpoint. It requires the
  double-submit header `X-CSRF-Token` matching the `sfs_csrf` cookie (readable by our
  JavaScript, `Secure; SameSite=Strict`). Other endpoints use the bearer header, which
  browsers never attach automatically.
- Rate limiting (per client IP, sliding window, in memory per process): login
  10/min, register 20/hour, refresh 30/min, answered with 429 and `Retry-After`. With
  several backend processes, use nginx `limit_req` or a shared store instead.
- Keys: M1 does not create key pairs. M3 creates them on first use (see M3).
- Audit events: `auth.register`, `auth.login`, `auth.login_failed` (failure/denied,
  `details.reason`), `auth.locked`, `auth.refresh`, `auth.refresh_reuse`,
  `auth.logout`, `auth.password_change`. They never include passwords or tokens.

### M2 — AES-256-GCM file encryption
- Library: `cryptography.hazmat.primitives.ciphers.aead.AESGCM`.
- A fresh random 256-bit **file key** per file (`AESGCM.generate_key(256)`)
  and a fresh random **96-bit nonce** (`os.urandom(12)`). Never reuse a
  (key, nonce) pair.
- AAD = `file_id.bytes` (16 bytes) so a ciphertext cannot be swapped onto
  another file's record.
- Stored blob = ciphertext‖tag (as returned by `AESGCM.encrypt`). `nonce`
  stored in `files.nonce`. `ciphertext_sha256` and `plaintext_sha256` stored hex.
- The raw file key is never persisted — only RSA-OAEP-wrapped copies (M3).
- `MAX_UPLOAD_BYTES` (default 25 MiB) is enforced while reading the upload, before
  encryption (413). Starlette has already spooled the request body by then, so
  nginx `client_max_body_size` (M10) is the first limit in production.
- Filenames are metadata only: last path component, control characters removed, NFC,
  at most 255 characters. The on-disk name is always `<file_id>.bin`, and
  `storage.resolve` refuses any name that would leave `STORAGE_DIR`.
- Blobs are written to a temporary file in `STORAGE_DIR`, fsync'ed and atomically
  renamed, as the **last** step of an upload. A session `after_rollback` hook deletes the
  blob if anything later fails, including the COMMIT itself. Deletion is a soft delete
  of the record (the audit trail keeps its target), and the blob is removed after COMMIT.
- Download order: `require_access` (M5) → ciphertext SHA-256 → RSA-PSS/Ed25519
  manifest signature (M4) → unwrap the file key (M3) → AES-GCM decrypt (tag + AAD) →
  plaintext SHA-256 → download counter (M5). Any failed check returns 502
  `integrity_failure` with `details.check` and logs `file.integrity_failure`; no plaintext
  is returned. Responses are `application/octet-stream`, `Content-Disposition:
  attachment` (RFC 5987 UTF-8 name), `X-Content-Type-Options: nosniff`, `Cache-Control:
  no-store`.
- `GET /files` lists files with a currently valid grant, mirroring M5's grant rules for
  metadata only. Every content or metadata read of a single file goes through
  `sharing.require_access`.

### M3 — RSA/ECC key management
- **RSA vs ECC (decision).** Both are supported, chosen per key by its stored
  `algorithm` label, so they can coexist (e.g. before and after a rotation):

  | Family | `purpose="encryption"` (file-key wrapping) | `purpose="signing"` (M4) |
  |---|---|---|
  | `rsa` (default) | `RSA-OAEP-3072-SHA256`: RSA-3072, e=65537, OAEP with MGF1-SHA256, SHA-256, no label | `RSA-PSS-3072-SHA256` |
  | `ecc` | `ECIES-X25519-HKDF-SHA256-AES256GCM`: ephemeral X25519 → HKDF-SHA256 (info binds both public keys) → AES-256-GCM with the recipient key id as AAD; stored as `ephemeral_pub(32) ‖ nonce(12) ‖ ciphertext+tag` | `Ed25519` |

  `DEFAULT_KEY_ALGORITHM` (`rsa`/`ecc`) picks the family for **new** keys only.
  A key is only ever used with the algorithm on its label: there is no
  cross-format use, so mixed users and rotations are safe. No migration was needed
  (`user_keys.algorithm` is a string).
- Key separation: every user has one active encryption key and one active signing
  key; a pair is never used for both.
- Keys are created **on first use** (wrap, sign, `/keys/me`), not at registration,
  so M1 doesn't depend on M3. Concurrent first use is safe (savepoint plus the
  one-active-key unique index).
- Private keys: PKCS#8 DER, encrypted with AES-256-GCM under
  `MASTER_KEY_ENCRYPTION_KEY` with a random 96-bit nonce (`private_key_nonce`) and
  AAD = `"sfs-user-key-v1" ‖ user_id ‖ purpose ‖ key_id`. A ciphertext copied onto
  another user's or key's row fails to decrypt. A wrong master key fails closed (500).
- `fingerprint` = SHA-256 of the DER SubjectPublicKeyInfo, hex.
- Rotation (`POST /keys/rotate`, optionally switching family): old key →
  `is_active=False`, `revoked_at=now`, but kept, so existing wrapped file keys
  still unwrap and old signatures still verify. Grants are not re-wrapped automatically.
- Unwrapping requires a key of **that user** and purpose `encryption`; any other key
  id returns 404, and tampered or mismatched data returns 502.
- Audit events: `key.generate`, `key.rotate`.

### M4 — RSA-PSS digital signatures
- **Signatures prove authorship, hashes only prove sameness.** A matching SHA-256 shows the
  bytes weren't changed after hashing; it says nothing about who produced them. Only a
  verified signature by the owner's key does that, and M4 never treats a hash match
  as authorship.
- Algorithms follow the signer's M3 key: RSA keys (the default) sign with **RSA-PSS**
  (`PSS(MGF1(SHA256), salt_length=PSS.DIGEST_LENGTH)`, SHA-256, i.e. a 32-byte salt),
  stored as `RSA-PSS-SHA256`. ECC keys sign with **Ed25519**, stored as `Ed25519`.
  Rows written by the first M4 build carry `RSA-PSS-3072-SHA256` and are read as
  `RSA-PSS-SHA256`.
- Signed message = canonical manifest bytes (sorted keys, no whitespace, ASCII):
  `json.dumps({"v":1,"file_id","owner_id","original_filename","content_type",
  "size_bytes","plaintext_sha256","ciphertext_sha256","nonce_b64",
  "encryption_algorithm"}, sort_keys=True, separators=(",",":"), ensure_ascii=True)`.
  Changing any of these fields, including the owner, invalidates the signature.
- Signing happens at upload with the owner's active signing key; `files.signing_key_id`
  records the exact key. Verification uses that key even after rotation.
- Verification (`explain_verification`) fails closed, in order: no signature → signing
  key missing or not `purpose="signing"` → key not owned by the file's owner (blocks a
  valid signature by someone else) → key algorithm ≠ stored signature algorithm (blocks
  algorithm confusion) → cryptographic check.
- `GET /signatures/files/{id}` and `POST /signatures/files/{id}/verify` need read access
  through M5 (`require_access`): the same audited 404 for "not shared with you",
  "deleted" and "does not exist". The verify endpoint reports `signature_valid`
  (authorship) and `ciphertext_intact` (the stored blob's SHA-256 equals the signed
  `ciphertext_sha256`) separately; `valid` requires both. Each run is audited
  (`file.signature_verify`).
- Download must refuse (502 `integrity_failure`) when verification fails and emit a
  `file.integrity_failure` audit event (implemented in M2).

### M5 — Sharing & access control
- Default deny. Access requires a `file_access_grants` row where
  `revoked_at IS NULL`, (`expires_at IS NULL OR expires_at > now`),
  (`max_downloads IS NULL OR download_count < max_downloads`), and the file is
  not deleted.
- `permission="owner"` may share/revoke/delete; `"read"` may download only.
  Recipients cannot re-share (keeps the model simple and auditable).
- Sharing re-wraps the file key with the recipient's active **encryption**
  public key; the server never stores the raw file key.
- Return **404** (not 403) when a user lacks access to a file id, to avoid
  revealing existence. Log `share.access_denied`.
- Increment `download_count` atomically (`UPDATE ... SET download_count = download_count + 1 WHERE ... AND download_count < max_downloads`).
  Implemented with `RETURNING`; a download that loses the race is a denial. Verified on
  PostgreSQL 18: 10 concurrent downloads with `max_downloads=3` → exactly 3 succeed.
- `require_access` (`app/modules/sharing/service.py`) is the only enforcement point and
  is called for every read of content, metadata or signatures (M2, M4, M9). Every
  failure is recorded as `share.access_denied` (`details.reason` ∈ `no_such_file`,
  `no_grant`, `revoked`, `expired`, `download_limit_reached`, `not_owner`) **before**
  raising, so the event survives the rollback. All failures return the identical 404
  `File not found.` (no existence oracle).
- Owner grants are never limited or expirable, and can't be revoked (delete the file
  instead). A re-share to the same user updates their single grant row (fresh wrapped
  key, counters reset), matching the unique (`file_id`, `grantee_id`) constraint.
- Sharing requires an active recipient account. An unknown email returns 404, which
  lets a signed-in user check whether an email is registered; this is accepted for
  this project and bounded by authentication.

### M6 — Tamper-evident audit log
- Append-only from the application's perspective (no update/delete routes).
- `entry_hash = HMAC-SHA256(AUDIT_HMAC_KEY, prev_hash_bytes ‖ canonical_json(entry))`
  where `canonical_json` covers `occurred_at, actor_user_id, event_type,
  outcome, resource_type, resource_id, ip_address, user_agent, details`.
  Genesis `prev_hash` = 64 zeros. `id` is **not** hashed: the database assigns it
  at insert, and gaps are normal (rolled-back transactions consume sequence
  values). Chain order is `id` order, and the chain is defined by the `prev_hash` links.
- **When events are written.** Modules call `record_event(db, event)`, which only
  queues the event. `app.core.database` writes the queue at the end of the
  transaction by calling M6's `append_entries(db, events)`:
  - **Commit path:** every queued event is appended in the *same* transaction
    immediately before `COMMIT`. The business change and its audit record are
    saved together or not at all. If `append_entries` fails, the business change
    is rolled back (no action without an audit record).
  - **Rollback path:** the business transaction is rolled back *first*. Then only
    the `failure`/`denied` events are appended in a new, separate transaction.
    Nothing from the failed request can be committed with them. Success events
    from a rolled-back request are dropped, because the action didn't happen. If
    this write fails, the error is logged and the original error is still returned.
- **Locking.** `append_entries` serializes the chain with a transaction-scoped
  lock taken as its first step (PostgreSQL: `SELECT pg_advisory_xact_lock(<const>)`),
  then reads the latest `entry_hash`. The lock is held only between the end of the
  request and its `COMMIT`. A rolled-back request never holds it while its failure
  events are written, so it cannot deadlock against itself.
  `tests/test_audit_transactions.py` checks this plumbing with a test double that
  follows the same locking contract. On PostgreSQL that includes 40 concurrent
  transactions producing one unbroken chain. That double is not M6's
  implementation and is not proof that M6 is correct.
- **Known limitation:** a crash between the business `ROLLBACK` and the separate
  failure-event `COMMIT` loses those failure events (they are not atomic with
  anything). Document this in the report; an outbox table would remove it.
- `verify_chain` recomputes every hash and reports the first broken id.
- Never log secrets: passwords, tokens, raw keys, file contents.

### M7 — Isolation Forest anomaly detection
- `sklearn.ensemble.IsolationForest(n_estimators=200, contamination=env, random_state=42)`.
- Features per (user, 1-hour window) from `audit_logs`: login count, failed
  login count, distinct IPs, downloads, uploads, shares created, access
  denials, bytes downloaded, off-hours flag.
- Model persisted with `joblib` to `MODEL_DIR` (volume), versioned by
  timestamp. Never unpickle files from untrusted sources.
- Results written to `anomaly_detections`; anomalies emit `anomaly.detected`.
- Report honest metrics on a labeled synthetic dataset (precision/recall); do
  not claim real-world accuracy.

### M8 — LLM-based security event analysis
- `LLM_PROVIDER`: `disabled` (default; `/analysis` returns 503 and nothing is
  fabricated), `fake` (offline deterministic rules over the same redacted prompt, for
  demos and tests), or `openai_compatible` (`POST {LLM_BASE_URL}/chat/completions` with
  `LLM_API_KEY`, `LLM_MODEL`, `LLM_TIMEOUT_SECONDS`). No SDK is used and CI needs no key.
  A non-local `http://` base URL is refused: data only leaves the server over TLS.
- **Redaction** (`redaction.py`), before anything reaches a provider: actor and resource
  ids become keyed pseudonyms (HMAC, key derived from `AUDIT_HMAC_KEY`, stable so the
  model can correlate events); IPv4 is cut to /24 and IPv6 to /48; user agents are
  dropped; `details` keeps only allowlisted keys with scalar values, and emails, UUIDs and
  token-like strings in them are replaced. Passwords, keys, tokens and file contents are
  never in audit details, and unexpected fields are dropped rather than forwarded.
- **Prompt injection:** the system prompt declares the `<data>` block untrusted and says
  to ignore instructions inside it. The data is JSON-encoded with `<` escaped, so event
  text can't close the block.
- **Output validation:** the reply must be a JSON object matching `ModelOutput` (summary ≤
  4000 chars, ≤ 20 findings, severities from a fixed set). Unknown fields are dropped,
  and evidence ids not present in the input are removed. Anything else stores the
  analysis as `failed` with a neutral message, and provider errors and timeouts likewise.
- Stored per run: scope, provider, model, `prompt_sha256` (not the prompt), status,
  summary and findings. The API key is never stored. Runs are audited (`analysis.run`).
- **LLM output has no authority:** it is advisory text for an admin. No code path uses it
  for authentication, authorization, access control or cryptographic verification.
- The provider call runs inside the request (bounded by `LLM_TIMEOUT_SECONDS`) and holds
  a database connection meanwhile. That is acceptable for an admin-only endpoint; a
  background job would be needed at larger scale.

### M9 — Cryptographic verification & attack testing
- `/verification` endpoints run: GCM decrypt check, ciphertext SHA-256 match,
  RSA-PSS signature check, audit chain verification; results to
  `verification_runs`.
- `backend/tests/security/` must cover at minimum: tampered ciphertext byte →
  GCM failure; swapped nonce; ciphertext moved to another file id (AAD);
  forged/modified signature; wrong recipient private key; expired/revoked share
  → 404; IDOR on another user's file id; edited/deleted audit row → chain break;
  JWT with `alg=none` / wrong secret / expired; SQL injection strings in login
  and search fields; oversized upload → 413.
  These run as real end-to-end tests through the HTTP API
  (`backend/tests/security/test_attacks.py`); each is skipped only while a module it
  needs still reports `implemented=False`, and the skip reason names it.

### M10 — Secure data transmission & protocol security
- **Development vs production.** Development (`docker compose up` or a local uvicorn) is
  plain HTTP on localhost: no HTTPS enforcement, no HSTS. Production-style is
  `docker compose --profile tls up`: nginx terminates TLS, the backend requires HTTPS
  (`ENFORCE_HTTPS=true`, and always on when `ENVIRONMENT=production`). **The TLS profile
  has only been checked statically; it has not been run with Docker yet.**
- **App-side (`app/modules/transport`, tested):**
  - every response, including errors and rejections, carries `X-Content-Type-Options:
    nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
    `Permissions-Policy`, `Cross-Origin-Opener-Policy` / `-Resource-Policy: same-origin`,
    and a strict API CSP (`default-src 'none'; frame-ancestors 'none'`). `/api/docs` is
    exempt from the CSP because Swagger UI loads CDN assets;
  - HSTS (`max-age=HSTS_MAX_AGE_SECONDS; includeSubDomains`) only on HTTPS responses;
  - when HTTPS is required, plain-HTTP GET/HEAD get 308 to https and other methods get 400
    (a redirect would make clients resend bodies or credentials in clear first).
    `/api/v1/health` is exempt for internal probes;
  - "HTTPS" means uvicorn's resolved scheme. The app never reads `X-Forwarded-Proto`
    itself, and uvicorn honours it only from `FORWARDED_ALLOW_IPS` (the nginx container,
    pinned to `172.28.0.10` in Compose; `127.0.0.1` by default in the image, replacing
    the old `'*'`). A client sending `X-Forwarded-Proto: https` is still rejected
    (tested);
  - CORS is limited to `CORS_ORIGINS` (tested with an allowed and a foreign origin).
    The SPA is same-origin behind nginx, so production needs no CORS origins at all.
- **nginx (`infra/nginx/nginx.conf`):** `ssl_protocols TLSv1.2 TLSv1.3`, TLS 1.2 limited
  to ECDHE + AES-GCM / ChaCha20-Poly1305 (Mozilla intermediate), session tickets off,
  HTTP→HTTPS 301, HSTS, `server_tokens off`, `client_max_body_size 26m`, `limit_req` on
  `/api/v1/auth/`. It overwrites `X-Forwarded-For` with `$remote_addr` (never appends
  client values) and passes `X-TLS-Protocol` for `/transport/status`.
- **Production frontend:** `infra/nginx/Dockerfile` builds the SPA (`npm run build`) and
  serves the static files from nginx with an SPA CSP (`default-src 'self'; script-src
  'self'; style-src 'self'; frame-ancestors 'none'` …). The Vite dev server is never
  behind the TLS proxy.
- Dev certificates come from `scripts/gen-dev-certs.sh` (self-signed RSA-3072, key
  `chmod 600`) into `infra/nginx/certs/`, which is git- and docker-ignored. Browsers
  will warn about the self-signed certificate; real deployments need a CA-issued one.
- **Still required (manual):** run `docker compose --profile tls up --build`, then check
  with `openssl s_client -connect localhost:443 -tls1_1` (must fail),
  `-tls1_2`/`-tls1_3` (must succeed), `curl -I http://localhost` (301) and
  `curl -kI https://localhost/api/v1/health` (HSTS present). Record the results in the
  report.

## 3. Secrets management

| Variable | Used by | Format | Generate with |
|---|---|---|---|
| `POSTGRES_PASSWORD` | db | string | `python -c "import secrets;print(secrets.token_urlsafe(32))"` |
| `JWT_SECRET_KEY` | M1 | ≥32 random bytes | same as above |
| `MASTER_KEY_ENCRYPTION_KEY` | M3 | base64 of 32 bytes | `python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"` |
| `AUDIT_HMAC_KEY` | M6 | base64 of 32 bytes | same as above |
| `LLM_API_KEY` | M8 | provider key | from provider console; never commit |

The backend refuses to start if a required secret is missing or too short.
