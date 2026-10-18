# API Contracts

Base URL: `/api/v1`. All bodies are JSON (`application/json`) unless marked
multipart. Timestamps are ISO-8601 UTC strings. IDs are UUID strings unless
noted. The live, generated spec is at `/api/docs` (Swagger) and
`/api/openapi.json` while the backend is running.

> **Changing a contract:** open a PR that edits this file *and* the module's
> `schemas.py` together, and request review from every module listed under
> "Consumers". Do not silently change field names.

## 1. Conventions

### Authentication
`Authorization: Bearer <access_token>` (JWT, issued by M1). Endpoints marked
🔒 require it; 🛡 additionally require `role == "admin"`.

### Error envelope (all non-2xx responses)
```json
{
  "error": {
    "code": "not_implemented",
    "message": "AES-256-GCM file encryption is not implemented yet.",
    "module": "M2",
    "details": null
  }
}
```

| HTTP | `code` | When |
|---|---|---|
| 400 | `bad_request` | malformed input not caught by schema |
| 401 | `unauthenticated` | missing/invalid/expired token |
| 403 | `forbidden` | authenticated but not allowed |
| 404 | `not_found` | resource absent **or** caller has no access (avoid IDOR oracle) |
| 409 | `conflict` | duplicate email, already shared, etc. |
| 413 | `payload_too_large` | file > `MAX_UPLOAD_BYTES` |
| 422 | `validation_error` | Pydantic validation failure (`details` = field errors) |
| 423 | `account_locked` | too many failed logins |
| 429 | `rate_limited` | rate limit exceeded |
| 500 | `internal_error` | unexpected; never leaks stack traces |
| 501 | `not_implemented` | module not built yet (honest stub) |
| 502 | `integrity_failure` | signature or GCM tag verification failed on stored data |
| 503 | `service_unavailable` | dependency disabled (e.g. LLM provider not configured) |

### Pagination (list endpoints)
Query: `?limit=50&offset=0` (limit max 200). Response:
```json
{ "items": [ ... ], "total": 123, "limit": 50, "offset": 0 }
```

## 2. Core (Lead)

| Method | Path | Auth | Response |
|---|---|---|---|
| GET | `/health` | – | `{ "status": "ok", "version": "0.1.0", "database": "ok" \| "unavailable" }` |
| GET | `/modules` | – | `[{ "number": 1, "key": "auth", "name": "...", "implemented": false }]` |

## 3. M1 — Authentication (`/auth`)

| Method | Path | Auth | Request | Response |
|---|---|---|---|---|
| POST | `/auth/register` | – | `RegisterRequest` | 201 `UserOut`; 409 taken; 422 policy; 429 |
| POST | `/auth/login` | – | `LoginRequest` | 200 `TokenResponse` + `sfs_refresh` and `sfs_csrf` cookies; 401; 423 locked; 429 |
| POST | `/auth/refresh` | cookie + `X-CSRF-Token` header | – | 200 `TokenResponse` + rotated cookies; 401; 403 CSRF; 429 |
| POST | `/auth/logout` | 🔒 | – | 204 |
| GET | `/auth/me` | 🔒 | – | 200 `UserOut` |
| POST | `/auth/change-password` | 🔒 | `ChangePasswordRequest` | 204 |

```jsonc
// RegisterRequest
{ "email": "a@b.edu", "username": "alice", "password": "≥12 chars" }
// LoginRequest
{ "email": "a@b.edu", "password": "..." }
// TokenResponse
{ "access_token": "eyJ...", "token_type": "bearer", "expires_in": 900 }
// UserOut
{ "id": "uuid", "email": "a@b.edu", "username": "alice", "role": "user", "created_at": "..." }
// ChangePasswordRequest
{ "current_password": "...", "new_password": "..." }
```

- 🔒 endpoints return 401 with `WWW-Authenticate: Bearer` for a missing, malformed,
  expired or revoked token.
- `logout` and `change-password` clear both cookies; `change-password` ends **every**
  session (sign in again). A wrong `current_password` returns 403.

## 4. M2 — Files & encryption (`/files`)

| Method | Path | Auth | Request | Response |
|---|---|---|---|---|
| POST | `/files` | 🔒 | multipart: `file` | 201 `FileOut` |
| GET | `/files` | 🔒 | pagination | 200 `Page[FileOut]` (owned + shared with me) |
| GET | `/files/{file_id}` | 🔒 | – | 200 `FileOut` |
| GET | `/files/{file_id}/download` | 🔒 | – | 200 `application/octet-stream` (decrypted) |
| DELETE | `/files/{file_id}` | 🔒 owner | – | 204 (soft delete + blob removal) |

```jsonc
// FileOut
{
  "id": "uuid", "owner_id": "uuid", "original_filename": "report.pdf",
  "content_type": "application/pdf", "size_bytes": 1024,
  "encryption_algorithm": "AES-256-GCM", "plaintext_sha256": "hex",
  "signature_algorithm": "RSA-PSS-SHA256", "permission": "owner" | "read",
  "created_at": "..."
}
```

## 5. M3 — Key management (`/keys`)

| Method | Path | Auth | Response |
|---|---|---|---|
| GET | `/keys/me` | 🔒 | 200 `[PublicKeyOut]` (active encryption + signing keys) |
| POST | `/keys/rotate` | 🔒 | `{ "purpose": "encryption" \| "signing" }` → 200 `PublicKeyOut` |
| GET | `/keys/users/{user_id}/public` | 🔒 | 200 `[PublicKeyOut]` |

```jsonc
// PublicKeyOut — private keys are NEVER returned by any endpoint
{ "id": "uuid", "user_id": "uuid", "purpose": "encryption", "algorithm": "RSA-OAEP-3072-SHA256",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----...", "fingerprint": "hex", "is_active": true, "created_at": "..." }
```

## 6. M4 — Signatures (`/signatures`)

| Method | Path | Auth | Response |
|---|---|---|---|
| GET | `/signatures/files/{file_id}` | 🔒 access | 200 `SignatureOut` |
| POST | `/signatures/files/{file_id}/verify` | 🔒 access | 200 `SignatureVerifyResult` |

```jsonc
// SignatureOut
{ "file_id": "uuid", "algorithm": "RSA-PSS-SHA256", "signature_b64": "...",
  "signing_key_id": "uuid", "signer_id": "uuid", "manifest": { ... } }
// SignatureVerifyResult
{ "file_id": "uuid", "valid": true, "checked_at": "...", "reason": null }
```

## 7. M5 — Sharing & access control (`/shares`)

| Method | Path | Auth | Request | Response |
|---|---|---|---|---|
| POST | `/shares` | 🔒 owner | `ShareCreate` | 201 `ShareOut` |
| GET | `/shares/outgoing` | 🔒 | pagination | 200 `Page[ShareOut]` |
| GET | `/shares/incoming` | 🔒 | pagination | 200 `Page[ShareOut]` |
| DELETE | `/shares/{grant_id}` | 🔒 owner | – | 204 (sets `revoked_at`) |

```jsonc
// ShareCreate
{ "file_id": "uuid", "recipient_email": "b@b.edu", "expires_at": "..." | null, "max_downloads": 5 | null }
// ShareOut
{ "id": "uuid", "file_id": "uuid", "file_name": "report.pdf", "grantee_id": "uuid",
  "grantee_email": "b@b.edu", "granted_by_id": "uuid", "permission": "read",
  "expires_at": null, "revoked_at": null, "max_downloads": null, "download_count": 0, "created_at": "..." }
```

## 8. M6 — Audit log (`/audit`)

| Method | Path | Auth | Response |
|---|---|---|---|
| GET | `/audit/logs` | 🔒 (own events) / 🛡 (all) | `?event_type=&actor_id=&since=&until=` + pagination → `Page[AuditLogOut]` |
| GET | `/audit/verify` | 🛡 | 200 `ChainVerification` |

```jsonc
// AuditLogOut
{ "id": 42, "occurred_at": "...", "actor_user_id": "uuid" | null, "event_type": "file.upload",
  "outcome": "success", "resource_type": "file", "resource_id": "uuid", "ip_address": "1.2.3.4",
  "details": { }, "prev_hash": "hex", "entry_hash": "hex" }
// ChainVerification
{ "valid": true, "checked_entries": 42, "first_broken_id": null, "reason": null }
```

### Standard event types
`auth.register`, `auth.login`, `auth.login_failed`, `auth.logout`,
`auth.password_change`, `auth.locked`, `user.role_change`, `key.generate`, `key.rotate`,
`file.upload`, `file.download`, `file.delete`, `file.integrity_failure`,
`share.create`, `share.revoke`, `share.access_denied`, `audit.verify`,
`anomaly.train`, `anomaly.detected`, `analysis.run`, `verification.run`,
`transport.insecure_request`. New types: add here in the same PR.

## 9. M7 — Anomaly detection (`/anomaly`) 🛡

| Method | Path | Request | Response |
|---|---|---|---|
| POST | `/anomaly/train` | `{ "since": "..." \| null }` | 200 `ModelInfo` |
| POST | `/anomaly/score` | `{ "since": "..." \| null }` | 200 `[AnomalyOut]` |
| GET | `/anomaly/detections` | `?only_anomalies=true` + pagination | 200 `Page[AnomalyOut]` |

```jsonc
// ModelInfo
{ "model_version": "iforest-2026-10-15T10:00:00Z", "trained_on_events": 1200,
  "features": ["logins_per_hour", "..."], "contamination": 0.05 }
// AnomalyOut
{ "id": "uuid", "user_id": "uuid" | null, "audit_log_id": 42 | null, "window_start": "...", "window_end": "...",
  "features": { "failed_logins": 9 }, "score": -0.21, "is_anomaly": true, "model_version": "...", "created_at": "..." }
```

## 10. M8 — LLM security analysis (`/analysis`) 🛡

| Method | Path | Request | Response |
|---|---|---|---|
| POST | `/analysis` | `AnalysisRequest` | 201 `AnalysisOut` (or 503 if `LLM_PROVIDER=disabled`) |
| GET | `/analysis` | pagination | 200 `Page[AnalysisOut]` |
| GET | `/analysis/{analysis_id}` | – | 200 `AnalysisOut` |

```jsonc
// AnalysisRequest
{ "since": "...", "until": "...", "include_anomalies": true, "max_events": 200 }
// AnalysisOut
{ "id": "uuid", "status": "completed", "provider": "...", "model": "...", "summary": "...",
  "findings": [ { "severity": "high", "title": "...", "evidence_event_ids": [41, 42], "recommendation": "..." } ],
  "created_at": "...", "completed_at": "..." }
```

## 11. M9 — Verification (`/verification`)

| Method | Path | Auth | Response |
|---|---|---|---|
| POST | `/verification/files/{file_id}` | 🔒 access | 200 `VerificationReport` |
| POST | `/verification/audit-chain` | 🛡 | 200 `VerificationReport` |
| GET | `/verification/runs` | 🛡 | pagination → `Page[VerificationReport]` |

```jsonc
// VerificationReport
{ "id": "uuid", "target_type": "file", "target_id": "uuid", "passed": false,
  "checks": [ { "name": "gcm_tag", "passed": true, "detail": null },
              { "name": "rsa_pss_signature", "passed": false, "detail": "signature mismatch" },
              { "name": "ciphertext_sha256", "passed": true, "detail": null } ],
  "created_at": "..." }
```

## 12. M10 — Transport (`/transport`)

| Method | Path | Auth | Response |
|---|---|---|---|
| GET | `/transport/status` | – | 200 `TransportStatus` |

```jsonc
// TransportStatus
{ "scheme": "https", "behind_proxy": true, "hsts_enabled": true, "https_enforced": true,
  "tls_version": "TLSv1.3" | null }
```
