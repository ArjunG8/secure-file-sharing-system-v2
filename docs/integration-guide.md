# Integration Guide

The rules that let ten people build one application without stepping on each
other. New members should start with [team-start-guide.md](team-start-guide.md),
which has the setup commands and first-week plan; this file is the detailed
reference.

## 1. Setup

See [team-start-guide.md §3](team-start-guide.md#3-setup-and-everyday-commands)
for the commands (PowerShell and macOS/Linux). In short: Python 3.12+, Node
20.19+ or 22.12+, and PostgreSQL 16 for running the app and generating
migrations. Tests need no database server: they use in-memory SQLite.

## 2. GitHub collaboration workflow

Branches: **`develop`** is the integration branch, and all module work targets
it. **`main`** is the stable branch: it only receives tested `develop → main`
PRs that the Lead opens at milestones (e.g. end of each week, final demo).

1. **Never commit directly to `develop` or `main`.** The Lead enables branch
   protection on both: require a PR, 1 approving review, and passing CI.
2. Branch from the latest `develop`:
   `git switch develop`, `git pull`, `git switch -c m3/rsa-oaep-wrap`.
   Branch names: `mN/<short-topic>` for module work, `chore/…` and `docs/…` for the Lead.
3. Keep PRs small (≤ ~400 lines), one concern each.
4. Commit messages: `m3: add RSA-OAEP key wrapping` (module prefix, imperative).
5. Before pushing: `pytest`, `ruff check .` and `npm test` pass locally, and
   your branch is rebased on `develop` (`git pull --rebase origin develop`).
6. Open the PR **into `develop`** using the template, link the issue, and fill in the
   security checklist.
7. CODEOWNERS reviewers are requested automatically. A change to another module's
   files needs that owner's approval; a change to a shared file needs the Lead's.
8. Squash-merge, then delete the branch.
9. Track work in GitHub Issues with the labels `module:m1` … `module:m10`,
   `type:feature`, `type:bug`, `type:test` and `blocked`.

## 3. Implementing your module: checklist

1. Read your module card in [module-ownership.md](module-ownership.md#module-cards),
   your section in `security-design.md`, and your endpoints in `api-contracts.md`.
2. Implement the functions in `backend/app/modules/<name>/service.py` (replacing the
   `NotImplementedFeature` raises). Keep the signatures. If you must change one,
   update `architecture.md` §4 and tell every consumer listed on your card.
3. Implement the endpoints in `router.py` using your `schemas.py` models.
4. Call `audit.service.record_event(...)` for every security-relevant action,
   including failures and denials (see §4.3).
5. Write tests in `backend/tests/modules/test_<name>.py`: the happy path plus at least one
   negative case (wrong key, tampered data, unauthorized user, etc.).
6. Remove your endpoints from **your module's block** in
   `backend/tests/test_not_implemented.py` (`STUBBED["M3"] = [...]`). Don't touch
   other modules' blocks; keeping edits inside your own block avoids merge conflicts.
7. Set `implemented=True` in your module's `__init__.py` **only when** all of
   your endpoints work and are tested.
8. Build your frontend page in `frontend/src/features/<name>/`.

## 4. Integration points (where modules touch)

### 4.1 Routes and pages
Every module's `router` is already included by `app/api/router.py`, and every page
is already registered in `frontend/src/routes.jsx` and the nav. Add endpoints only in
your own `router.py` and pages only in your own feature folder. Ask the Lead if you
need a new route prefix or page.

### 4.2 Database sessions: always `DbSession`
```python
from app.core.database import DbSession

@router.get("/{file_id}")
def get_file(db: DbSession, file_id: uuid.UUID, user: User = Depends(get_current_user)):
    ...
```
`DbSession` is `get_db` with FastAPI's `scope="function"`, so the transaction
**commits before the response is sent**. A failed commit becomes an error
response, never a false success. Never write `Depends(get_db)` yourself:
`tests/test_database.py` fails if any route does. Put `db: DbSession` first in
the parameter list, because Python requires parameters without defaults to come
before those with defaults.

Consequence: the session is closed before the response body is sent. **Build the
whole response before returning** (M2: read and decrypt the file into memory and
return `Response(content=...)`), and never use the session inside a
`StreamingResponse` generator or a `BackgroundTasks` function. Files are at most
`MAX_UPLOAD_BYTES` (25 MiB), so holding one in memory is fine.

### 4.3 Transactions and audit events (one rule for everyone)
- One request means one transaction. It **commits when the endpoint returns
  normally and rolls back when it raises** (including `AppError`).
- Services and routers **never call `db.commit()` or `db.rollback()`**. Call
  `db.flush()` when you need database-generated values (ids, defaults) earlier.
- **Reject by raising, never by returning** an error response: a returned
  response, whatever its status code, commits everything written so far.
- `record_event(db, event)` only **queues** the event. At the end of the request:
  - commit path: all queued events are written in the same transaction just
    before COMMIT (atomic with your change);
  - rollback path: your changes are undone first, then only the
    `failure`/`denied` events are written in a separate transaction.
  So record the denial, **then** raise:
  ```python
  audit_service.record_event(db, AuditEventIn(event_type="share.access_denied",
                                              outcome="denied", actor_user_id=user.id,
                                              resource_type="file", resource_id=str(file_id)))
  raise AppError(404, "File not found.")
  ```
- Scripts and background jobs use `with session_scope() as db:` from
  `app.core.database`, which applies the same rule (see `app/cli.py`).
- Design, locking and the known limitation are in `security-design.md` (M6).

Responsibilities that cross modules:

| Module | Responsibility under this rule |
|---|---|
| M2 | Upload/download run M3, M4 and M5 calls inside **one** request transaction. On an integrity failure, record `file.integrity_failure` (outcome `failure`), then raise `AppError(502)` |
| M5 | `require_access` records `share.access_denied` (outcome `denied`) and then raises 404. The download counter update runs in the request transaction, so a failed download doesn't count |
| M6 | Implements `append_entries` (lock → read last hash → insert → flush; never commit) plus `verify_chain`. Doesn't change `record_event`'s queueing |
| everyone | Calls `record_event`, never writes `audit_logs` directly |

### 4.4 Adding or changing a table
1. Edit **your** model file in `app/models/`.
2. Start PostgreSQL (your local install, or `docker compose up -d db`) and
   bring it up to date. Alembic reads `DATABASE_URL` from `.env`, and it must point at
   `localhost` (the `.env.example` default):
   ```bash
   cd backend
   alembic upgrade head
   alembic revision --autogenerate -m "m5 add grant note column"
   ```
   Rename the file to `NNNN_m5_add_grant_note_column.py` and review it by hand.
   Autogenerate misses some changes (CHECK constraints, partial indexes).
   Migrations must be safe on existing data: check before you transform, and
   stop with a clear error rather than silently deleting or merging rows (see
   `0002_normalize_user_emails.py` for an example).
3. Before opening the PR: `git pull --rebase origin develop`, then check that
   `alembic heads` shows **one** head. If it shows two, set your `down_revision` to the
   other head.
4. `pytest tests/test_migrations.py` must pass (it detects model/migration drift).

### 4.5 Tests: fixtures and safety
| Fixture | Use |
|---|---|
| `db` | A SQLAlchemy session on the test database |
| `client` | `TestClient` for the whole app |
| `create_user(role="user", email=None)` | Saves a `User` and returns it. Its password hash is a placeholder, so it **cannot log in** |
| `client_as(user)` | The client acting as `user`, bypassing M1's token check, for testing *your* module's authorization logic |

Built-in safety (`tests/conftest.py`, covered by `tests/test_test_safety.py`):
- Every table is emptied after each test, even when a test fails.
- **Your personal `.env` is ignored**: tests read only real environment variables.
  `STORAGE_DIR` and `MODEL_DIR` point at a temporary folder that is deleted
  afterwards.
- Secrets are random for every run.
- SQLite enforces foreign keys (`PRAGMA foreign_keys=ON`), so cascade and
  set-null behaviour matches PostgreSQL.
- `TEST_DATABASE_URL` (a real environment variable, not `.env`) runs the
  suite on PostgreSQL. The database **name must contain `test`** and must differ
  from `DATABASE_URL`; otherwise the run is refused, because the suite deletes
  every row.

Tests that are about authentication itself (M1, M9's JWT attacks) must use real
tokens instead of `client_as`. Concurrency tests only mean something on PostgreSQL;
skip them on SQLite with a clear reason (see `tests/test_audit_transactions.py`).

### 4.6 Emails
All emails are trimmed and lowercased: by `NormalizedEmail` in request
schemas, by the `User` model on every write, and by the database CHECK
`ck_users_email_normalized`. Use `NormalizedEmail` for any new email input field,
and look users up with `normalize_email(value)` from `app.schemas.common`.

### 4.7 Admin accounts
Admin-only endpoints (M6, M7, M8, M9) need an admin. In tests use
`create_user(role="admin")`. In a running app, see the bootstrap steps in
[team-start-guide.md §3](team-start-guide.md#first-admin-account).

### 4.8 Calling another module
```python
from app.modules.keys import service as keys_service
from app.modules.audit import service as audit_service
from app.modules.audit.schemas import AuditEventIn

wrapped = keys_service.wrap_key_for_user(db, user.id, file_key)
audit_service.record_event(db, AuditEventIn(event_type="file.upload", actor_user_id=user.id, ...))
```
Import only another module's `service.py` and `schemas.py`.

### 4.9 Stubs
Until M6 lands, queued audit events are **not** persisted: `append_entries`
logs `... was NOT recorded` for each one. Every other unimplemented service function
raises `NotImplementedFeature`, which the API returns as `501 not_implemented`
with the owning module's number.

### 4.10 Mocking a dependency that isn't merged yet
```python
def test_upload_wraps_key(client_as, create_user, monkeypatch):
    monkeypatch.setattr(keys_service, "wrap_key_for_user", lambda db, uid, k: WrappedKey(b"x", uuid4()))
    alice = create_user()
    r = client_as(alice).post("/api/v1/files", files={"file": ("a.txt", b"hi", "text/plain")})
```

| Waiting module | Needs | Until that is merged |
|---|---|---|
| M1 registration | M3 `ensure_user_keys` | Mock it in M1 tests |
| M2, M5 | M1 auth, M3 wrap/unwrap, M4 sign/verify | `client_as`, plus mocks for the services |
| M7 | Real audit data from M6 | Train and test on synthetic events built inside the test |
| M8 | An LLM provider | A fake provider in tests; CI never calls a real API or needs a key |
| M9 attack tests | The feature under attack | Keep the test skipped with its reason; never fake a pass |

## 5. Definition of done
The general checklist and each module's specific criteria are in
[team-start-guide.md §6](team-start-guide.md#6-definition-of-done) and on the
module cards.

## 6. Final integration (Week 4)
1. The Lead freezes contracts; only bug-fix PRs after that.
2. Someone with Docker runs `docker compose --profile tls up --build` on a clean
   machine. **This hasn't been verified yet** (see README).
3. Walk through the demo: register two users → upload → share → download as the
   recipient → revoke → tamper with a blob on disk and show the verification failure →
   edit an audit row and show the chain break → run anomaly scoring → run LLM
   analysis (only if a provider key is configured) → show TLS/HSTS in the browser.
4. M9 runs the full `tests/security` suite and records the results for the report.
