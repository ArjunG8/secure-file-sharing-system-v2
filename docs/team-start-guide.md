# Team Start Guide

Read this first. It's the short version for the ten module members; details are linked.
We are building **one** application (one React frontend, one FastAPI backend, one
PostgreSQL schema). Your module is a package inside it, not a separate app.

## 1. Module assignments

Fill in names and GitHub usernames in [module-ownership.md](module-ownership.md)
and `.github/CODEOWNERS`. Each module's full card (owned files, inputs/outputs,
dependencies, tests, done criteria) is in
[module-ownership.md → Module cards](module-ownership.md#module-cards).

| # | Module | Member | Responsibility in one line |
|---|---|---|---|
| 1 | Authentication & Argon2id | _TBD_ | Register/login, Argon2id hashing, lockout, JWT + refresh cookie, `get_current_user` |
| 2 | AES-256-GCM files | _TBD_ | Encrypt/decrypt files, blob storage, **owns the upload/download flow** |
| 3 | RSA-OAEP keys | _TBD_ | Per-user RSA key pairs, KEK-encrypted private keys, wrap/unwrap file keys, rotation |
| 4 | RSA-PSS signatures | _TBD_ | Sign file manifests at upload, verify at download |
| 5 | Sharing & access control | _TBD_ | Grants, `require_access` (default deny, 404), share/revoke, expiry and limits |
| 6 | Audit log | _TBD_ | HMAC hash chain (`append_entries`), chain verification, `/audit` |
| 7 | Isolation Forest | _TBD_ | Features from audit logs, train/score, store detections |
| 8 | LLM analysis | _TBD_ | Redact events, call a configurable provider, validated findings; 503 if disabled |
| 9 | Verification & attacks | _TBD_ | `/verification` checks plus the attack-test suite in `tests/security/` |
| 10 | HTTPS/TLS | _TBD_ | nginx TLS, HSTS and security headers, HTTPS enforcement |

The Lead (repository owner, may also own a module) owns the shared files and approves changes to them.

## 2. Branches and pull requests

- `develop` is where all work is integrated. `main` is stable and only gets
  `develop → main` PRs from the Lead at milestones.
- Never commit directly to `develop` or `main`.
- Branch names: `m<N>/<short-topic>`, e.g. `m3/rsa-oaep-wrap`, `m5/require-access`.
- Commit messages: `m3: add RSA-OAEP key wrapping`.
- PRs go **into `develop`**, stay small (≤ ~400 lines), use the PR template, and need
  1 approval plus green CI. Squash-merge.

Full rules: [integration-guide.md §2](integration-guide.md#2-github-collaboration-workflow).

## 3. Setup and everyday commands

Prerequisites: Git, **Python 3.12+**, **Node 20.19+ or 22.12+**, and **PostgreSQL 16**
(a local install, or Docker running only the database). Tests don't need PostgreSQL.

**macOS / Linux (bash, zsh)**
```bash
git clone https://github.com/ArjunG8/secure-file-sharing-system-v2.git
cd secure-file-sharing-system-v2
git switch develop
cp .env.example .env              # then fill in the empty values (see below)

cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
pytest                            # backend tests (SQLite in memory)
ruff check .                      # lint

cd ../frontend
npm install
npm test
npm run build
```

**Windows (PowerShell)**
```powershell
git clone https://github.com/ArjunG8/secure-file-sharing-system-v2.git
cd secure-file-sharing-system-v2
git switch develop
Copy-Item .env.example .env       # then fill in the empty values (see below)

cd backend
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1        # if blocked: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
pip install -r requirements-dev.txt
pytest
ruff check .

cd ..\frontend
npm install
npm test
npm run build
```

**Filling in `.env`.** Generate each secret, paste it in, and never commit `.env`:
```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"                     # JWT_SECRET_KEY, POSTGRES_PASSWORD
python -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())"  # MASTER_KEY_ENCRYPTION_KEY, AUDIT_HMAC_KEY
```
Put the PostgreSQL password into `DATABASE_URL` too. Leave `LLM_PROVIDER=disabled`
unless you are M8 testing a real provider.

**Database, migrations and running the app** (from `backend/`, with the venv active):
```bash
# PostgreSQL must be running and DATABASE_URL in .env must point at it.
# Database only, through Docker:   docker compose up -d db   (from the repo root)
alembic upgrade head              # create or upgrade the tables (reads .env)
uvicorn --factory app.main:create_app --reload     # http://localhost:8000/api/docs
```
Frontend dev server: `npm run dev` in `frontend/` → http://localhost:5173 (it proxies `/api` to port 8000).

**Running the tests on PostgreSQL (optional; CI always does this).** Create a separate,
empty database whose name contains `test`, then set a *real* environment variable;
`.env` is ignored by the tests:
```bash
export TEST_DATABASE_URL="postgresql+psycopg://USER:PASSWORD@localhost:5432/securefiles_test"   # bash
$env:TEST_DATABASE_URL = "postgresql+psycopg://USER:PASSWORD@localhost:5432/securefiles_test"  # PowerShell
pytest
```
The suite refuses to run against a database without `test` in its name, or against
your `DATABASE_URL`, because it deletes every row.

**Docker Compose (full stack).** `docker compose up --build` should start the database,
backend (migrations on start, auto-reload) and frontend. **No one on the team has
verified this yet**; the first person with Docker should run it and report back
(M10 owns that check together with the TLS profile).

### First admin account
Admin endpoints (audit, anomaly, analysis, verification) need an admin. Accounts
are created **only** through normal registration (M1), so passwords are always
Argon2id-hashed. The CLI changes roles only:
1. Register the account in the app (requires M1). Until M1 exists, use
   `create_user(role="admin")` in tests instead.
2. Dry run: from `backend/`, run `python -m app.cli promote-admin you@example.edu`.
   It prints the matched account (id, username, email, role, status) and changes nothing.
3. If that's the right account, run it again with `--yes`. Inactive or locked accounts are
   refused, an audit event is recorded, and demoting the last active admin is refused.

Never promote someone by editing the database directly.

## 4. Staying in sync with `develop`, and migrations

```bash
git switch develop && git pull                 # start of each day
git switch m3/rsa-oaep-wrap
git rebase develop                             # or: git pull --rebase origin develop
pytest && ruff check .                         # re-run after every rebase
git push --force-with-lease                    # only on your own feature branch
```

Changing a table:
1. Edit **your** model file, then run `alembic upgrade head` and
   `alembic revision --autogenerate -m "m5 add grant note"` against your local PostgreSQL.
2. Rename the file to `NNNN_m5_<description>.py` and read it line by line.
3. Before the PR: rebase on `develop`, check that `alembic heads` shows **one** head (if two,
   set your `down_revision` to the other head), then run `pytest tests/test_migrations.py`.
4. Migrations must be safe on existing data: refuse with a clear error rather than
   deleting or merging rows.

## 5. Shared files and conflict rules

- **Lead approval is required** for shared files: `app/main.py`, `app/cli.py`,
  `app/core/*`, `app/api/router.py`, `app/schemas/common.py`, `app/models/__init__.py`
  and `base.py`, Alembic config and Lead migrations, shared tests, frontend shell
  files, Compose/CI/docs. The full list is in
  [module-ownership.md](module-ownership.md#exact-file-ownership).
- `tests/test_not_implemented.py`: edit **only your own `STUBBED["Mn"]` block**.
- `models/file.py`: M2 and M4 both approve changes.
- API change: update `docs/api-contracts.md` and `tests/test_api_contract.py` in the same PR.
- New setting: update `core/config.py` and `.env.example` in the same PR.
- Dependencies: a one-line PR plus the lockfile. On a `package-lock.json` conflict, re-run `npm install`.
- Changing a public `service.py` signature needs Lead approval and every consumer's agreement.

Coding rules everyone follows (see [integration-guide.md §4](integration-guide.md#4-integration-points-where-modules-touch)):
`db: DbSession` in every route; never `commit()` in services; reject by **raising**;
call `record_event` before raising on a denial; build the whole response before
returning; use `NormalizedEmail` for email inputs.

## 6. Definition of done

A module is done only when **all** of these are true:
- [ ] Every endpoint for the module in `api-contracts.md` works, and its block is
      removed from `tests/test_not_implemented.py`.
- [ ] Tests in `tests/modules/test_<name>.py` cover the happy path **and** negative/attack
      cases, and pass in CI on SQLite and PostgreSQL.
- [ ] Follows `security-design.md` (or the PR updates it with the reason).
- [ ] Security-relevant actions call `record_event`, including denials and failures.
- [ ] No secrets in code, tests or logs; configuration comes from `get_settings()`.
- [ ] The frontend page works against the real backend.
- [ ] `MODULE_INFO.implemented = True` (the honesty test fails if any endpoint is still a stub).
- [ ] A short design and limitations write-up in `docs/modules/m<N>-<name>.md`.
- [ ] The module card's "Done when" criterion is met
      ([module cards](module-ownership.md#module-cards)).

## 7. First-week implementation order

All of these are independent, so every member can start on day 1. Use mocks for
anything not merged yet ([integration-guide.md §4.10](integration-guide.md#410-mocking-a-dependency-that-isnt-merged-yet)).

| Day | Merge target | Work (pure functions and unit tests first, endpoints later) |
|---|---|---|
| 1 | — | Everyone: setup, green tests, read your card, open an issue for your plan |
| 1–3 | **M1** first | `hash_password`/`verify_password`, then `get_current_user` (**this unblocks every protected endpoint**) |
| 1–3 | **M3** first | Key generation, KEK-encrypted storage, `wrap`/`unwrap` (unblocks M2, M4, M5) |
| 1–3 | M2, M4 | `encrypt_bytes`/`decrypt_bytes`; `build_manifest`/`sign`/`verify` |
| 1–3 | M6 | `compute_entry_hash`, `append_entries` with locking, `verify_chain` |
| 1–5 | M10 | Security-header middleware, dev certs, nginx config; **verify Docker Compose** |
| 1–5 | M7, M8 | M7: feature extraction on synthetic events; M8: redaction and prompt building with a fake provider |
| 1–5 | M9 | Turn each skipped attack test into a real (still skipped) test body with exact assertions |
| 4–5 | M5 | Owner grants and `require_access` (after M1 and M3 merge); M2 then wires upload/download |

Week 2 onward: M2 upload/download end to end → M5 sharing → M6 `/audit` endpoints →
M7 on real audit data → M8 over audit and anomalies → M9 enables its attack tests as
features land. The longer schedule is in [module-ownership.md](module-ownership.md#suggested-schedule-adjust-to-your-deadline).
