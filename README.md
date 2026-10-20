# secure-file-sharing-system

**Secure File Sharing System** is a Cryptography and Network Security college
project. It is one web application (React frontend, FastAPI backend,
PostgreSQL database) built by ten members. Each member owns one security
module.

> **Project status: foundation only.** The architecture, database schema, API
> contracts and skeleton are in place. **None of the ten security modules is
> implemented yet.** Every module endpoint returns `501 not_implemented`, and
> the Module Status page in the UI shows exactly what is built.

| # | Module | Status |
|---|---|---|
| 1 | Authentication & Argon2id password security | not implemented |
| 2 | AES-256-GCM file encryption | not implemented |
| 3 | RSA-OAEP key management | not implemented |
| 4 | RSA-PSS digital signatures | not implemented |
| 5 | Secure file sharing & access control | not implemented |
| 6 | Tamper-evident audit logging | not implemented |
| 7 | Isolation Forest anomaly detection | not implemented |
| 8 | LLM-based security event analysis | not implemented |
| 9 | Cryptographic verification & attack testing | not implemented |
| 10 | HTTPS/TLS & transport security | not implemented |

## Documentation

**New team members: start with [docs/team-start-guide.md](docs/team-start-guide.md).**

| Doc | Contents |
|---|---|
| [docs/team-start-guide.md](docs/team-start-guide.md) | Assignments, workflow, setup commands (PowerShell and macOS/Linux), definition of done, first-week order |
| [docs/architecture.md](docs/architecture.md) | Repository layout, request pipelines, database design, module interfaces, frontend, testing |
| [docs/api-contracts.md](docs/api-contracts.md) | Every endpoint, request/response schema and error code |
| [docs/security-design.md](docs/security-design.md) | Threat model and the exact cryptographic parameters for each module |
| [docs/module-ownership.md](docs/module-ownership.md) | File ownership, module cards (inputs/outputs, dependencies, tests, done criteria), schedule |
| [docs/integration-guide.md](docs/integration-guide.md) | Git workflow, transaction and audit rules, migrations, test fixtures, integration points |

## Tech stack

React 19 + Vite + Tailwind CSS v4 · Python 3.12 + FastAPI · PostgreSQL 16 ·
SQLAlchemy 2 + Alembic · Pytest + HTTPX · Vitest · scikit-learn · Docker Compose · nginx (TLS)

## Quick start (local, without Docker)

Windows PowerShell versions of these commands are in
[docs/team-start-guide.md §3](docs/team-start-guide.md#3-setup-and-everyday-commands).

Prerequisites:

- **Python 3.12+**
- **Node 20.19+ or 22.12+** (required by Vite)
- **PostgreSQL 16**: either install it locally, or run only the database with
  Docker using `docker compose up -d db`, which listens on `127.0.0.1:5432`.
  SQLite is used for tests only.

```bash
cp .env.example .env        # fill in the empty secrets and the password in DATABASE_URL

cd backend
python -m venv .venv
source .venv/bin/activate    # macOS / Linux
# .venv\Scripts\Activate.ps1 # Windows PowerShell   (cmd: .venv\Scripts\activate.bat,
#                            #  Git Bash: source .venv/Scripts/activate)
pip install -r requirements-dev.txt
pytest                       # backend tests (in-memory SQLite, no database needed)
alembic upgrade head         # creates the tables; reads DATABASE_URL from .env
uvicorn --factory app.main:create_app --reload

cd ../frontend
npm install
npm test                     # frontend tests
npm run dev                  # http://localhost:5173 (proxies /api to :8000)
```

API docs while the backend runs: http://localhost:8000/api/docs

### First admin account

The audit, anomaly, analysis and verification endpoints require the `admin`
role. Register normally (this needs Module 1), then promote that account from
`backend/`. The first command is a dry run that shows the matched account; the
second applies the change:

```bash
python -m app.cli promote-admin you@example.edu
python -m app.cli promote-admin you@example.edu --yes
```

Inactive or locked accounts are refused, and the last active admin can't be demoted.

## Quick start (Docker Compose): not yet verified

> **Nobody has run the Compose setup yet** (Docker wasn't available while it was
> written). Its configuration has been reviewed and the YAML parses, but treat it as
> untested until someone with Docker runs it and reports back (M10 owns this check).

```bash
cp .env.example .env         # fill in POSTGRES_PASSWORD, JWT_SECRET_KEY, MASTER_KEY_ENCRYPTION_KEY, AUDIT_HMAC_KEY
docker compose up --build    # http://localhost:5173
```

As configured, the backend container runs `alembic upgrade head` on start and
uvicorn with `--reload` on the read-only mounted `backend/app` (polling, for
Windows and macOS hosts). A change to `requirements.txt` needs
`docker compose up --build`. The admin command would be
`docker compose exec backend python -m app.cli promote-admin you@example.edu`
(add `--yes` after checking the dry-run output).

HTTPS through the nginx proxy, serving the production frontend build (Module 10; configuration statically tested, **not yet run with Docker**):

```bash
sh scripts/gen-dev-certs.sh
docker compose --profile tls up --build    # https://localhost
```

## Security rules for contributors

- Never commit `.env`, private keys, certificates or API keys. `.gitignore`
  blocks the common cases, but check `git status` before every commit anyway.
- Never mark a module implemented, or claim a feature works, until its code
  and tests are merged.
- All work goes through pull requests into `develop`. Nobody pushes directly
  to `develop` or `main` (see docs/integration-guide.md).
