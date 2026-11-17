# SecureAI Workspace

A production-oriented learning project for authentication, authorization,
database security, multi-tenancy, API security and AI application security.

| Phase | Scope | Status |
|---|---|---|
| 1 | Database architecture, RBAC model, PostgreSQL RLS, seed data, DB security tests | ✅ done |
| 2 | Authentication (Argon2id, JWT, refresh rotation/reuse detection, reset) | pending approval |
| 3+ | FastAPI authorization services, API tests, AI/LLM security, frontend | planned |

Start with **[docs/phase-1-database-architecture.md](docs/phase-1-database-architecture.md)**.

## Quick start

Requirements: Docker, [uv](https://docs.astral.sh/uv/).

```bash
cp .env.example .env     # replace every secret (openssl rand -hex 24)
docker compose up -d --wait
uv sync
uv run alembic upgrade head
uv run python -m app.db.seed_dev     # prints a generated dev password once
uv run pytest -v                     # uses the separate secureai_test database
```

Postgres listens on `127.0.0.1:55432` only. The application will connect as
`secureai_app` (NOBYPASSRLS); migrations and seeding use `secureai_migrator`.

## Layout

```
docker/postgres/init/00-bootstrap.sh   one-time superuser bootstrap: roles + databases
migrations/versions/0001_*             tables, constraints, composite FKs
migrations/versions/0002_*             grants, RLS helpers, policies, invariant triggers
migrations/versions/0003_*             roles, permissions, role->permission matrix
app/db/seed_dev.py                     fictional dev/test data (refuses in production)
tests/db/                              DB-level security tests (RLS, grants, escalation)
docs/                                  architecture + security documentation
```
