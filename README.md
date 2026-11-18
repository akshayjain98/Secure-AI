# SecureAI Workspace

A production-oriented learning project for authentication, authorization,
database security, multi-tenancy, API security and AI application security.

| Phase | Scope | Status |
|---|---|---|
| 1 | Database architecture, RBAC model, PostgreSQL RLS, seed data, DB security tests | ✅ done |
| 2 | Authentication (Argon2id, JWT, refresh rotation/reuse detection, reset) | ✅ done |
| 3 | Authorization APIs (projects, tasks, documents, members, audit) on RLS | ✅ done |
| 4+ | AI/LLM security, frontend | planned |

Start with **[docs/phase-1-database-architecture.md](docs/phase-1-database-architecture.md)**, then
**[docs/phase-2-authentication.md](docs/phase-2-authentication.md)** and
**[docs/phase-3-authorization-apis.md](docs/phase-3-authorization-apis.md)**.

## Quick start

Requirements: Docker, [uv](https://docs.astral.sh/uv/).

```bash
cp .env.example .env     # replace every secret (openssl rand -hex 24)
docker compose up -d --wait
uv sync
# existing volume from before Phase 2? run once first:
#   docker exec -i secureai-postgres bash < docker/postgres/upgrades/0004_auth_definer_role.sh
uv run alembic upgrade head
uv run python -m app.db.seed_dev     # prints a generated dev password once
uv run pytest -v                     # uses the separate secureai_test database
uv run uvicorn app.api.main:create_app --factory --port 8000   # API, docs at /docs
```

Postgres listens on `127.0.0.1:55432` only. The application will connect as
`secureai_app` (NOBYPASSRLS); migrations and seeding use `secureai_migrator`.

## Layout

```
docker/postgres/init/00-bootstrap.sh   one-time superuser bootstrap: roles + databases
migrations/versions/0001_*             tables, constraints, composite FKs
migrations/versions/0002_*             grants, RLS helpers, policies, invariant triggers
migrations/versions/0003_*             roles, permissions, role->permission matrix
migrations/versions/0004_*             secureai_auth: login, refresh rotation, reset (definer fns)
migrations/versions/0005_*             registration + email verification, request ids, last-admin guard
migrations/versions/0006_*             invite resolver, invite-only memberships, logout on removal
migrations/versions/0007_*             write-audit triggers on every tenant table
app/auth/                              argon2id + policy, opaque tokens, JWT, auth flows
app/api/                               FastAPI: /auth/*, /me, /orgs/{org} (+members, overrides, projects, tasks, documents, audit-logs) on RLS
app/db/seed_dev.py                     fictional dev/test data (refuses in production)
tests/db/                              DB-level security tests (RLS, grants, escalation, auth fns)
tests/auth/                            auth primitives + end-to-end auth flows
tests/api/                             HTTP-level tests (auth, IDOR, tenancy, mass assignment)
docs/                                  architecture + security documentation
```
