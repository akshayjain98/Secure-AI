"""API test fixtures: a real app wired to the test database, with an in-memory outbox."""

from __future__ import annotations

from collections.abc import Callable, Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from psycopg_pool import ConnectionPool

from app.api.email import OutboxEmailSender
from app.api.main import create_app
from app.config import Settings
from app.db.dsn import psycopg_conninfo
from tests.conftest import TEST_DB

JWT_KEYS = {"k2": b"\x02" * 32, "k1": b"\x01" * 32}
PEPPER = b"\x07" * 32
PASSWORD = "test-only-password"  # seed users' password (tests/conftest.py)
CSRF = {"X-SecureAI-CSRF": "1"}
REFRESH_COOKIE = "__Secure-secureai_refresh"


@pytest.fixture(scope="session")
def pool() -> Iterator[ConnectionPool]:
    p = ConnectionPool(psycopg_conninfo("app", TEST_DB), kwargs={"autocommit": True},
                       min_size=1, max_size=4, open=True)
    yield p
    p.close()


@pytest.fixture
def settings() -> Settings:
    return Settings(env="development", jwt_keys=dict(JWT_KEYS), token_pepper=PEPPER,
                    public_url="https://app.example")


@pytest.fixture
def outbox() -> OutboxEmailSender:
    return OutboxEmailSender()


@pytest.fixture
def make_app(pool, outbox) -> Callable[[Settings], FastAPI]:
    return lambda s: create_app(s, pool=pool, mailer=outbox)


@pytest.fixture
def app(make_app, settings) -> FastAPI:
    return make_app(settings)


@pytest.fixture
def new_client(app) -> Callable[[], TestClient]:
    """Independent clients = independent cookie jars (e.g. attacker vs victim)."""
    clients: list[TestClient] = []

    def _new(target: FastAPI | None = None) -> TestClient:
        # https base URL: the refresh cookie is Secure and is not sent over http.
        c = TestClient(target or app, base_url="https://testserver")
        clients.append(c)
        return c
    yield _new
    for c in clients:
        c.close()


@pytest.fixture
def client(new_client) -> TestClient:
    return new_client()


def login(client: TestClient, email: str, password: str = PASSWORD) -> dict[str, str]:
    r = client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture
def auth_as(app) -> Callable[[str], dict[str, str]]:
    """Bearer headers for a seed user, minted with the app's own codec.

    Access tokens are stateless (signature + expiry), so this is equivalent to
    logging in, without paying for Argon2 in every resource test. Login itself
    is covered by test_auth_api.py.
    """
    import uuid

    from app.db.seed_dev import ID

    def _auth(user: str) -> dict[str, str]:
        token, _ = app.state.secureai.codec.issue(ID.user(user), uuid.uuid4())
        return {"Authorization": f"Bearer {token}"}
    return _auth


@pytest.fixture(autouse=True)
def _purge_api_created_rows(admin_conn) -> Iterator[None]:
    """API writes COMMIT, as in production. Delete everything that isn't seed
    data after each test, so later tests (incl. tests/db's exact-set assertions)
    always see pristine seed rows. Runs as the BYPASSRLS migrator."""
    yield
    from app.db.seed_dev import ID, PROJECTS, TASKS

    seed_tasks = [ID.task(k) for k in TASKS]
    seed_projects = [ID.project(k) for k in PROJECTS]
    seed_members = [(ID.project(k), ID.user(u)) for k, (*_, members) in PROJECTS.items()
                    for u, _ in members]
    with admin_conn.transaction():
        admin_conn.execute("DELETE FROM secureai.tasks WHERE NOT (id = ANY(%s))", (seed_tasks,))
        admin_conn.execute(
            "DELETE FROM secureai.project_members pm WHERE NOT EXISTS ("
            "SELECT 1 FROM unnest(%s::uuid[], %s::uuid[]) s(p, u) "
            "WHERE s.p = pm.project_id AND s.u = pm.user_id)",
            ([p for p, _ in seed_members], [u for _, u in seed_members]))
        admin_conn.execute("DELETE FROM secureai.projects WHERE NOT (id = ANY(%s))", (seed_projects,))
