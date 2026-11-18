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
