"""Shared fixtures for database security tests.

The test database is rebuilt from scratch once per session:
  drop schemas -> alembic upgrade head -> load fictional seed data.

Two kinds of connections are used, and the distinction matters:
  * app_conn   - secureai_app, NOBYPASSRLS. This is what we are testing.
  * admin_conn - secureai_migrator, BYPASSRLS. Only for arranging fixtures and
                 for verifying ground truth "behind" RLS.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import psycopg
import pytest
from alembic import command
from alembic.config import Config

from app.auth.passwords import hash_password
from app.db import seed_dev
from app.db.dsn import psycopg_conninfo, sqlalchemy_url, testing_database_name
from app.db.seed_dev import ID

ROOT = Path(__file__).resolve().parents[1]
TEST_DB = testing_database_name()


@pytest.fixture(scope="session", autouse=True)
def _database() -> Iterator[None]:
    with psycopg.connect(psycopg_conninfo("migrator", TEST_DB), autocommit=True) as conn:
        conn.execute("DROP SCHEMA IF EXISTS secureai_auth CASCADE")
        conn.execute("DROP SCHEMA IF EXISTS secureai_rls CASCADE")
        conn.execute("DROP SCHEMA IF EXISTS secureai CASCADE")
        conn.execute("DROP TABLE IF EXISTS secureai_migrations.alembic_version")

    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.attributes["sqlalchemy_url"] = sqlalchemy_url("migrator", TEST_DB)
    command.upgrade(cfg, "head")

    seed_dev.seed(psycopg_conninfo("migrator", TEST_DB), password="test-only-password")
    yield


@pytest.fixture
def app_conn() -> Iterator[psycopg.Connection]:
    with psycopg.connect(psycopg_conninfo("app", TEST_DB), autocommit=True) as conn:
        yield conn


@pytest.fixture
def admin_conn() -> Iterator[psycopg.Connection]:
    with psycopg.connect(psycopg_conninfo("migrator", TEST_DB), autocommit=True) as conn:
        yield conn


@contextmanager
def as_user(
    conn: psycopg.Connection, user: str, org: str | None = None, *, commit: bool = False
) -> Iterator[psycopg.Connection]:
    """Run a block as `user` in `org`, inside one transaction.

    Rolled back by default so tests never leak state; pass commit=True when a
    later transaction (e.g. as another user) must observe the change.
    """
    with conn.transaction(force_rollback=not commit):
        conn.execute(
            "SELECT secureai_rls.set_context(%s, %s)",
            (ID.user(user), ID.org(org) if org else None),
        )
        yield conn


def ids(conn: psycopg.Connection, sql: str, params: tuple = ()) -> set:
    return {row[0] for row in conn.execute(sql, params).fetchall()}


def rowcount(conn: psycopg.Connection, sql: str, params: tuple = ()) -> int:
    cur = conn.execute(sql, params)
    return cur.rowcount


@dataclass(frozen=True)
class FreshUser:
    id: uuid.UUID
    email: str
    password: str


@pytest.fixture
def make_user(admin_conn) -> Callable[..., FreshUser]:
    """Create an isolated user, so lockout/reset tests never disturb seed users."""
    def _make(password: str = "correct-horse-battery-staple", status: str = "active",
              password_hash: str | None = None) -> FreshUser:
        uid = uuid.uuid4()
        email = f"user-{uid.hex[:12]}@test.example"
        admin_conn.execute(
            "INSERT INTO secureai.users (id, email, display_name, status) VALUES (%s, %s, %s, %s)",
            (uid, email, "Test User", status))
        admin_conn.execute(
            "INSERT INTO secureai.user_credentials (user_id, password_hash) VALUES (%s, %s)",
            (uid, password_hash or hash_password(password)))
        return FreshUser(uid, email, password)
    return _make


@pytest.fixture
def new_app_conn() -> Callable[..., psycopg.Connection]:
    """Factory for extra app connections (concurrency tests). Closed at teardown."""
    conns: list[psycopg.Connection] = []

    def _open(autocommit: bool = True) -> psycopg.Connection:
        conn = psycopg.connect(psycopg_conninfo("app", TEST_DB), autocommit=autocommit)
        conns.append(conn)
        return conn
    yield _open
    for conn in conns:
        conn.close()
