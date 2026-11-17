"""Database connection parameters, built from environment variables.

Two distinct credentials exist and they must never be swapped:

* ``migrator`` - BYPASSRLS ops role. Alembic, seed scripts, test setup only.
* ``app``      - NOBYPASSRLS role used by the API server. Every query it runs
                 is subject to Row-Level Security.
"""

from __future__ import annotations

import os
from typing import Literal

from dotenv import load_dotenv
from psycopg.conninfo import make_conninfo
from sqlalchemy.engine import URL

load_dotenv()

Role = Literal["migrator", "app"]

_DB_USERS: dict[Role, str] = {
    "migrator": "secureai_migrator",
    "app": "secureai_app",
}


def _require(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Required environment variable {name} is not set")
    return value


def database_name() -> str:
    return os.environ.get("SECUREAI_DB_NAME", "secureai")


def testing_database_name() -> str:
    name = os.environ.get("SECUREAI_TEST_DB_NAME", "secureai_test")
    if name == database_name():
        raise RuntimeError("Test database must differ from the main database")
    return name


def _params(role: Role, database: str | None) -> dict[str, str | int]:
    return {
        "host": os.environ.get("SECUREAI_DB_HOST", "127.0.0.1"),
        "port": int(os.environ.get("SECUREAI_DB_PORT", "55432")),
        "dbname": database or database_name(),
        "user": _DB_USERS[role],
        "password": _require(f"SECUREAI_{role.upper()}_PASSWORD"),
        "sslmode": os.environ.get("SECUREAI_DB_SSLMODE", "prefer"),
        "application_name": f"secureai-{role}",
    }


def psycopg_conninfo(role: Role, database: str | None = None) -> str:
    return make_conninfo(**_params(role, database))


def sqlalchemy_url(role: Role, database: str | None = None) -> URL:
    p = _params(role, database)
    return URL.create(
        "postgresql+psycopg",
        username=str(p["user"]),
        password=str(p["password"]),
        host=str(p["host"]),
        port=int(p["port"]),
        database=str(p["dbname"]),
        query={"sslmode": str(p["sslmode"]), "application_name": str(p["application_name"])},
    )
