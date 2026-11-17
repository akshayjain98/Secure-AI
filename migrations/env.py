"""Alembic environment.

Security notes:
* Connects as ``secureai_migrator`` (never as the application role).
* Immediately ``SET ROLE secureai_owner`` so every object created is owned by
  the NOLOGIN owner role, not by a login role.
* Offline (SQL-script) mode is disabled: the RLS migration switches roles
  mid-transaction and must run against a live database.
"""

from __future__ import annotations

from alembic import context
from sqlalchemy import create_engine, pool

from app.db.dsn import sqlalchemy_url

config = context.config


def run_migrations_online() -> None:
    url = config.attributes.get("sqlalchemy_url") or sqlalchemy_url("migrator")
    engine = create_engine(url, poolclass=pool.NullPool)
    with engine.connect() as connection:
        connection.exec_driver_sql("SET ROLE secureai_owner")
        connection.exec_driver_sql("SET lock_timeout = '10s'")
        connection.exec_driver_sql("SET search_path = pg_catalog")
        connection.commit()

        context.configure(
            connection=connection,
            target_metadata=None,
            version_table_schema="secureai_migrations",
            transaction_per_migration=True,
        )
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    raise RuntimeError("Offline migrations are not supported for this project")

run_migrations_online()
