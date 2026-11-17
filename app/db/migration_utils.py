"""Helpers for raw-SQL Alembic migrations."""

from alembic import op


def run_sql(sql: str) -> None:
    """Execute a SQL script verbatim on the migration connection.

    Uses the raw DBAPI cursor with *no* parameters so psycopg does not try to
    interpret '%' (LIKE patterns, format()) or ':' inside SQL literals as
    placeholders. It shares the migration's transaction.
    """
    cursor = op.get_bind().connection.dbapi_connection.cursor()
    try:
        cursor.execute(sql)
    finally:
        cursor.close()
