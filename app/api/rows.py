"""404-versus-403 for RLS-filtered reads and writes.

Under RLS, a row you can't see and a row that doesn't exist look the same:
SELECT returns nothing and UPDATE/DELETE affect 0 rows, with no error.

* Not visible -> **404**. Never confirm that a hidden id exists, whether it's
  another user's private task or another tenant's project.
* Visible but the write affected 0 rows -> **403**. The caller can already
  read the row, so saying "you may not change it" reveals nothing new, and
  it is a much better answer than a confusing 404 for something they can see.

The visibility probe runs in the same transaction and under the same RLS
context as the write, so it answers exactly the caller's question.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, LiteralString

import psycopg
from fastapi import HTTPException, status
from psycopg.rows import dict_row

NOT_ALLOWED = "Not allowed"


def not_found(what: str) -> HTTPException:
    return HTTPException(status.HTTP_404_NOT_FOUND, f"{what} not found")


def fetch_one(conn: psycopg.Connection, query: LiteralString | Any, params: Sequence[Any],
              what: str) -> dict[str, Any]:
    row = conn.cursor(row_factory=dict_row).execute(query, params).fetchone()
    if row is None:
        raise not_found(what)
    return row


def write_or_404(conn: psycopg.Connection, query: LiteralString | Any, params: Sequence[Any], *,
                 table: LiteralString, row_id: Any, what: str) -> dict[str, Any]:
    """Run an UPDATE/DELETE ... RETURNING. 0 rows -> 403 if visible, else 404."""
    row = conn.cursor(row_factory=dict_row).execute(query, params).fetchone()
    if row is not None:
        return row
    raise_hidden_or_forbidden(conn, table, row_id, what)
    raise AssertionError("unreachable")


def raise_hidden_or_forbidden(conn: psycopg.Connection, table: LiteralString, row_id: Any,
                              what: str) -> None:
    visible = conn.execute(
        f"SELECT EXISTS (SELECT 1 FROM secureai.{table} WHERE id = %s)", (row_id,)).fetchone()[0]
    if visible:
        raise HTTPException(status.HTTP_403_FORBIDDEN, NOT_ALLOWED)
    raise not_found(what)
