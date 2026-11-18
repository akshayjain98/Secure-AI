"""Keyset pagination over RLS-filtered result sets.

OFFSET pagination makes PostgreSQL produce and discard every skipped row, and
under RLS that means evaluating policies for each of them, so page 500 costs
500 pages of work. Keyset pagination resumes from the last row seen:

    WHERE (created_at, id) < (:last_created_at, :last_id)
    ORDER BY created_at DESC, id DESC LIMIT :n

``id`` breaks ties between rows with the same timestamp.

The cursor is an opaque base64url blob, but it's not a security boundary and
needs no signature. It only says where to resume, the query is still
RLS-filtered, and a forged cursor can't return a row the caller couldn't
already list. Malformed cursors are a 422.
"""

from __future__ import annotations

import base64
import binascii
import json
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Any, Generic, LiteralString, TypeVar

import psycopg
from fastapi import Depends, HTTPException, Query, status
from psycopg.rows import dict_row
from pydantic import BaseModel

T = TypeVar("T")

DEFAULT_LIMIT = 50
MAX_LIMIT = 100


class Page(BaseModel, Generic[T]):
    items: list[T]
    next_cursor: str | None


@dataclass(frozen=True)
class PageParams:
    after: tuple[datetime, uuid.UUID] | None
    limit: int


def encode_cursor(created_at: datetime, row_id: uuid.UUID) -> str:
    raw = json.dumps([created_at.isoformat(), str(row_id)]).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime, uuid.UUID]:
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        ts, rid = json.loads(raw)
        at = datetime.fromisoformat(ts)
        if at.tzinfo is None:
            raise ValueError("naive timestamp")
        return at, uuid.UUID(rid)
    except (binascii.Error, ValueError, TypeError, UnicodeDecodeError):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Invalid cursor") from None


def page_params(
    cursor: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
) -> PageParams:
    return PageParams(decode_cursor(cursor) if cursor else None, limit)


Paging = Annotated[PageParams, Depends(page_params)]


def paginate(conn: psycopg.Connection, select: LiteralString, where: list[LiteralString],
             params: Sequence[Any], page: PageParams,
             build: Callable[[dict[str, Any]], T], ts: LiteralString = "created_at") -> Page[T]:
    """``select`` is "SELECT ... FROM one_table"; every fragment is a code constant.
    ``ts`` is the timestamp column the keyset orders on (audit_logs: occurred_at)."""
    clauses = list(where)
    args = list(params)
    if page.after is not None:
        clauses.append(f"({ts}, id) < (%s, %s)")
        args.extend(page.after)
    sql = select + (" WHERE " + " AND ".join(clauses) if clauses else "")
    sql += f" ORDER BY {ts} DESC, id DESC LIMIT %s"
    rows = conn.cursor(row_factory=dict_row).execute(sql, [*args, page.limit + 1]).fetchall()

    more = len(rows) > page.limit
    rows = rows[:page.limit]
    nxt = encode_cursor(rows[-1][ts], rows[-1]["id"]) if more else None
    return Page[Any](items=[build(r) for r in rows], next_cursor=nxt)
