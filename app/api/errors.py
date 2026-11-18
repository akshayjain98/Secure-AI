"""Turn database refusals into HTTP responses without leaking schema details.

The database is the authorization engine, so most "no" answers arrive as
PostgreSQL errors. Raw messages name tables, policies and constraints
("new row violates row-level security policy for table \"tasks\""), which is
reconnaissance data for an attacker. Each one becomes a short, generic
message. Only our own trigger messages (prefix ``secureai:``) are shown,
because they were written for humans and describe a rule, not the schema.

| SQLSTATE | Source                                     | HTTP |
|----------|--------------------------------------------|------|
| 42501    | WITH CHECK / column grant / our triggers   | 403 (last-admin: 409) |
| 23503    | FK: RESTRICT on delete, dangling reference | 409  |
| 23505    | UNIQUE                                     | 409  |
| 23514, 23502, 22xxx | CHECK / NOT NULL / bad value     | 422  |

RLS USING failures don't raise at all; UPDATE/DELETE just affect 0 rows. See
app/api/rows.py for how those become 404 or 403.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from psycopg import errors

log = logging.getLogger("secureai.api")

_OUR_PREFIX = "secureai: "
_LAST_ADMIN = "at least one active administrator"


def _primary(exc: errors.Error) -> str:
    diag = exc.diag.message_primary if exc.diag else None
    return diag or str(exc)


def _respond(status: int, detail: str) -> JSONResponse:
    return JSONResponse({"detail": detail}, status_code=status)


def install(app: FastAPI) -> None:
    @app.exception_handler(errors.InsufficientPrivilege)
    async def insufficient_privilege(_: Request, exc: errors.InsufficientPrivilege) -> JSONResponse:
        msg = _primary(exc)
        if msg.startswith(_OUR_PREFIX):
            rule = msg.removeprefix(_OUR_PREFIX)
            if _LAST_ADMIN in rule:
                return _respond(409, "An organization must keep at least one active administrator")
            return _respond(403, rule[:1].upper() + rule[1:])
        if msg.startswith("permission denied"):
            # A column/table grant refused the statement. The request models
            # should make this unreachable, so it points to a code bug.
            log.warning("privilege error reached the API: %s", msg)
        return _respond(403, "Not allowed")

    @app.exception_handler(errors.ForeignKeyViolation)
    async def fk_violation(_: Request, exc: errors.ForeignKeyViolation) -> JSONResponse:
        return _respond(409, "Conflicts with related records")

    @app.exception_handler(errors.UniqueViolation)
    async def unique_violation(_: Request, exc: errors.UniqueViolation) -> JSONResponse:
        return _respond(409, "Already exists")

    async def invalid(_: Request, exc: errors.Error) -> JSONResponse:
        return _respond(422, "Invalid value")

    for cls in (errors.CheckViolation, errors.NotNullViolation, errors.DataError):
        app.add_exception_handler(cls, invalid)
