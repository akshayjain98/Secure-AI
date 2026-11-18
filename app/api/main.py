"""FastAPI application factory.

Run (dev):  uv run uvicorn app.api.main:create_app --factory --port 8000
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from psycopg_pool import ConnectionPool

from app.api import routes_auth, routes_me
from app.api.deps import AppState
from app.api.email import ConsoleEmailSender, EmailSender
from app.api.ratelimit import RateLimited, RateLimiter
from app.auth.jwt_tokens import AccessTokenCodec
from app.auth.service import AuthService
from app.auth.tokens import TokenHasher
from app.config import Settings
from app.db.dsn import psycopg_conninfo

log = logging.getLogger("secureai.api")

# An API serves no HTML, so lock the browser down completely.
SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def create_app(settings: Settings | None = None, pool: ConnectionPool | None = None,
               mailer: EmailSender | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    owns_pool = pool is None
    if pool is None:
        # Autocommit: request code opens explicit transactions; auth flows need it.
        pool = ConnectionPool(psycopg_conninfo("app"), kwargs={"autocommit": True},
                              min_size=1, max_size=10, open=False,
                              check=ConnectionPool.check_connection)

    state = AppState(
        settings=settings,
        pool=pool,
        service=AuthService(TokenHasher(settings.token_pepper), settings.auth),
        codec=AccessTokenCodec(settings.jwt_keys, settings.issuer, settings.audience,
                               settings.access_ttl),
        limiter=RateLimiter(),
        mailer=mailer or ConsoleEmailSender(settings.is_production),
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if owns_pool:
            pool.open(wait=True)
        try:
            yield
        finally:
            if owns_pool:
                pool.close()

    docs = not settings.is_production
    app = FastAPI(title="SecureAI Workspace API", lifespan=lifespan,
                  docs_url="/docs" if docs else None, redoc_url=None,
                  openapi_url="/openapi.json" if docs else None)
    app.state.secureai = state

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        return response

    @app.exception_handler(RateLimited)
    async def rate_limited(_: Request, exc: RateLimited) -> JSONResponse:
        return JSONResponse({"detail": "Too many requests"}, status_code=429,
                            headers={"Retry-After": str(exc.retry_after)})

    @app.exception_handler(Exception)
    async def unhandled(_: Request, exc: Exception) -> JSONResponse:
        # Never leak SQL, stack traces or constraint names to the client.
        log.exception("unhandled error", exc_info=exc)
        return JSONResponse({"detail": "Internal server error"}, status_code=500)

    app.include_router(routes_auth.router)
    app.include_router(routes_me.router)
    return app
