"""Request-scoped dependencies: app state, client info, authentication, RLS transaction."""

from __future__ import annotations

import ipaddress
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Annotated

import psycopg
from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from psycopg import errors
from psycopg_pool import ConnectionPool

from app.api.email import EmailSender
from app.api.ratelimit import RateLimiter
from app.auth.jwt_tokens import AccessClaims, AccessTokenCodec, InvalidAccessToken
from app.auth.service import AuthService, ClientInfo
from app.config import Settings


@dataclass
class AppState:
    settings: Settings
    pool: ConnectionPool
    service: AuthService
    codec: AccessTokenCodec
    limiter: RateLimiter
    mailer: EmailSender


def get_state(request: Request) -> AppState:
    return request.app.state.secureai


State = Annotated[AppState, Depends(get_state)]


def _peer_ip(request: Request) -> str | None:
    """The direct peer, validated. Non-IP peers (unix sockets, test clients) -> None.

    X-Forwarded-For is client-controlled and is honoured ONLY behind a trusted
    proxy, through uvicorn --forwarded-allow-ips, never parsed here.
    """
    host = request.client.host if request.client else None
    try:
        return str(ipaddress.ip_address(host)) if host else None
    except ValueError:
        return None


def client_info(request: Request) -> ClientInfo:
    return ClientInfo(
        ip=_peer_ip(request),
        user_agent=(request.headers.get("user-agent") or "")[:512] or None,
        request_id=getattr(request.state, "request_id", None),
    )


Client = Annotated[ClientInfo, Depends(client_info)]

_bearer = HTTPBearer(auto_error=False)
_UNAUTHENTICATED = HTTPException(
    status.HTTP_401_UNAUTHORIZED, "Not authenticated", headers={"WWW-Authenticate": "Bearer"})


def current_claims(
    state: State,
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> AccessClaims:
    if creds is None or creds.scheme.lower() != "bearer":
        raise _UNAUTHENTICATED
    try:
        return state.codec.verify(creds.credentials)
    except InvalidAccessToken:
        raise _UNAUTHENTICATED from None


Claims = Annotated[AccessClaims, Depends(current_claims)]


def rls_connection(
    state: State,
    claims: Claims,
    client: Client,
    x_org_id: Annotated[uuid.UUID | None, Header()] = None,
) -> Iterator[psycopg.Connection]:
    """One transaction per request with the verified identity bound by set_context().

    The org comes from the X-Org-Id header and is NOT trusted: set_context()
    re-checks that the membership and the org are active, and raises if not.
    The context is transaction-local (SET LOCAL semantics), so a pooled
    connection can never carry it into the next request.
    """
    with state.pool.connection() as conn, conn.transaction():
        if client.request_id:
            conn.execute("SELECT set_config('secureai.request_id', %s, true)", (client.request_id,))
        try:
            conn.execute("SELECT secureai_rls.set_context(%s, %s)", (claims.user_id, x_org_id))
        except errors.InsufficientPrivilege:
            if x_org_id is not None:
                raise HTTPException(status.HTTP_403_FORBIDDEN, "No access to this organization") from None
            raise _UNAUTHENTICATED from None
        yield conn


# scope="function": COMMIT happens before the response is sent, so a client
# never sees 200 for a write that then fails to commit.
RlsConn = Annotated[psycopg.Connection, Depends(rls_connection, scope="function")]
