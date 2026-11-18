"""/auth endpoints.

Response rules (account-enumeration resistance):
* login: every failure is 401 "Invalid email or password". Unknown, locked,
  inactive and wrong password can't be told apart (body, status or timing).
* password reset request: always 202 with the same body. The DB work and
  the email run in a background task, so latency doesn't leak the outcome.
* refresh: every failure is 401 and clears the cookie.

Refresh token transport: an HttpOnly, Secure, SameSite=Strict cookie scoped to
Path=/auth, so JavaScript can't read it and the browser sends it only to
these endpoints. Cookie-authenticated endpoints (refresh, logout) also require
the X-SecureAI-CSRF header. A cross-site form or fetch can't set it without a
CORS preflight, which this API never approves.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Cookie, Header, HTTPException, Response, status
from psycopg import errors
from pydantic import BaseModel, ConfigDict, Field

from app.api.deps import AppState, Claims, Client, State
from app.api.email import reset_link, verify_link
from app.auth.passwords import PasswordPolicyError
from app.auth.service import (
    ClientInfo,
    InvalidCredentials,
    InvalidRefreshToken,
    InvalidResetToken,
    InvalidVerificationToken,
    RefreshTokenReuse,
    Session,
)
from app.auth.service import EMAIL_RE

log = logging.getLogger("secureai.auth")
router = APIRouter(prefix="/auth", tags=["auth"])

REFRESH_COOKIE = "__Secure-secureai_refresh"
COOKIE_PATH = "/auth"
CSRF_HEADER = "X-SecureAI-CSRF"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_max_length=1024)


class LoginIn(_Strict):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=1024)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int


class ResetRequestIn(_Strict):
    email: str = Field(min_length=3, max_length=320)


class ResetConfirmIn(_Strict):
    token: str = Field(min_length=10, max_length=128)
    new_password: str = Field(min_length=1, max_length=1024)


class ChangePasswordIn(_Strict):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=1, max_length=1024)


class RegisterIn(_Strict):
    email: str = Field(min_length=3, max_length=320)
    display_name: str = Field(min_length=1, max_length=200)


class VerifyEmailIn(_Strict):
    token: str = Field(min_length=10, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class Message(BaseModel):
    detail: str


# ------------------------------------------------------------------ helpers
def _issue_tokens(response: Response, state: AppState, session: Session) -> TokenOut:
    access, exp = state.codec.issue(session.user_id, session.family_id)
    max_age = int((session.refresh_expires_at - datetime.now(UTC)).total_seconds())
    response.set_cookie(
        REFRESH_COOKIE, session.refresh_token, max_age=max(max_age, 0), path=COOKIE_PATH,
        secure=True, httponly=True, samesite="strict")
    return TokenOut(access_token=access, expires_in=int(state.settings.access_ttl.total_seconds()))


def _clear_cookie(response: Response) -> None:
    response.delete_cookie(REFRESH_COOKIE, path=COOKIE_PATH, secure=True, httponly=True,
                           samesite="strict")


def _require_csrf_header(value: str | None) -> None:
    if value != "1":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Missing CSRF header")


def _norm(email: str) -> str:
    return email.strip().lower()


# ---------------------------------------------------------------- endpoints
@router.post("/login", response_model=TokenOut)
def login(body: LoginIn, response: Response, state: State, client: Client) -> TokenOut:
    s = state.settings
    state.limiter.hit("login_ip", client.ip, *s.login_per_ip)
    state.limiter.hit("login_email", _norm(body.email), *s.login_per_email)
    with state.pool.connection() as conn:
        try:
            session = state.service.login(conn, body.email, body.password, client)
        except InvalidCredentials:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password") from None
    return _issue_tokens(response, state, session)


_SESSION_EXPIRED = "Session expired, please sign in again"


@router.post("/refresh", response_model=TokenOut)
def refresh(
    response: Response, state: State, client: Client,
    csrf: Annotated[str | None, Header(alias=CSRF_HEADER)] = None,
    refresh_token: Annotated[str | None, Cookie(alias=REFRESH_COOKIE)] = None,
) -> TokenOut:
    _require_csrf_header(csrf)
    state.limiter.hit("refresh_ip", client.ip, *state.settings.refresh_per_ip)
    if not refresh_token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _SESSION_EXPIRED)
    with state.pool.connection() as conn:
        try:
            session = state.service.refresh(conn, refresh_token, client)
        except InvalidRefreshToken as exc:
            if isinstance(exc, RefreshTokenReuse):
                # Security alert: page on this (a stolen refresh token was replayed).
                log.warning("security_alert refresh_token_reuse", extra={
                    "event": "refresh_token_reuse", "user_id": str(exc.user_id),
                    "request_id": client.request_id, "ip": client.ip})
            # Raising would discard the Set-Cookie on `response`, so return an
            # explicit 401 that clears the cookie.
            err = Response(status_code=status.HTTP_401_UNAUTHORIZED,
                           content=Message(detail=_SESSION_EXPIRED).model_dump_json(),
                           media_type="application/json")
            _clear_cookie(err)
            return err  # type: ignore[return-value]
    return _issue_tokens(response, state, session)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    state: State, client: Client,
    csrf: Annotated[str | None, Header(alias=CSRF_HEADER)] = None,
    refresh_token: Annotated[str | None, Cookie(alias=REFRESH_COOKIE)] = None,
) -> Response:
    _require_csrf_header(csrf)
    if refresh_token:
        with state.pool.connection() as conn:
            state.service.logout(conn, refresh_token, client)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    _clear_cookie(response)
    return response


_RESET_ACCEPTED = "If an account exists for that email, a reset link has been sent."


def _process_reset_request(state: AppState, email: str, client: ClientInfo) -> None:
    """Background task. Never raises: failures are logged, the client already got 202."""
    try:
        with state.pool.connection() as conn:
            token = state.service.request_password_reset(conn, email, client)
        if token is not None:
            state.mailer.send_password_reset(_norm(email), reset_link(state.settings.public_url, token))
    except Exception:  # noqa: BLE001 - must not surface to the client
        log.exception("password reset request processing failed")


@router.post("/password-reset/request", status_code=status.HTTP_202_ACCEPTED, response_model=Message)
def request_reset(body: ResetRequestIn, background: BackgroundTasks, state: State,
                  client: Client) -> Message:
    state.limiter.hit("reset_ip", client.ip, *state.settings.reset_per_ip)
    background.add_task(_process_reset_request, state, body.email, client)
    return Message(detail=_RESET_ACCEPTED)


@router.post("/password-reset/confirm", status_code=status.HTTP_204_NO_CONTENT)
def confirm_reset(body: ResetConfirmIn, state: State, client: Client) -> None:
    state.limiter.hit("reset_confirm_ip", client.ip, *state.settings.reset_per_ip)
    with state.pool.connection() as conn:
        try:
            state.service.reset_password(conn, body.token, body.new_password, client)
        except PasswordPolicyError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from None
        except InvalidResetToken:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid or expired reset link") from None


@router.post("/password/change", status_code=status.HTTP_204_NO_CONTENT)
def change_password(body: ChangePasswordIn, claims: Claims, state: State, client: Client) -> None:
    state.limiter.hit("login_ip", client.ip, *state.settings.login_per_ip)
    with state.pool.connection() as conn:
        try:
            state.service.change_password(
                conn, claims.user_id, body.current_password, body.new_password,
                keep_family_id=claims.session_family_id, client=client)
        except PasswordPolicyError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from None
        except errors.InsufficientPrivilege:  # account disabled since the JWT was issued
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated") from None
        except InvalidCredentials:
            # 403, not 401: the session is fine, the confirmation is not.
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Current password is incorrect") from None


# ------------------------------------------------------------- registration
_REGISTER_ACCEPTED = "Check your inbox to finish creating your account."


def _process_registration(state: AppState, email: str, display_name: str, client: ClientInfo) -> None:
    """Background task: DB work + email after the uniform 202 has been sent."""
    try:
        with state.pool.connection() as conn:
            result = state.service.register(conn, email, display_name, client)
        if result.verification_token:
            state.mailer.send_email_verification(
                result.email, verify_link(state.settings.public_url, result.verification_token))
        elif result.outcome == "exists":
            # Tell the real owner, not the requester, that the account exists.
            state.mailer.send_account_exists(result.email, f"{state.settings.public_url}/reset-password")
    except Exception:  # noqa: BLE001
        log.exception("registration processing failed")


@router.post("/register", status_code=status.HTTP_202_ACCEPTED, response_model=Message)
def register(body: RegisterIn, background: BackgroundTasks, state: State, client: Client) -> Message:
    state.limiter.hit("register_ip", client.ip, *state.settings.register_per_ip)
    # Validate format synchronously: a 422 for a malformed address says nothing
    # about whether an account exists.
    from app.auth.service import EMAIL_RE
    email = _norm(body.email)
    if not EMAIL_RE.fullmatch(email) or not body.display_name.strip():
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Enter a valid email and name")
    background.add_task(_process_registration, state, email, body.display_name, client)
    return Message(detail=_REGISTER_ACCEPTED)


@router.post("/verify-email", status_code=status.HTTP_204_NO_CONTENT)
def verify_email(body: VerifyEmailIn, state: State, client: Client) -> None:
    """Proves inbox ownership and sets the password. The user then signs in."""
    state.limiter.hit("register_ip", client.ip, *state.settings.register_per_ip)
    with state.pool.connection() as conn:
        try:
            state.service.verify_email(conn, body.token, body.password, client)
        except PasswordPolicyError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from None
        except InvalidVerificationToken:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid or expired verification link") from None
