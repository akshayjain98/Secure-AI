"""Authentication flows on top of the secureai_auth database functions.

The HTTP layer (next step) will be a thin wrapper around these functions. It
must map every AuthError subclass to ONE generic client response; the
subclasses exist for logging and metrics, never for the client.

Connections must be in autocommit mode. Each flow controls its own
transaction boundaries because some of them are security-relevant:

* login: the attempt counter is COMMITTED before the slow Argon2 verification,
  so a crashed or aborted request still counts, and no row lock is held while
  hashing.
* refresh: a reuse-detected revocation is committed before the error is raised.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Literal

import psycopg

from app.auth import passwords
from app.auth.breach import BreachChecker, NoBreachCheck
from app.auth.tokens import TokenHasher, is_well_formed, new_token

# Mirrors the users.email CHECK constraint, so bad input is a 422, not a DB error.
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@dataclass(frozen=True)
class AuthSettings:
    refresh_idle_ttl: timedelta = timedelta(days=14)
    reset_ttl: timedelta = timedelta(minutes=30)
    verify_ttl: timedelta = timedelta(hours=24)


@dataclass(frozen=True)
class ClientInfo:
    ip: str | None = None
    user_agent: str | None = None
    # Server-generated per request; stamped onto every audit row (audit_logs.request_id).
    request_id: str | None = None


class AuthError(Exception):
    """Base class. Clients only ever see a generic message."""


class InvalidCredentials(AuthError):
    pass


class InvalidRefreshToken(AuthError):
    def __init__(self, outcome: str, user_id: uuid.UUID | None = None):
        super().__init__(outcome)
        self.outcome = outcome
        self.user_id = user_id  # for security alerting only, never for the client


class RefreshTokenReuse(InvalidRefreshToken):
    """A rotated token was replayed; the whole family has been revoked."""


class InvalidResetToken(AuthError):
    pass


class InvalidVerificationToken(AuthError):
    pass


RegistrationOutcome = Literal["created", "resent", "exists", "suppressed", "rate_limited"]


@dataclass(frozen=True)
class RegistrationResult:
    """What the API should email. The HTTP response is the same for every outcome."""
    outcome: RegistrationOutcome
    email: str
    verification_token: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class Session:
    user_id: uuid.UUID
    family_id: uuid.UUID
    refresh_token: str = field(repr=False)
    refresh_expires_at: datetime


def _require_autocommit(conn: psycopg.Connection) -> None:
    if not conn.autocommit:
        raise RuntimeError("auth flows require an autocommit connection")


@contextmanager
def _tx(conn: psycopg.Connection, client: ClientInfo) -> Iterator[None]:
    """A transaction whose audit rows carry the request id (transaction-local GUC)."""
    with conn.transaction():
        if client.request_id:
            conn.execute("SELECT set_config('secureai.request_id', %s, true)", (client.request_id,))
        yield


@dataclass
class AuthService:
    token_hasher: TokenHasher
    settings: AuthSettings = field(default_factory=AuthSettings)
    breach_checker: BreachChecker = field(default_factory=NoBreachCheck)

    def _validate_new_password(self, password: str, email: str | None = None) -> None:
        """Policy first (cheap, local), then the breach corpus (network, fail-open)."""
        passwords.validate_policy(password, email=email)
        if self.breach_checker.is_breached(password):
            raise passwords.PasswordPolicyError(
                "This password appears in a known data breach. Please choose a different one.")

    # ------------------------------------------------------------------ login
    def _verify_password(self, conn: psycopg.Connection, email: str, password: str,
                         client: ClientInfo) -> uuid.UUID:
        """begin_login -> argon2 verify -> complete_login. Returns the user id."""
        with _tx(conn, client):
            outcome, user_id, stored_hash = conn.execute(
                "SELECT outcome, user_id, password_hash "
                "FROM secureai_auth.begin_login(%s, %s::inet, %s)",
                (email, client.ip, client.user_agent)).fetchone()

        if outcome != "ok":
            passwords.dummy_verify(password)  # equalise timing with the 'ok' path
            raise InvalidCredentials(outcome)

        ok = passwords.verify_password(stored_hash, password)
        rehashed = passwords.hash_password(password) if ok and passwords.needs_rehash(stored_hash) else None
        with _tx(conn, client):
            conn.execute(
                "SELECT secureai_auth.complete_login(%s, %s, %s, %s::inet, %s)",
                (user_id, ok, rehashed, client.ip, client.user_agent))
        if not ok:
            raise InvalidCredentials("bad_password")
        return user_id

    def login(self, conn: psycopg.Connection, email: str, password: str,
              client: ClientInfo = ClientInfo()) -> Session:
        _require_autocommit(conn)
        user_id = self._verify_password(conn, email, password, client)
        token = new_token("refresh")
        with _tx(conn, client):
            _, family_id, expires_at = conn.execute(
                "SELECT session_id, family_id, expires_at "
                "FROM secureai_auth.create_refresh_session(%s, %s, %s, %s::inet, %s)",
                (user_id, self.token_hasher.digest(token, "refresh"),
                 self.settings.refresh_idle_ttl, client.ip, client.user_agent)).fetchone()
        return Session(user_id, family_id, token, expires_at)

    # ---------------------------------------------------------------- refresh
    def refresh(self, conn: psycopg.Connection, refresh_token: str,
                client: ClientInfo = ClientInfo()) -> Session:
        _require_autocommit(conn)
        if not is_well_formed(refresh_token, "refresh"):
            raise InvalidRefreshToken("malformed")
        new = new_token("refresh")
        with _tx(conn, client):
            outcome, user_id, family_id, _, expires_at = conn.execute(
                "SELECT outcome, user_id, family_id, session_id, expires_at "
                "FROM secureai_auth.rotate_refresh_session(%s, %s, %s, %s::inet, %s)",
                (self.token_hasher.digest(refresh_token, "refresh"),
                 self.token_hasher.digest(new, "refresh"),
                 self.settings.refresh_idle_ttl, client.ip, client.user_agent)).fetchone()
        # The transaction has committed: any family revocation is durable now.
        if outcome == "reuse_detected":
            raise RefreshTokenReuse(outcome, user_id)
        if outcome != "ok":
            raise InvalidRefreshToken(outcome, user_id)
        return Session(user_id, family_id, new, expires_at)

    def logout(self, conn: psycopg.Connection, refresh_token: str,
               client: ClientInfo = ClientInfo()) -> None:
        """Idempotent: unknown or malformed tokens are silently ignored."""
        _require_autocommit(conn)
        if not is_well_formed(refresh_token, "refresh"):
            return
        with _tx(conn, client):
            conn.execute("SELECT secureai_auth.revoke_refresh_session(%s, %s::inet, %s)",
                         (self.token_hasher.digest(refresh_token, "refresh"),
                          client.ip, client.user_agent))

    # --------------------------------------------------------- password reset
    def request_password_reset(self, conn: psycopg.Connection, email: str,
                               client: ClientInfo = ClientInfo()) -> str | None:
        """Returns the raw token to email to the user, or None.

        The caller must respond identically either way and should send the
        email asynchronously, so response time doesn't reveal the outcome.
        """
        _require_autocommit(conn)
        token = new_token("reset")
        with _tx(conn, client):
            user_id = conn.execute(
                "SELECT secureai_auth.request_password_reset(%s, %s, %s, %s::inet, %s)",
                (email, self.token_hasher.digest(token, "reset"), self.settings.reset_ttl,
                 client.ip, client.user_agent)).fetchone()[0]
        return token if user_id is not None else None

    def reset_password(self, conn: psycopg.Connection, reset_token: str, new_password: str,
                       client: ClientInfo = ClientInfo()) -> uuid.UUID:
        """Raises PasswordPolicyError (safe to show) or InvalidResetToken."""
        _require_autocommit(conn)
        if not is_well_formed(reset_token, "reset"):
            raise InvalidResetToken("malformed")
        self._validate_new_password(new_password)
        new_hash = passwords.hash_password(new_password)
        with _tx(conn, client):
            user_id = conn.execute(
                "SELECT secureai_auth.consume_password_reset(%s, %s, %s::inet, %s)",
                (self.token_hasher.digest(reset_token, "reset"), new_hash,
                 client.ip, client.user_agent)).fetchone()[0]
        if user_id is None:
            raise InvalidResetToken("rejected")
        return user_id

    # -------------------------------------------------------- password change
    def change_password(self, conn: psycopg.Connection, user_id: uuid.UUID,
                        current_password: str, new_password: str,
                        keep_family_id: uuid.UUID | None = None,
                        client: ClientInfo = ClientInfo()) -> int:
        """For an already-authenticated user (user_id from a verified JWT).

        Returns the number of other sessions revoked.
        """
        _require_autocommit(conn)
        with _tx(conn, client):
            conn.execute("SELECT secureai_rls.set_context(%s)", (user_id,))
            email = conn.execute("SELECT email FROM secureai.users WHERE id = %s",
                                 (user_id,)).fetchone()[0]
        self._validate_new_password(new_password, email)
        # Goes through the lockout counter, so this can't be used to brute-force.
        self._verify_password(conn, email, current_password, client)
        new_hash = passwords.hash_password(new_password)
        with _tx(conn, client):
            conn.execute("SELECT secureai_rls.set_context(%s)", (user_id,))
            return conn.execute(
                "SELECT secureai_auth.change_password(%s, %s, %s::inet, %s)",
                (new_hash, keep_family_id, client.ip, client.user_agent)).fetchone()[0]

    # ----------------------------------------------------------- registration
    def register(self, conn: psycopg.Connection, email: str, display_name: str,
                 client: ClientInfo = ClientInfo()) -> RegistrationResult:
        """Step 1: create a PENDING user with no password. Never reveals existence.

        Raises ValueError for malformed input (safe to show: it says nothing
        about whether the account exists).
        """
        _require_autocommit(conn)
        normalized = email.strip().lower()
        if len(normalized) > 320 or not EMAIL_RE.fullmatch(normalized):
            raise ValueError("Enter a valid email address")
        name = display_name.strip()
        if not 1 <= len(name) <= 200:
            raise ValueError("Display name must be 1-200 characters")
        token = new_token("verify")
        with _tx(conn, client):
            outcome, _ = conn.execute(
                "SELECT outcome, user_id FROM secureai_auth.register_user(%s, %s, %s, %s, %s::inet, %s)",
                (normalized, name, self.token_hasher.digest(token, "verify"),
                 self.settings.verify_ttl, client.ip, client.user_agent)).fetchone()
        return RegistrationResult(outcome, normalized,
                                  token if outcome in ("created", "resent") else None)

    def verify_email(self, conn: psycopg.Connection, verification_token: str, password: str,
                     client: ClientInfo = ClientInfo()) -> uuid.UUID:
        """Step 2: prove inbox ownership AND choose the password, atomically."""
        _require_autocommit(conn)
        if not is_well_formed(verification_token, "verify"):
            raise InvalidVerificationToken("malformed")
        self._validate_new_password(password)
        new_hash = passwords.hash_password(password)
        with _tx(conn, client):
            user_id = conn.execute(
                "SELECT secureai_auth.verify_email_and_set_password(%s, %s, %s::inet, %s)",
                (self.token_hasher.digest(verification_token, "verify"), new_hash,
                 client.ip, client.user_agent)).fetchone()[0]
        if user_id is None:
            raise InvalidVerificationToken("rejected")
        return user_id
