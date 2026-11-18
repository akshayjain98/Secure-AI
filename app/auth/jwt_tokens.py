"""Short-lived access tokens (JWT, RFC 9068 profile).

* HS256 with a keyset: the header ``kid`` selects the key, and unknown kids are
  rejected. The algorithm is PINNED on decode, which defeats ``alg=none`` and
  algorithm-confusion attacks.
* Required claims: iss, aud, sub, sid, iat, nbf, exp, jti. ``typ`` must be
  ``at+jwt``, so another kind of JWT signed with the same key can't be
  replayed as an access token.
* No roles or permissions in the token. Authorization is decided live in the
  database on every request (Phase 1 §5.3), so a revoked permission takes
  effect at once and doesn't wait for token expiry.
* Not revocable by design: lifetime is 10 minutes. ``set_context()`` still
  rejects disabled users on every request.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import timedelta

import jwt

ALGORITHM = "HS256"
TOKEN_TYPE = "at+jwt"
LEEWAY_SECONDS = 30


class InvalidAccessToken(Exception):
    pass


@dataclass(frozen=True)
class AccessClaims:
    user_id: uuid.UUID
    session_family_id: uuid.UUID
    jti: str
    expires_at: int


@dataclass(frozen=True)
class AccessTokenCodec:
    keys: dict[str, bytes] = field(repr=False)  # first = signing key
    issuer: str
    audience: str
    ttl: timedelta

    def __post_init__(self) -> None:
        if not self.keys:
            raise ValueError("at least one JWT key is required")
        if not timedelta(minutes=1) <= self.ttl <= timedelta(minutes=60):
            raise ValueError("access token ttl must be 1..60 minutes")

    @property
    def _signing_kid(self) -> str:
        return next(iter(self.keys))

    def issue(self, user_id: uuid.UUID, session_family_id: uuid.UUID) -> tuple[str, int]:
        now = int(time.time())
        exp = now + int(self.ttl.total_seconds())
        token = jwt.encode(
            {
                "iss": self.issuer, "aud": self.audience,
                "sub": str(user_id), "sid": str(session_family_id),
                "iat": now, "nbf": now, "exp": exp, "jti": uuid.uuid4().hex,
            },
            self.keys[self._signing_kid],
            algorithm=ALGORITHM,
            headers={"kid": self._signing_kid, "typ": TOKEN_TYPE},
        )
        return token, exp

    def verify(self, token: str) -> AccessClaims:
        try:
            header = jwt.get_unverified_header(token)
            if header.get("typ") != TOKEN_TYPE or header.get("alg") != ALGORITHM:
                raise InvalidAccessToken("wrong token type")
            key = self.keys.get(header.get("kid", ""))
            if key is None:
                raise InvalidAccessToken("unknown key id")
            claims = jwt.decode(
                token, key,
                algorithms=[ALGORITHM],
                audience=self.audience, issuer=self.issuer, leeway=LEEWAY_SECONDS,
                options={"require": ["iss", "aud", "sub", "sid", "iat", "nbf", "exp", "jti"]},
            )
            return AccessClaims(
                user_id=uuid.UUID(claims["sub"]),
                session_family_id=uuid.UUID(claims["sid"]),
                jti=str(claims["jti"]),
                expires_at=int(claims["exp"]),
            )
        except InvalidAccessToken:
            raise
        except (jwt.PyJWTError, ValueError, TypeError, KeyError) as exc:
            raise InvalidAccessToken(type(exc).__name__) from exc
