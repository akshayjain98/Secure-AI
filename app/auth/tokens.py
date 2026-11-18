"""Opaque refresh and password-reset tokens.

* 256 bits from the OS CSPRNG, base64url. Brute force is not a concern, so
  a fast keyed hash is enough. Argon2 isn't needed for these.
* The database stores only HMAC-SHA256(pepper, purpose || token). The pepper
  lives outside the database, so a DB dump alone can't be used to check
  stolen tokens or compute valid ones.
* The purpose prefix gives domain separation: a reset token can never hash to
  something the refresh table would accept, and vice versa.
* Visible prefixes (``sart_`` / ``sapr_`` / ``save_``) let secret scanners and log
  redaction recognise leaked tokens.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from dataclasses import dataclass
from typing import Literal

Purpose = Literal["refresh", "reset", "verify"]

_PREFIX: dict[Purpose, str] = {"refresh": "sart_", "reset": "sapr_", "verify": "save_"}
_TOKEN_BYTES = 32
# token_urlsafe(32) -> 43 chars of [A-Za-z0-9_-]
_BODY = re.compile(r"^[A-Za-z0-9_-]{43}$")
MIN_PEPPER_BYTES = 32


class TokenFormatError(ValueError):
    pass


def new_token(purpose: Purpose) -> str:
    return _PREFIX[purpose] + secrets.token_urlsafe(_TOKEN_BYTES)


def is_well_formed(token: str, purpose: Purpose) -> bool:
    prefix = _PREFIX[purpose]
    return isinstance(token, str) and token.startswith(prefix) and bool(
        _BODY.fullmatch(token[len(prefix):]))


@dataclass(frozen=True)
class TokenHasher:
    pepper: bytes

    def __post_init__(self) -> None:
        if len(self.pepper) < MIN_PEPPER_BYTES:
            raise ValueError(f"token pepper must be at least {MIN_PEPPER_BYTES} bytes")

    def __repr__(self) -> str:  # never print the key
        return "TokenHasher(pepper=<redacted>)"

    def digest(self, token: str, purpose: Purpose) -> bytes:
        if not is_well_formed(token, purpose):
            raise TokenFormatError("malformed token")
        msg = purpose.encode() + b"\x00" + token.encode()
        return hmac.new(self.pepper, msg, hashlib.sha256).digest()

    @classmethod
    def from_env(cls, var: str = "SECUREAI_TOKEN_PEPPER") -> TokenHasher:
        raw = os.environ.get(var)
        if not raw:
            raise RuntimeError(f"{var} is not set (generate with: openssl rand -hex 32)")
        try:
            pepper = bytes.fromhex(raw)
        except ValueError as exc:
            raise RuntimeError(f"{var} must be hex-encoded") from exc
        return cls(pepper)
