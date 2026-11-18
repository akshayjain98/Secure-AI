"""Password hashing (Argon2id) and password policy.

* Parameters are pinned explicitly (RFC 9106 second recommended option:
  t=3, m=64 MiB, p=4) so a library upgrade can't silently change them.
  needs_rehash() detects hashes made with older parameters, and login
  upgrades them transparently.
* Passwords are NFKC-normalised before hashing so the same visible password
  typed on different keyboards or OSes hashes the same.
* dummy_verify() burns the same CPU time as a real verification. Login calls
  it for unknown or locked accounts so response time doesn't reveal whether
  an email is registered.
"""

from __future__ import annotations

import unicodedata
from functools import lru_cache

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

MIN_LENGTH = 12
# Long enough for any passphrase/password manager; bounds request cost.
MAX_LENGTH = 256

_HASHER = PasswordHasher(
    time_cost=3, memory_cost=64 * 1024, parallelism=4, hash_len=32, salt_len=16, type=Type.ID)


class PasswordPolicyError(ValueError):
    """The candidate password does not meet policy. Message is safe to show."""


def _normalize(password: str) -> str:
    return unicodedata.normalize("NFKC", password)


def validate_policy(password: str, *, email: str | None = None) -> None:
    """NIST SP 800-63B style: length over composition rules. No forced symbols."""
    if not isinstance(password, str):
        raise PasswordPolicyError("Password must be a string")
    pw = _normalize(password)
    if len(pw) < MIN_LENGTH:
        raise PasswordPolicyError(f"Password must be at least {MIN_LENGTH} characters")
    if len(pw) > MAX_LENGTH:
        raise PasswordPolicyError(f"Password must be at most {MAX_LENGTH} characters")
    if not pw.strip():
        raise PasswordPolicyError("Password must not be only whitespace")
    if len(set(pw)) < 4:
        raise PasswordPolicyError("Password is too repetitive")
    if email:
        local = email.split("@", 1)[0].lower()
        if len(local) >= 4 and local in pw.lower():
            raise PasswordPolicyError("Password must not contain your email name")


def hash_password(password: str) -> str:
    return _HASHER.hash(_normalize(password))


def verify_password(stored_hash: str, password: str) -> bool:
    """True only for a correct password. Malformed hashes fail closed."""
    if len(password) > MAX_LENGTH * 4:  # cheap guard before any normalisation work
        return False
    try:
        return _HASHER.verify(stored_hash, _normalize(password))
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    try:
        return _HASHER.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return True


@lru_cache(maxsize=1)
def _dummy_hash() -> str:
    return _HASHER.hash("secureai-dummy-password-for-timing")


def dummy_verify(password: str) -> None:
    """Spend the same time as a real verify; always 'fails'."""
    verify_password(_dummy_hash(), password)
