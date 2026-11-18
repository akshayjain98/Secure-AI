"""Pure unit tests: password hashing/policy and opaque tokens. No database."""

from __future__ import annotations

import pytest
from argon2 import PasswordHasher

from app.auth import passwords, tokens
from app.auth.passwords import PasswordPolicyError
from app.auth.tokens import TokenFormatError, TokenHasher

PEPPER = bytes(range(32))


# ---------------------------------------------------------------- passwords
def test_hash_is_argon2id_with_pinned_parameters():
    h = passwords.hash_password("correct-horse-battery-staple")
    assert h.startswith("$argon2id$v=19$m=65536,t=3,p=4$")
    assert not passwords.needs_rehash(h)


def test_verify_accepts_correct_rejects_wrong_and_garbage():
    h = passwords.hash_password("correct-horse-battery-staple")
    assert passwords.verify_password(h, "correct-horse-battery-staple")
    assert not passwords.verify_password(h, "correct-horse-battery-stapler")
    assert not passwords.verify_password("not-a-hash", "anything")
    assert not passwords.verify_password(h, "x" * 10_000)


def test_unicode_normalisation_makes_equivalent_input_verify():
    composed, decomposed = "café-passphrase!", "café-passphrase!"
    assert passwords.verify_password(passwords.hash_password(composed), decomposed)


def test_weaker_parameters_trigger_rehash():
    weak = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash("pw-pw-pw-pw-pw")
    assert passwords.needs_rehash(weak)
    assert passwords.verify_password(weak, "pw-pw-pw-pw-pw")


@pytest.mark.parametrize("candidate", [
    "short", "x" * 257, " " * 20, "aaaaaaaaaaaaaaaa", "abababababababab",
])
def test_policy_rejects(candidate):
    with pytest.raises(PasswordPolicyError):
        passwords.validate_policy(candidate)


def test_policy_rejects_password_containing_email_name():
    with pytest.raises(PasswordPolicyError, match="email"):
        passwords.validate_policy("my-name-is-priyanka-2026", email="priyanka@example.com")


@pytest.mark.parametrize("candidate", ["correct horse battery staple", "Tr0ub4dor&3-xyz", "密码密码密码密码abcd"])
def test_policy_accepts_long_passphrases_without_composition_rules(candidate):
    passwords.validate_policy(candidate)


# ------------------------------------------------------------------- tokens
def test_tokens_are_prefixed_unique_and_well_formed():
    a, b = tokens.new_token("refresh"), tokens.new_token("refresh")
    assert a != b and a.startswith("sart_") and len(a) == 5 + 43
    assert tokens.is_well_formed(a, "refresh")
    assert not tokens.is_well_formed(a, "reset")
    assert tokens.new_token("reset").startswith("sapr_")


@pytest.mark.parametrize("bad", ["", "sart_", "sart_short", "sart_" + "!" * 43, "SART_" + "a" * 43, None])
def test_malformed_tokens_are_rejected(bad):
    assert not tokens.is_well_formed(bad, "refresh")
    with pytest.raises(TokenFormatError):
        TokenHasher(PEPPER).digest(bad, "refresh")


def test_digest_is_keyed_and_deterministic():
    t = tokens.new_token("refresh")
    d = TokenHasher(PEPPER).digest(t, "refresh")
    assert len(d) == 32
    assert d == TokenHasher(PEPPER).digest(t, "refresh")
    assert d != TokenHasher(bytes(32)).digest(t, "refresh")


def test_short_pepper_is_refused_and_never_printed():
    with pytest.raises(ValueError):
        TokenHasher(b"too-short")
    assert PEPPER.hex() not in repr(TokenHasher(PEPPER))


def test_pepper_from_env(monkeypatch):
    monkeypatch.setenv("SECUREAI_TOKEN_PEPPER", PEPPER.hex())
    assert TokenHasher.from_env().pepper == PEPPER
    monkeypatch.setenv("SECUREAI_TOKEN_PEPPER", "zz")
    with pytest.raises(RuntimeError, match="hex"):
        TokenHasher.from_env()
    monkeypatch.delenv("SECUREAI_TOKEN_PEPPER")
    with pytest.raises(RuntimeError, match="not set"):
        TokenHasher.from_env()
