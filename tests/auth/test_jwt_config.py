"""Unit tests: access-token codec, settings parsing, rate limiter."""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from app.api.ratelimit import RateLimited, RateLimiter
from app.auth.jwt_tokens import AccessTokenCodec, InvalidAccessToken
from app.config import Settings, parse_jwt_keys

KEY = b"\x01" * 32


def codec(**over):
    args = {"keys": {"k1": KEY}, "issuer": "secureai", "audience": "secureai-api",
            "ttl": timedelta(minutes=10)} | over
    return AccessTokenCodec(**args)


def test_roundtrip_and_no_authorization_data_in_token():
    import jwt
    uid, sid = uuid.uuid4(), uuid.uuid4()
    token, exp = codec().issue(uid, sid)
    claims = codec().verify(token)
    assert (claims.user_id, claims.session_family_id, claims.expires_at) == (uid, sid, exp)
    raw = jwt.decode(token, options={"verify_signature": False})
    assert set(raw) == {"iss", "aud", "sub", "sid", "iat", "nbf", "exp", "jti"}


def test_each_token_has_unique_jti():
    uid, sid = uuid.uuid4(), uuid.uuid4()
    assert codec().verify(codec().issue(uid, sid)[0]).jti != codec().verify(codec().issue(uid, sid)[0]).jti


def test_signing_uses_first_key_and_verification_needs_its_kid():
    token, _ = codec(keys={"new": b"\x02" * 32, "old": KEY}).issue(uuid.uuid4(), uuid.uuid4())
    with pytest.raises(InvalidAccessToken):
        codec().verify(token)  # only knows "k1"


@pytest.mark.parametrize("ttl", [timedelta(seconds=30), timedelta(hours=2)])
def test_ttl_bounds(ttl):
    with pytest.raises(ValueError):
        codec(ttl=ttl)


def test_parse_jwt_keys_preserves_order_and_validates():
    keys = parse_jwt_keys(f"b:{'22' * 32}, a:{'11' * 32}")
    assert list(keys) == ["b", "a"]
    for bad in ["", "nokey", f"a:{'11' * 8}", "a:zz", f"a:{'11' * 32},a:{'22' * 32}", f"a b:{'11' * 32}"]:
        with pytest.raises(RuntimeError):
            parse_jwt_keys(bad)


def test_settings_from_env_fail_fast(monkeypatch):
    monkeypatch.delenv("SECUREAI_JWT_KEYS", raising=False)
    with pytest.raises(RuntimeError, match="JWT_KEYS"):
        Settings.from_env()
    monkeypatch.setenv("SECUREAI_JWT_KEYS", f"k1:{'11' * 32}")
    monkeypatch.setenv("SECUREAI_TOKEN_PEPPER", "11" * 32)
    monkeypatch.setenv("SECUREAI_ENV", "production")
    monkeypatch.setenv("SECUREAI_PUBLIC_URL", "http://insecure.example")
    with pytest.raises(RuntimeError, match="https"):
        Settings.from_env()
    monkeypatch.setenv("SECUREAI_PUBLIC_URL", "https://app.example/")
    s = Settings.from_env()
    assert s.is_production and s.public_url == "https://app.example"
    assert "11" * 32 not in repr(s)


def test_rate_limiter_window_and_keys():
    now = [0.0]
    rl = RateLimiter(clock=lambda: now[0])
    for _ in range(3):
        rl.hit("b", "k", 3, 60)
    with pytest.raises(RateLimited) as exc:
        rl.hit("b", "k", 3, 60)
    assert exc.value.retry_after == 60
    rl.hit("b", "other", 3, 60)   # separate key
    rl.hit("c", "k", 3, 60)       # separate bucket
    now[0] = 60.0
    rl.hit("b", "k", 3, 60)       # window reset
