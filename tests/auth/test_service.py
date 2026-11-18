"""End-to-end auth flows through AuthService against the real database."""

from __future__ import annotations

import psycopg
import pytest
from argon2 import PasswordHasher

from app.auth.passwords import PasswordPolicyError, verify_password
from app.auth.service import (
    AuthService,
    ClientInfo,
    InvalidCredentials,
    InvalidRefreshToken,
    InvalidResetToken,
    RefreshTokenReuse,
)
from app.auth.tokens import TokenHasher

CLIENT = ClientInfo(ip="203.0.113.7", user_agent="pytest")


@pytest.fixture
def svc() -> AuthService:
    return AuthService(TokenHasher(bytes(range(32))))


def stored_hash(admin_conn, user_id):
    return admin_conn.execute(
        "SELECT password_hash FROM secureai.user_credentials WHERE user_id = %s",
        (user_id,)).fetchone()[0]


def test_login_refresh_logout_happy_path(svc, app_conn, make_user):
    u = make_user()
    s1 = svc.login(app_conn, u.email, u.password, CLIENT)
    assert s1.user_id == u.id
    s2 = svc.refresh(app_conn, s1.refresh_token, CLIENT)
    assert (s2.user_id, s2.family_id) == (u.id, s1.family_id)
    assert s2.refresh_token != s1.refresh_token
    svc.logout(app_conn, s2.refresh_token, CLIENT)
    with pytest.raises(InvalidRefreshToken) as exc:
        svc.refresh(app_conn, s2.refresh_token, CLIENT)
    assert exc.value.outcome == "revoked"


def test_wrong_password_and_unknown_email_raise_the_same_error(svc, app_conn, make_user):
    u = make_user()
    with pytest.raises(InvalidCredentials):
        svc.login(app_conn, u.email, "definitely-wrong-password", CLIENT)
    with pytest.raises(InvalidCredentials):
        svc.login(app_conn, "nobody@test.example", u.password, CLIENT)


def test_lockout_blocks_even_the_correct_password(svc, app_conn, make_user):
    u = make_user()
    for _ in range(5):
        with pytest.raises(InvalidCredentials):
            svc.login(app_conn, u.email, "definitely-wrong-password", CLIENT)
    with pytest.raises(InvalidCredentials, match="locked"):
        svc.login(app_conn, u.email, u.password, CLIENT)


def test_login_transparently_upgrades_weak_hash(svc, app_conn, admin_conn, make_user):
    weak = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1)
    u = make_user(password_hash=weak.hash("correct-horse-battery-staple"))
    svc.login(app_conn, u.email, u.password, CLIENT)
    upgraded = stored_hash(admin_conn, u.id)
    assert upgraded.startswith("$argon2id$v=19$m=65536,t=3,p=4$")
    assert verify_password(upgraded, u.password)


def test_replayed_refresh_token_kills_attacker_and_victim(svc, app_conn, make_user):
    u = make_user()
    stolen = svc.login(app_conn, u.email, u.password, CLIENT).refresh_token
    victim = svc.refresh(app_conn, stolen, CLIENT)           # victim keeps using the app
    with pytest.raises(RefreshTokenReuse):
        svc.refresh(app_conn, stolen, CLIENT)                 # attacker replays
    with pytest.raises(InvalidRefreshToken):
        svc.refresh(app_conn, victim.refresh_token, CLIENT)   # revocation was committed


def test_malformed_refresh_token_never_reaches_db(svc, app_conn):
    with pytest.raises(InvalidRefreshToken, match="malformed"):
        svc.refresh(app_conn, "sapr_" + "a" * 43, CLIENT)  # a reset-shaped token
    svc.logout(app_conn, "garbage", CLIENT)  # idempotent no-op


def test_password_reset_flow(svc, app_conn, make_user):
    u = make_user()
    session = svc.login(app_conn, u.email, u.password, CLIENT)
    assert svc.request_password_reset(app_conn, "nobody@test.example", CLIENT) is None
    token = svc.request_password_reset(app_conn, u.email, CLIENT)
    assert token and token.startswith("sapr_")

    with pytest.raises(PasswordPolicyError):
        svc.reset_password(app_conn, token, "short", CLIENT)
    assert svc.reset_password(app_conn, token, "a-brand-new-passphrase", CLIENT) == u.id

    with pytest.raises(InvalidResetToken):
        svc.reset_password(app_conn, token, "yet-another-passphrase", CLIENT)
    with pytest.raises(InvalidRefreshToken):
        svc.refresh(app_conn, session.refresh_token, CLIENT)  # all sessions revoked
    with pytest.raises(InvalidCredentials):
        svc.login(app_conn, u.email, u.password, CLIENT)
    svc.login(app_conn, u.email, "a-brand-new-passphrase", CLIENT)


def test_change_password_keeps_current_session_only(svc, app_conn, make_user):
    u = make_user()
    current = svc.login(app_conn, u.email, u.password, CLIENT)
    other = svc.login(app_conn, u.email, u.password, CLIENT)
    with pytest.raises(InvalidCredentials):
        svc.change_password(app_conn, u.id, "wrong-current-password", "next-long-passphrase",
                            current.family_id, CLIENT)
    revoked = svc.change_password(app_conn, u.id, u.password, "next-long-passphrase",
                                  current.family_id, CLIENT)
    assert revoked == 1
    svc.refresh(app_conn, current.refresh_token, CLIENT)
    with pytest.raises(InvalidRefreshToken):
        svc.refresh(app_conn, other.refresh_token, CLIENT)
    svc.login(app_conn, u.email, "next-long-passphrase", CLIENT)


def test_flows_refuse_non_autocommit_connections(svc, new_app_conn, make_user):
    u = make_user()
    conn: psycopg.Connection = new_app_conn(autocommit=False)
    with pytest.raises(RuntimeError, match="autocommit"):
        svc.login(conn, u.email, u.password, CLIENT)
