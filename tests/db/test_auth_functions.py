"""DB-level tests for the secureai_auth SECURITY DEFINER functions (migration 0004).

All calls go through app_conn (secureai_app, NOBYPASSRLS) exactly as the API
will; admin_conn is used only to arrange state and to read ground truth.
"""

from __future__ import annotations

import os
import threading
import time

import pytest
from psycopg import errors

from app.auth.passwords import hash_password, verify_password
from tests.conftest import as_user

DAY = "1 day"


def h() -> bytes:
    """A random 32-byte stand-in for HMAC(pepper, token)."""
    return os.urandom(32)


def begin(conn, email):
    return conn.execute(
        "SELECT outcome, user_id, password_hash FROM secureai_auth.begin_login(%s)", (email,)).fetchone()


def creds(admin_conn, user_id):
    return admin_conn.execute(
        "SELECT failed_login_count, locked_until, password_hash, password_changed_at "
        "FROM secureai.user_credentials WHERE user_id = %s", (user_id,)).fetchone()


def new_session(conn, user_id, token_hash, ttl=DAY):
    return conn.execute(
        "SELECT session_id, family_id, expires_at "
        "FROM secureai_auth.create_refresh_session(%s, %s, %s::interval)",
        (user_id, token_hash, ttl)).fetchone()


def rotate(conn, old, new, ttl=DAY):
    return conn.execute(
        "SELECT outcome, user_id, family_id, session_id, expires_at "
        "FROM secureai_auth.rotate_refresh_session(%s, %s, %s::interval)", (old, new, ttl)).fetchone()


def family_statuses(admin_conn, family_id):
    return sorted(r[0] for r in admin_conn.execute(
        "SELECT status FROM secureai.refresh_token_sessions WHERE family_id = %s",
        (family_id,)).fetchall())


def last_audit(admin_conn, action):
    return admin_conn.execute(
        "SELECT outcome, actor_user_id, metadata FROM secureai.audit_logs "
        "WHERE action = %s ORDER BY occurred_at DESC, id DESC LIMIT 1", (action,)).fetchone()


# ---------------------------------------------------------------- posture
def test_auth_definer_role_is_nologin_and_owns_every_auth_function(admin_conn):
    row = admin_conn.execute(
        "SELECT rolcanlogin, rolsuper, rolbypassrls, rolcreaterole FROM pg_roles "
        "WHERE rolname = 'secureai_auth_definer'").fetchone()
    assert row == (False, False, True, False)
    owners = admin_conn.execute(
        "SELECT DISTINCT pg_get_userbyid(p.proowner) FROM pg_proc p "
        "JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'secureai_auth'").fetchall()
    assert owners == [("secureai_auth_definer",)]


def test_auth_definer_cannot_touch_tenant_data(admin_conn):
    for table in ("tasks", "documents", "messages", "organization_memberships", "role_permissions"):
        assert not admin_conn.execute(
            "SELECT has_table_privilege('secureai_auth_definer', %s, 'SELECT')",
            (f"secureai.{table}",)).fetchone()[0], table


@pytest.mark.parametrize("sql", [
    "SELECT secureai_auth.audit('auth.login', 'success', NULL, NULL, NULL, NULL, NULL)",
    "SELECT secureai_auth.normalize_email('a@b.c')",
])
def test_app_cannot_call_internal_helpers(app_conn, sql):
    with pytest.raises(errors.InsufficientPrivilege):
        app_conn.execute(sql)


# ------------------------------------------------------------------ login
def test_begin_login_unknown_email_returns_no_hash_and_does_not_log_email(app_conn, admin_conn):
    email = "nobody-here@test.example"
    assert begin(app_conn, email) == ("unknown", None, None)
    outcome, actor, metadata = last_audit(admin_conn, "auth.login")
    assert (outcome, actor, metadata) == ("failure", None, {"reason": "unknown_user"})
    assert admin_conn.execute(
        "SELECT count(*) FROM secureai.audit_logs WHERE metadata::text LIKE %s",
        (f"%{email}%",)).fetchone()[0] == 0


def test_begin_login_returns_verifiable_hash_and_counts_attempt(app_conn, admin_conn, make_user):
    u = make_user()
    outcome, user_id, stored = begin(app_conn, u.email)
    assert (outcome, user_id) == ("ok", u.id)
    assert verify_password(stored, u.password)
    assert creds(admin_conn, u.id)[0] == 1  # counted before verification


def test_email_lookup_is_case_and_whitespace_insensitive(app_conn, make_user):
    u = make_user()
    assert begin(app_conn, f"  {u.email.upper()} ")[0] == "ok"


def test_complete_login_success_resets_counter(app_conn, admin_conn, make_user):
    u = make_user()
    for _ in range(3):
        begin(app_conn, u.email)
    app_conn.execute("SELECT secureai_auth.complete_login(%s, true)", (u.id,))
    assert creds(admin_conn, u.id)[:2] == (0, None)
    assert last_audit(admin_conn, "auth.login")[:2] == ("success", u.id)


def test_lockout_after_five_attempts_withholds_hash(app_conn, admin_conn, make_user):
    u = make_user()
    for _ in range(5):
        assert begin(app_conn, u.email)[0] == "ok"
    assert creds(admin_conn, u.id)[1] is not None
    assert begin(app_conn, u.email) == ("locked", None, None)
    assert last_audit(admin_conn, "auth.login")[2] == {"reason": "locked_out"}


def test_correct_password_on_fifth_attempt_still_succeeds(app_conn, admin_conn, make_user):
    """The 5th attempt sets the lock pessimistically; success must clear it."""
    u = make_user()
    for _ in range(5):
        begin(app_conn, u.email)
    app_conn.execute("SELECT secureai_auth.complete_login(%s, true)", (u.id,))
    assert begin(app_conn, u.email)[0] == "ok"


def test_expired_lockout_starts_a_fresh_window(app_conn, admin_conn, make_user):
    u = make_user()
    admin_conn.execute(
        "UPDATE secureai.user_credentials SET failed_login_count = 5, "
        "locked_until = now() - interval '1 second' WHERE user_id = %s", (u.id,))
    assert begin(app_conn, u.email)[0] == "ok"
    assert creds(admin_conn, u.id)[:2] == (1, None)


@pytest.mark.parametrize("status", ["pending", "disabled", "locked"])
def test_inactive_accounts_get_no_hash(app_conn, make_user, status):
    u = make_user(status=status)
    assert begin(app_conn, u.email) == ("inactive", None, None)


def test_complete_login_success_fails_closed_for_disabled_user(app_conn, admin_conn, make_user):
    u = make_user()
    begin(app_conn, u.email)
    admin_conn.execute("UPDATE secureai.users SET status = 'disabled' WHERE id = %s", (u.id,))
    with pytest.raises(errors.InsufficientPrivilege, match="not active"):
        app_conn.execute("SELECT secureai_auth.complete_login(%s, true)", (u.id,))


def test_complete_login_rejects_non_argon2id_rehash(app_conn, make_user):
    u = make_user()
    with pytest.raises(errors.CheckViolation):
        app_conn.execute("SELECT secureai_auth.complete_login(%s, true, 'md5:abc')", (u.id,))


# ---------------------------------------------------------------- refresh
def test_rotation_issues_child_and_retires_parent(app_conn, admin_conn, make_user):
    u = make_user()
    old, new = h(), h()
    sid, family, _ = new_session(app_conn, u.id, old)
    outcome, user_id, fam, new_sid, _ = rotate(app_conn, old, new)
    assert (outcome, user_id, fam) == ("ok", u.id, family)
    parent, status = admin_conn.execute(
        "SELECT parent_id, status FROM secureai.refresh_token_sessions WHERE id = %s",
        (new_sid,)).fetchone()
    assert (parent, status) == (sid, "active")
    assert family_statuses(admin_conn, family) == ["active", "rotated"]


def test_reuse_of_rotated_token_revokes_entire_family(app_conn, admin_conn, make_user):
    u = make_user()
    t1, t2, t3 = h(), h(), h()
    _, family, _ = new_session(app_conn, u.id, t1)
    assert rotate(app_conn, t1, t2)[0] == "ok"          # legitimate user rotates
    assert rotate(app_conn, t1, t3)[0] == "reuse_detected"  # attacker replays t1
    assert family_statuses(admin_conn, family) == ["revoked", "rotated"]
    assert rotate(app_conn, t2, h())[0] == "revoked"     # victim's token is dead too
    outcome, actor, meta = last_audit(admin_conn, "auth.refresh_reuse_detected")
    assert (outcome, actor, meta["sessions_revoked"]) == ("denied", u.id, 1)


def test_reuse_does_not_affect_other_families(app_conn, admin_conn, make_user):
    u = make_user()
    a1, a2, b1 = h(), h(), h()
    new_session(app_conn, u.id, a1)
    _, family_b, _ = new_session(app_conn, u.id, b1)  # second device
    rotate(app_conn, a1, a2)
    rotate(app_conn, a1, h())
    assert family_statuses(admin_conn, family_b) == ["active"]


def test_unknown_token_is_invalid(app_conn):
    assert rotate(app_conn, h(), h())[0] == "invalid"


def test_expired_token_is_rejected(app_conn, admin_conn, make_user):
    u = make_user()
    old = h()
    sid, _, _ = new_session(app_conn, u.id, old)
    admin_conn.execute(
        "UPDATE secureai.refresh_token_sessions SET created_at = now() - interval '2 days', "
        "expires_at = now() - interval '1 second' WHERE id = %s", (sid,))
    assert rotate(app_conn, old, h())[0] == "expired"


def test_absolute_family_lifetime_is_capped_at_30_days(app_conn, admin_conn, make_user):
    u = make_user()
    old = h()
    sid, _, _ = new_session(app_conn, u.id, old)
    admin_conn.execute(
        "UPDATE secureai.refresh_token_sessions SET created_at = now() - interval '31 days' "
        "WHERE id = %s", (sid,))
    assert rotate(app_conn, old, h())[0] == "expired"


def test_rotation_never_extends_past_family_cap(app_conn, admin_conn, make_user):
    u = make_user()
    old = h()
    sid, _, _ = new_session(app_conn, u.id, old)
    admin_conn.execute(
        "UPDATE secureai.refresh_token_sessions SET created_at = now() - interval '29 days' "
        "WHERE id = %s", (sid,))
    _, _, _, _, expires_at = rotate(app_conn, old, h(), ttl="14 days")
    remaining = admin_conn.execute("SELECT %s::timestamptz - now()", (expires_at,)).fetchone()[0]
    assert remaining.total_seconds() < 86400 + 5


def test_disabled_user_cannot_refresh_and_family_is_revoked(app_conn, admin_conn, make_user):
    u = make_user()
    old = h()
    _, family, _ = new_session(app_conn, u.id, old)
    admin_conn.execute("UPDATE secureai.users SET status = 'disabled' WHERE id = %s", (u.id,))
    assert rotate(app_conn, old, h())[0] == "inactive"
    assert family_statuses(admin_conn, family) == ["revoked"]


def test_cannot_create_session_for_inactive_user(app_conn, make_user):
    u = make_user(status="disabled")
    with pytest.raises(errors.InsufficientPrivilege):
        new_session(app_conn, u.id, h())


@pytest.mark.parametrize("ttl", ["0 seconds", "31 days"])
def test_ttl_bounds_are_enforced(app_conn, make_user, ttl):
    u = make_user()
    with pytest.raises(errors.InvalidParameterValue):
        new_session(app_conn, u.id, h(), ttl=ttl)


def test_logout_revokes_family(app_conn, admin_conn, make_user):
    u = make_user()
    t1, t2 = h(), h()
    _, family, _ = new_session(app_conn, u.id, t1)
    rotate(app_conn, t1, t2)
    assert app_conn.execute("SELECT secureai_auth.revoke_refresh_session(%s)", (t2,)).fetchone()[0]
    assert family_statuses(admin_conn, family) == ["revoked", "rotated"]
    assert app_conn.execute("SELECT secureai_auth.revoke_refresh_session(%s)", (h(),)).fetchone()[0] is False


def test_concurrent_rotation_of_same_token_cannot_fork_the_family(
        admin_conn, make_user, new_app_conn):
    """Two requests race with the same refresh token. Exactly one may win; the
    loser must be treated as reuse, and the winner's new token revoked too."""
    u = make_user()
    old = h()
    setup = new_app_conn()
    _, family, _ = new_session(setup, u.id, old)

    first = new_app_conn(autocommit=False)
    second = new_app_conn()
    r1 = rotate(first, old, h())  # holds the per-user lock, not yet committed

    result: dict = {}
    t = threading.Thread(target=lambda: result.update(r2=rotate(second, old, h())))
    t.start()
    deadline = time.monotonic() + 5
    while not admin_conn.execute("SELECT EXISTS (SELECT 1 FROM pg_locks WHERE NOT granted)").fetchone()[0]:
        assert time.monotonic() < deadline, "second rotation never blocked on the lock"
        time.sleep(0.02)
    first.commit()
    t.join(timeout=10)

    assert r1[0] == "ok"
    assert result["r2"][0] == "reuse_detected"
    assert "active" not in family_statuses(admin_conn, family)


# --------------------------------------------------------- password reset
def request_reset(conn, email, token_hash, ttl="30 minutes"):
    return conn.execute(
        "SELECT secureai_auth.request_password_reset(%s, %s, %s::interval)",
        (email, token_hash, ttl)).fetchone()[0]


def consume(conn, token_hash, new_hash):
    return conn.execute("SELECT secureai_auth.consume_password_reset(%s, %s)",
                        (token_hash, new_hash)).fetchone()[0]


def test_reset_request_for_unknown_or_inactive_user_returns_null(app_conn, admin_conn, make_user):
    assert request_reset(app_conn, "ghost@test.example", h()) is None
    u = make_user(status="disabled")
    assert request_reset(app_conn, u.email, h()) is None
    assert admin_conn.execute(
        "SELECT count(*) FROM secureai.password_reset_tokens WHERE user_id = %s",
        (u.id,)).fetchone()[0] == 0


def test_full_reset_sets_hash_clears_lockout_and_revokes_all_sessions(app_conn, admin_conn, make_user):
    u = make_user()
    s1, s2 = h(), h()
    _, fam1, _ = new_session(app_conn, u.id, s1)
    _, fam2, _ = new_session(app_conn, u.id, s2)
    admin_conn.execute("UPDATE secureai.user_credentials SET failed_login_count = 5, "
                       "locked_until = now() + interval '10 minutes' WHERE user_id = %s", (u.id,))
    before = creds(admin_conn, u.id)

    token = h()
    assert request_reset(app_conn, u.email, token) == u.id
    new_hash = hash_password("a-brand-new-passphrase")
    assert consume(app_conn, token, new_hash) == u.id

    failed, locked, stored, changed_at = creds(admin_conn, u.id)
    assert (failed, locked, stored) == (0, None, new_hash)
    assert changed_at > before[3]
    assert family_statuses(admin_conn, fam1) == family_statuses(admin_conn, fam2) == ["revoked"]
    assert consume(app_conn, token, new_hash) is None  # single use
    assert last_audit(admin_conn, "auth.password_reset")[2] == {"reason": "token_used"}


def test_new_reset_request_invalidates_previous_token(app_conn, make_user):
    u = make_user()
    first, second = h(), h()
    request_reset(app_conn, u.email, first)
    request_reset(app_conn, u.email, second)
    assert consume(app_conn, first, hash_password("another-new-passphrase")) is None
    assert consume(app_conn, second, hash_password("another-new-passphrase")) == u.id


def test_expired_reset_token_is_rejected(app_conn, admin_conn, make_user):
    u = make_user()
    token = h()
    request_reset(app_conn, u.email, token)
    admin_conn.execute(
        "UPDATE secureai.password_reset_tokens SET created_at = now() - interval '2 hours', "
        "expires_at = now() - interval '1 hour' WHERE token_hash = %s", (token,))
    assert consume(app_conn, token, hash_password("another-new-passphrase")) is None


def test_reset_requests_are_rate_limited(app_conn, admin_conn, make_user):
    u = make_user()
    issued = [request_reset(app_conn, u.email, h()) for _ in range(4)]
    assert issued == [u.id, u.id, u.id, None]
    assert last_audit(admin_conn, "auth.password_reset_requested")[2] == {"reason": "rate_limited"}


@pytest.mark.parametrize("ttl", ["1 minute", "2 hours"])
def test_reset_ttl_bounds(app_conn, make_user, ttl):
    u = make_user()
    with pytest.raises(errors.InvalidParameterValue):
        request_reset(app_conn, u.email, h(), ttl=ttl)


def test_consume_rejects_non_argon2id_hash_and_keeps_token_usable(app_conn, make_user):
    u = make_user()
    token = h()
    request_reset(app_conn, u.email, token)
    with pytest.raises(errors.InvalidParameterValue):
        consume(app_conn, token, "$2b$12$bcrypt-is-not-allowed")
    assert consume(app_conn, token, hash_password("another-new-passphrase")) == u.id


# -------------------------------------------------------- password change
def test_change_password_requires_rls_context(app_conn):
    with pytest.raises(errors.InsufficientPrivilege, match="context is required"):
        app_conn.execute("SELECT secureai_auth.change_password(%s)", (hash_password("x" * 12),))


def test_change_password_changes_only_own_and_keeps_current_family(app_conn, admin_conn):
    from app.db.seed_dev import ID
    priya = ID.user("priya")
    rahul_before = creds(admin_conn, ID.user("rahul"))[2]
    with as_user(app_conn, "priya"):  # rolled back at the end
        _, keep_family, _ = new_session(app_conn, priya, h())
        new_session(app_conn, priya, h())
        new_hash = hash_password("priya-new-passphrase")
        revoked = app_conn.execute("SELECT secureai_auth.change_password(%s, %s)",
                                   (new_hash, keep_family)).fetchone()[0]
        assert revoked >= 1
        statuses = dict(app_conn.execute(
            "SELECT family_id, status FROM secureai.refresh_token_sessions WHERE user_id = %s",
            (priya,)).fetchall())
        assert statuses[keep_family] == "active"
        assert [s for f, s in statuses.items() if f != keep_family and s == "active"] == []
    # rolled back: priya's real password and rahul's credentials are untouched
    assert creds(admin_conn, ID.user("rahul"))[2] == rahul_before
    assert verify_password(creds(admin_conn, priya)[2], "test-only-password")
