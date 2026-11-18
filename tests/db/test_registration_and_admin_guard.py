"""Migration 0005: registration functions, request-id audit stamping, last-admin guard."""

from __future__ import annotations

import os
import threading
import time
import uuid

import pytest
from psycopg import errors

from app.auth.passwords import hash_password, verify_password
from app.db.seed_dev import ID


def h() -> bytes:
    return os.urandom(32)


def register(conn, email, token_hash, name="New Person"):
    return conn.execute(
        "SELECT outcome, user_id FROM secureai_auth.register_user(%s, %s, %s)",
        (email, name, token_hash)).fetchone()


def verify(conn, token_hash, pw_hash):
    return conn.execute("SELECT secureai_auth.verify_email_and_set_password(%s, %s)",
                        (token_hash, pw_hash)).fetchone()[0]


def fresh_email() -> str:
    return f"new-{uuid.uuid4().hex[:12]}@test.example"


# ----------------------------------------------------------- registration
def test_register_creates_pending_user_without_any_password(app_conn, admin_conn):
    email = fresh_email()
    outcome, user_id = register(app_conn, email, h())
    assert outcome == "created"
    status, verified = admin_conn.execute(
        "SELECT status, email_verified_at FROM secureai.users WHERE id = %s", (user_id,)).fetchone()
    assert (status, verified) == ("pending", None)
    assert admin_conn.execute("SELECT count(*) FROM secureai.user_credentials WHERE user_id = %s",
                              (user_id,)).fetchone()[0] == 0
    # A pending user can't log in: there is no password to guess.
    assert app_conn.execute("SELECT outcome FROM secureai_auth.begin_login(%s)",
                            (email,)).fetchone()[0] == "unknown"


def test_verification_sets_password_and_activates(app_conn, admin_conn):
    email, token = fresh_email(), h()
    _, user_id = register(app_conn, email, token)
    pw_hash = hash_password("my-own-long-passphrase")
    assert verify(app_conn, token, pw_hash) == user_id
    assert admin_conn.execute("SELECT status FROM secureai.users WHERE id = %s",
                              (user_id,)).fetchone()[0] == "active"
    outcome, _, stored = app_conn.execute(
        "SELECT outcome, user_id, password_hash FROM secureai_auth.begin_login(%s)", (email,)).fetchone()
    assert outcome == "ok" and verify_password(stored, "my-own-long-passphrase")
    assert verify(app_conn, token, pw_hash) is None  # single use


def test_pre_account_takeover_is_impossible(app_conn, admin_conn):
    """Attacker registers the victim's address first. Without the victim's inbox
    they can't set a password. When the victim registers, a fresh link goes to
    the victim and the attacker's earlier link (if they ever saw it) is dead."""
    victim = fresh_email()
    attacker_token, victim_token = h(), h()
    assert register(app_conn, victim, attacker_token, "Attacker")[0] == "created"
    assert register(app_conn, victim, victim_token, "Victim")[0] == "resent"
    assert verify(app_conn, attacker_token, hash_password("attacker-chosen-pw")) is None
    assert verify(app_conn, victim_token, hash_password("victim-chosen-passphrase")) is not None


def test_register_existing_active_account_issues_no_token(app_conn, admin_conn):
    outcome, user_id = register(app_conn, "Priya@Asteria.example ", h())
    assert (outcome, user_id) == ("exists", ID.user("priya"))
    assert admin_conn.execute("SELECT count(*) FROM secureai.email_verification_tokens WHERE user_id = %s",
                              (user_id,)).fetchone()[0] == 0


def test_register_disabled_account_is_suppressed(app_conn, make_user):
    u = make_user(status="disabled")
    assert register(app_conn, u.email, h())[0] == "suppressed"


def test_register_is_rate_limited_per_address(app_conn):
    email = fresh_email()
    outcomes = [register(app_conn, email, h())[0] for _ in range(4)]
    assert outcomes == ["created", "resent", "resent", "rate_limited"]


def test_expired_verification_token_is_rejected(app_conn, admin_conn):
    token = h()
    register(app_conn, fresh_email(), token)
    admin_conn.execute(
        "UPDATE secureai.email_verification_tokens SET created_at = now() - interval '2 days', "
        "expires_at = now() - interval '1 day' WHERE token_hash = %s", (token,))
    assert verify(app_conn, token, hash_password("my-own-long-passphrase")) is None


def test_verify_rejects_non_argon2id_hash(app_conn):
    token = h()
    register(app_conn, fresh_email(), token)
    with pytest.raises(errors.InvalidParameterValue):
        verify(app_conn, token, "plaintext")


def test_auth_audit_rows_carry_the_request_id(app_conn, admin_conn):
    with app_conn.transaction():
        app_conn.execute("SELECT set_config('secureai.request_id', 'req-abc123', true)")
        app_conn.execute("SELECT * FROM secureai_auth.begin_login('nobody@test.example')")
    assert admin_conn.execute(
        "SELECT count(*) FROM secureai.audit_logs WHERE request_id = 'req-abc123' "
        "AND action = 'auth.login'").fetchone()[0] == 1


# ------------------------------------------------------- last-admin guard
@pytest.fixture
def org_with_two_admins(admin_conn, make_user):
    a, b = make_user(), make_user()
    org = uuid.uuid4()
    admin_conn.execute("INSERT INTO secureai.organizations (id, name, slug) VALUES (%s, %s, %s)",
                       (org, "Guard Test", f"guard-{org.hex[:12]}"))
    for u in (a, b):
        admin_conn.execute(
            "INSERT INTO secureai.organization_memberships (organization_id, user_id, role_id, status) "
            "SELECT %s, %s, id, 'active' FROM secureai.roles WHERE key = 'org_admin'", (org, u.id))
    return org, a, b


DEMOTE = ("UPDATE secureai.organization_memberships SET role_id = "
          "(SELECT id FROM secureai.roles WHERE key = 'employee') "
          "WHERE organization_id = %s AND user_id = %s")


def test_admin_can_demote_another_admin_while_one_remains(app_conn, org_with_two_admins):
    org, a, b = org_with_two_admins
    with app_conn.transaction(force_rollback=True):
        app_conn.execute("SELECT secureai_rls.set_context(%s, %s)", (a.id, org))
        assert app_conn.execute(DEMOTE, (org, b.id)).rowcount == 1


SUSPEND = ("UPDATE secureai.organization_memberships SET status = 'suspended' "
           "WHERE organization_id = %s AND user_id = %s")


@pytest.mark.parametrize("change", [DEMOTE, SUSPEND], ids=["demote", "suspend"])
def test_concurrent_mutual_removal_cannot_leave_zero_admins(
        org_with_two_admins, new_app_conn, admin_conn, change):
    """Phase 1 residual risk: A and B each pass RLS (each still sees itself as
    admin) and remove the other in parallel. Sequentially this can't happen,
    because the policy blocks self-edits and the first change strips the second
    actor's rights. Only the race needs the trigger."""
    org, a, b = org_with_two_admins
    first = new_app_conn(autocommit=False)
    first.execute("SELECT secureai_rls.set_context(%s, %s)", (a.id, org))
    assert first.execute(change, (org, b.id)).rowcount == 1  # holds the per-org lock

    second = new_app_conn(autocommit=False)
    result: dict = {}

    def b_removes_a():
        try:
            second.execute("SELECT secureai_rls.set_context(%s, %s)", (b.id, org))
            second.execute(change, (org, a.id))
            second.commit()
            result["second"] = "committed"
        except errors.InsufficientPrivilege as exc:
            second.rollback()
            result["second"] = str(exc)

    t = threading.Thread(target=b_removes_a)
    t.start()
    deadline = time.monotonic() + 5
    while not admin_conn.execute("SELECT EXISTS (SELECT 1 FROM pg_locks WHERE NOT granted)").fetchone()[0]:
        assert time.monotonic() < deadline, "second change never waited for the org lock"
        time.sleep(0.02)
    first.commit()
    t.join(timeout=10)

    assert "at least one active administrator" in result["second"]
    remaining = admin_conn.execute(
        "SELECT count(*) FROM secureai.organization_memberships m JOIN secureai.roles r ON r.id = m.role_id "
        "WHERE m.organization_id = %s AND r.key = 'org_admin' AND m.status = 'active'", (org,)).fetchone()[0]
    assert remaining == 1


def test_non_admin_changes_do_not_take_the_lock_or_fail(app_conn, org_with_two_admins, make_user, admin_conn):
    org, a, _ = org_with_two_admins
    m = make_user()
    admin_conn.execute(
        "INSERT INTO secureai.organization_memberships (organization_id, user_id, role_id, status) "
        "SELECT %s, %s, id, 'active' FROM secureai.roles WHERE key = 'manager'", (org, m.id))
    with app_conn.transaction(force_rollback=True):
        app_conn.execute("SELECT secureai_rls.set_context(%s, %s)", (a.id, org))
        assert app_conn.execute(SUSPEND, (org, m.id)).rowcount == 1


def test_trusted_maintenance_path_is_not_blocked(org_with_two_admins, admin_conn):
    org, a, b = org_with_two_admins
    with admin_conn.transaction(force_rollback=True):
        admin_conn.execute(DEMOTE, (org, a.id))
        admin_conn.execute(DEMOTE, (org, b.id))  # ops may fix data deliberately
