"""Migration 0006 at the SQL level: invite-only inserts, status transitions,
the invitee-only definer functions, and session revocation on removal.

The API always sends 'invited', so these rules are tested here directly: a
regression in the policy or trigger would not show up through the API.
"""

from __future__ import annotations

import uuid

import pytest
from psycopg import errors

from app.db.seed_dev import ID
from tests.conftest import as_user

A, B = ID.org("org_a"), ID.org("org_b")

INSERT = ("INSERT INTO secureai.organization_memberships "
          "(organization_id, user_id, role_id, status, invited_by) "
          "SELECT %s, %s, id, %s, %s FROM secureai.roles WHERE key = 'employee'")
SET_STATUS = ("UPDATE secureai.organization_memberships SET status = %s "
              "WHERE organization_id = %s AND user_id = %s")


@pytest.fixture
def david_invited_to_a(admin_conn):
    admin_conn.execute(INSERT, (A, ID.user("david"), "invited", ID.user("akshay")))
    yield
    admin_conn.execute("DELETE FROM secureai.organization_memberships "
                       "WHERE organization_id = %s AND user_id = %s", (A, ID.user("david")))


@pytest.mark.parametrize("initial", ["active", "suspended", "removed"])
def test_admin_can_only_insert_invited(app_conn, initial):
    with pytest.raises(errors.InsufficientPrivilege, match="row-level security"):
        with as_user(app_conn, "akshay", "org_a"):
            app_conn.execute(INSERT, (A, ID.user("david"), initial, ID.user("akshay")))


def test_admin_insert_of_invited_is_allowed(app_conn):
    with as_user(app_conn, "akshay", "org_a"):
        assert app_conn.execute(INSERT, (A, ID.user("david"), "invited", ID.user("akshay"))).rowcount == 1


@pytest.mark.parametrize("old,new", [
    ("invited", "active"), ("invited", "suspended"),
    ("removed", "active"), ("removed", "suspended"),
    ("active", "invited"), ("suspended", "invited"),
])
def test_forbidden_transitions(app_conn, admin_conn, david_invited_to_a, old, new):
    admin_conn.execute(SET_STATUS, (old, A, ID.user("david")))
    with pytest.raises(errors.InsufficientPrivilege, match=f"cannot change from {old} to {new}"):
        with as_user(app_conn, "akshay", "org_a"):
            app_conn.execute(SET_STATUS, (new, A, ID.user("david")))


@pytest.mark.parametrize("old,new", [
    ("active", "suspended"), ("suspended", "active"), ("invited", "removed"),
    ("active", "removed"), ("suspended", "removed"), ("removed", "invited"),
])
def test_allowed_transitions(app_conn, admin_conn, david_invited_to_a, old, new):
    admin_conn.execute(SET_STATUS, (old, A, ID.user("david")))
    with as_user(app_conn, "akshay", "org_a"):
        assert app_conn.execute(SET_STATUS, (new, A, ID.user("david"))).rowcount == 1


def test_maintenance_path_may_set_any_status(admin_conn, david_invited_to_a):
    with admin_conn.transaction(force_rollback=True):
        assert admin_conn.execute(SET_STATUS, ("active", A, ID.user("david"))).rowcount == 1


# ------------------------------------------------------------------ resolve_invitee
def test_resolve_invitee_needs_user_create_in_the_context_org(app_conn):
    for user, org in (("priya", "org_a"), ("rahul", "org_a"), ("akshay", None)):
        with pytest.raises(errors.InsufficientPrivilege, match="not allowed to invite"):
            with as_user(app_conn, user, org):
                app_conn.execute("SELECT secureai_auth.resolve_invitee('x@invite.example')")


def test_resolve_invitee_returns_existing_id_and_creates_pending(app_conn, admin_conn):
    email = f"db-{uuid.uuid4().hex[:10]}@invite.example"
    with as_user(app_conn, "akshay", "org_a", commit=True):
        john = app_conn.execute("SELECT secureai_auth.resolve_invitee(' John@Borealis.example ')").fetchone()[0]
        new = app_conn.execute("SELECT secureai_auth.resolve_invitee(%s)", (email,)).fetchone()[0]
    assert john == ID.user("john")
    assert admin_conn.execute("SELECT status, display_name FROM secureai.users WHERE id = %s",
                              (new,)).fetchone() == ("pending", email.split("@")[0])
    # The resolver doesn't open the directory: the new user is still invisible.
    with as_user(app_conn, "akshay", "org_a"):
        assert app_conn.execute("SELECT count(*) FROM secureai.users WHERE id = ANY(%s)",
                                ([john, new],)).fetchone()[0] == 0


# ------------------------------------------------------------------ invitee side
def test_invitations_are_visible_and_answerable_only_by_the_invitee(app_conn, david_invited_to_a):
    with as_user(app_conn, "david"):
        assert [r[0] for r in app_conn.execute(
            "SELECT organization_id FROM secureai_auth.my_invitations()").fetchall()] == [A]
    # The inviter can't accept on David's behalf: the function keys on the caller.
    for user, org in (("akshay", "org_a"), ("akshay", None), ("john", "org_b")):
        with as_user(app_conn, user, org):
            assert app_conn.execute("SELECT count(*) FROM secureai_auth.my_invitations()").fetchone()[0] == 0
            assert app_conn.execute("SELECT secureai_auth.respond_to_invitation(%s, true)",
                                    (A,)).fetchone()[0] is False
    with as_user(app_conn, "david"):
        assert app_conn.execute("SELECT secureai_auth.respond_to_invitation(%s, true)",
                                (A,)).fetchone()[0] is True


def test_invitee_functions_need_a_context(app_conn):
    with pytest.raises(errors.InsufficientPrivilege, match="user context is required"):
        app_conn.execute("SELECT secureai_auth.respond_to_invitation(%s, true)", (A,))
    assert app_conn.execute("SELECT count(*) FROM secureai_auth.my_invitations()").fetchone()[0] == 0


def test_trigger_function_is_not_callable_by_the_app(admin_conn):
    assert admin_conn.execute(
        "SELECT has_function_privilege('secureai_app', "
        "'secureai_auth.revoke_sessions_on_membership_end()', 'EXECUTE')").fetchone()[0] is False


# ------------------------------------------------------------------ session revocation
@pytest.fixture
def david_session(admin_conn):
    sid = admin_conn.execute(
        "INSERT INTO secureai.refresh_token_sessions (user_id, family_id, token_hash, expires_at) "
        "VALUES (%s, gen_random_uuid(), %s, now() + interval '1 day') RETURNING id",
        (ID.user("david"), uuid.uuid4().bytes * 2)).fetchone()[0]
    yield sid
    admin_conn.execute("DELETE FROM secureai.refresh_token_sessions WHERE id = %s", (sid,))


def session(admin_conn, sid):
    return admin_conn.execute("SELECT status, revoked_reason FROM secureai.refresh_token_sessions "
                              "WHERE id = %s", (sid,)).fetchone()


@pytest.mark.parametrize("new", ["suspended", "removed"])
def test_ending_a_membership_revokes_sessions_atomically(app_conn, admin_conn, david_session, new):
    with as_user(app_conn, "john", "org_b"):          # rolled back
        app_conn.execute(SET_STATUS, (new, B, ID.user("david")))
    assert session(admin_conn, david_session) == ("active", None)

    try:
        with as_user(app_conn, "john", "org_b", commit=True):
            app_conn.execute(SET_STATUS, (new, B, ID.user("david")))
        assert session(admin_conn, david_session) == ("revoked", "membership_revoked")
        meta = admin_conn.execute(
            "SELECT metadata FROM secureai.audit_logs WHERE action = 'auth.sessions_revoked' "
            "AND resource_id = %s ORDER BY occurred_at DESC LIMIT 1", (ID.user("david"),)).fetchone()[0]
        assert meta["reason"] == f"membership_{new}" and meta["sessions"] >= 1  # earlier tests may add more
        assert admin_conn.execute("SELECT count(*) FROM secureai.refresh_token_sessions "
                                  "WHERE user_id = %s AND status = 'active'",
                                  (ID.user("david"),)).fetchone()[0] == 0
    finally:
        admin_conn.execute(SET_STATUS, ("active", B, ID.user("david")))


def test_role_change_keeps_sessions(app_conn, admin_conn, david_session):
    change = ("UPDATE secureai.organization_memberships SET role_id = "
              "(SELECT id FROM secureai.roles WHERE key = %s) WHERE organization_id = %s AND user_id = %s")
    try:
        with as_user(app_conn, "john", "org_b", commit=True):
            assert app_conn.execute(change, ("viewer", B, ID.user("david"))).rowcount == 1
        assert session(admin_conn, david_session) == ("active", None)
    finally:
        admin_conn.execute(change, ("employee", B, ID.user("david")))
