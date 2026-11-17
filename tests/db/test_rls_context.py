"""Security context lifecycle: missing context, validation, and pool leakage.

Covers brief items 11 (missing context => denied) and 13 (no context leakage
across pooled connections).
"""

from __future__ import annotations

import uuid

import psycopg
import pytest
from psycopg import errors
from sqlalchemy import create_engine, text
from sqlalchemy.pool import QueuePool

from app.db.dsn import sqlalchemy_url
from app.db.seed_dev import ID
from tests.conftest import TEST_DB, as_user, ids

READABLE_TABLES = [
    "organizations", "users", "organization_memberships", "user_permission_overrides",
    "projects", "project_members", "tasks", "documents", "conversations", "messages",
    "audit_logs",
]


# ------------------------------------------------------------ missing context
@pytest.mark.parametrize("table", READABLE_TABLES)
def test_no_context_sees_no_rows(app_conn, table):
    assert app_conn.execute(f"SELECT count(*) FROM secureai.{table}").fetchone()[0] == 0


def test_no_context_sees_no_rows_even_by_exact_id(app_conn):
    assert app_conn.execute(
        "SELECT count(*) FROM secureai.tasks WHERE id = %s",
        (ID.task("priya_private_learning"),)).fetchone()[0] == 0


def test_no_context_cannot_insert(app_conn):
    with pytest.raises(errors.InsufficientPrivilege, match="row-level security"):
        app_conn.execute(
            "INSERT INTO secureai.tasks (organization_id, project_id, owner_id, title) "
            "VALUES (%s, %s, %s, 'injected')",
            (ID.org("org_a"), ID.project("apollo"), ID.user("priya")))


def test_no_context_update_and_delete_affect_nothing(app_conn, admin_conn):
    assert app_conn.execute("UPDATE secureai.tasks SET title = 'pwned'").rowcount == 0
    assert app_conn.execute("DELETE FROM secureai.tasks").rowcount == 0
    assert admin_conn.execute(
        "SELECT count(*) FROM secureai.tasks WHERE title = 'pwned'").fetchone()[0] == 0


def test_user_context_without_org_sees_no_tenant_rows(app_conn):
    with as_user(app_conn, "priya", org=None):
        assert app_conn.execute("SELECT count(*) FROM secureai.tasks").fetchone()[0] == 0
        # ...but can still see own profile and own org list (for org switching).
        assert ids(app_conn, "SELECT id FROM secureai.users") == {ID.user("priya")}
        assert ids(app_conn, "SELECT id FROM secureai.organizations") == {ID.org("org_a")}


# ---------------------------------------------------------- context validation
def test_set_context_requires_user(app_conn):
    with pytest.raises(errors.InsufficientPrivilege, match="user context is required"):
        with app_conn.transaction():
            app_conn.execute("SELECT secureai_rls.set_context(NULL, %s)", (ID.org("org_a"),))


def test_set_context_rejects_org_user_is_not_member_of(app_conn):
    """Equivalent of a tampered org claim / X-Org header: DB re-validates membership."""
    with pytest.raises(errors.InsufficientPrivilege, match="no active membership"):
        with as_user(app_conn, "priya", "org_b"):
            pass


def test_set_context_rejects_unknown_user(app_conn):
    with pytest.raises(errors.InsufficientPrivilege, match="not active"):
        with app_conn.transaction():
            app_conn.execute("SELECT secureai_rls.set_context(%s, NULL)", (uuid.uuid4(),))


def test_set_context_rejects_disabled_user(app_conn, admin_conn):
    admin_conn.execute("UPDATE secureai.users SET status = 'disabled' WHERE id = %s", (ID.user("david"),))
    try:
        with pytest.raises(errors.InsufficientPrivilege, match="not active"):
            with as_user(app_conn, "david", "org_b"):
                pass
    finally:
        admin_conn.execute("UPDATE secureai.users SET status = 'active' WHERE id = %s", (ID.user("david"),))


def test_set_context_rejects_suspended_membership(app_conn, admin_conn):
    sql = ("UPDATE secureai.organization_memberships SET status = %s "
           "WHERE organization_id = %s AND user_id = %s")
    admin_conn.execute(sql, ("suspended", ID.org("org_a"), ID.user("rahul")))
    try:
        with pytest.raises(errors.InsufficientPrivilege, match="no active membership"):
            with as_user(app_conn, "rahul", "org_a"):
                pass
    finally:
        admin_conn.execute(sql, ("active", ID.org("org_a"), ID.user("rahul")))


def test_set_context_rejects_suspended_organization(app_conn, admin_conn):
    admin_conn.execute("UPDATE secureai.organizations SET status = 'suspended' WHERE id = %s", (ID.org("org_b"),))
    try:
        with pytest.raises(errors.InsufficientPrivilege, match="no active membership"):
            with as_user(app_conn, "john", "org_b"):
                pass
    finally:
        admin_conn.execute("UPDATE secureai.organizations SET status = 'active' WHERE id = %s", (ID.org("org_b"),))


def test_context_cannot_be_switched_within_a_transaction(app_conn):
    with pytest.raises(errors.InsufficientPrivilege, match="already set"):
        with as_user(app_conn, "priya", "org_a"):
            app_conn.execute("SELECT secureai_rls.set_context(%s, %s)", (ID.user("akshay"), ID.org("org_a")))


# --------------------------------------------------------- leakage / pooling
def test_context_does_not_survive_commit(app_conn):
    with as_user(app_conn, "priya", "org_a", commit=True):
        assert app_conn.execute("SELECT count(*) FROM secureai.tasks").fetchone()[0] > 0
    # Same physical connection, next transaction, no set_context():
    assert app_conn.execute("SELECT secureai_rls.current_user_id()").fetchone()[0] is None
    assert app_conn.execute("SELECT count(*) FROM secureai.tasks").fetchone()[0] == 0


def test_context_does_not_survive_rollback(app_conn):
    with as_user(app_conn, "priya", "org_a"):
        pass
    assert app_conn.execute("SELECT count(*) FROM secureai.tasks").fetchone()[0] == 0


def test_session_level_set_is_ignored(app_conn):
    """Simulates the classic bug: SET (session) instead of SET LOCAL.

    Raw GUCs without a matching per-transaction stamp from set_context() are
    ignored, so a value that outlives its transaction cannot leak.
    """
    app_conn.execute(f"SET secureai.user_id = '{ID.user('priya')}'")
    app_conn.execute(f"SET secureai.org_id = '{ID.org('org_a')}'")
    try:
        assert app_conn.execute("SELECT secureai_rls.current_user_id()").fetchone()[0] is None
        assert app_conn.execute("SELECT count(*) FROM secureai.tasks").fetchone()[0] == 0
    finally:
        app_conn.execute("RESET ALL")


def test_stale_stamp_from_previous_transaction_is_ignored(app_conn):
    with as_user(app_conn, "priya", "org_a", commit=True):
        stamp = app_conn.execute("SELECT current_setting('secureai.ctx_tx')").fetchone()[0]
    # A buggy code path re-applies all three values at session level.
    app_conn.execute(f"SET secureai.user_id = '{ID.user('priya')}'")
    app_conn.execute(f"SET secureai.org_id = '{ID.org('org_a')}'")
    app_conn.execute(f"SET secureai.ctx_tx = '{stamp}'")
    try:
        assert app_conn.execute("SELECT count(*) FROM secureai.tasks").fetchone()[0] == 0
    finally:
        app_conn.execute("RESET ALL")


def test_sqlalchemy_pool_reuse_does_not_leak_identity():
    """One pooled connection serves Priya, then an anonymous request, then David."""
    engine = create_engine(sqlalchemy_url("app", TEST_DB), poolclass=QueuePool,
                           pool_size=1, max_overflow=0)
    try:
        def request(user: str | None, org: str | None):
            with engine.begin() as conn:  # one transaction per request
                if user:
                    conn.execute(text("SELECT secureai_rls.set_context(:u, :o)"),
                                 {"u": ID.user(user), "o": ID.org(org)})
                pid = conn.execute(text("SELECT pg_backend_pid()")).scalar_one()
                orgs = {r[0] for r in conn.execute(
                    text("SELECT DISTINCT organization_id FROM secureai.tasks"))}
                return pid, orgs

        pid1, orgs1 = request("priya", "org_a")
        pid2, orgs2 = request(None, None)
        pid3, orgs3 = request("david", "org_b")

        assert pid1 == pid2 == pid3, "test requires the same physical connection"
        assert orgs1 == {ID.org("org_a")}
        assert orgs2 == set()
        assert orgs3 == {ID.org("org_b")}
    finally:
        engine.dispose()


def test_concurrent_connections_are_isolated(app_conn):
    """Two live sessions with different identities do not influence each other."""
    from app.db.dsn import psycopg_conninfo

    with psycopg.connect(psycopg_conninfo("app", TEST_DB), autocommit=True) as other:
        with as_user(app_conn, "priya", "org_a"), as_user(other, "david", "org_b"):
            a = ids(app_conn, "SELECT DISTINCT organization_id FROM secureai.tasks")
            b = ids(other, "SELECT DISTINCT organization_id FROM secureai.tasks")
    assert a == {ID.org("org_a")} and b == {ID.org("org_b")}
