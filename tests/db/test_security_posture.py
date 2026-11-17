"""Structural guarantees: roles, ownership, RLS flags, grants, secret columns.

These tests catch configuration drift - e.g. someone running the app as the
table owner, adding a table without RLS, or granting EXECUTE to PUBLIC.
"""

from __future__ import annotations

import psycopg
import pytest
from psycopg import errors

from app.db.seed_dev import ID
from tests.conftest import as_user

TENANT_TABLES = [
    "organization_memberships", "user_permission_overrides", "projects", "project_members",
    "tasks", "documents", "conversations", "messages",
]
RLS_TABLES = TENANT_TABLES + [
    "organizations", "users", "user_credentials", "refresh_token_sessions",
    "password_reset_tokens", "audit_logs",
]
GLOBAL_REFERENCE_TABLES = ["roles", "permissions", "role_permissions"]


def test_app_role_has_no_dangerous_attributes(admin_conn):
    row = admin_conn.execute(
        "SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication, rolinherit "
        "FROM pg_roles WHERE rolname = 'secureai_app'").fetchone()
    assert row == (False, False, False, False, False, False)


def test_app_role_owns_nothing_and_is_member_of_nothing(admin_conn):
    owned = admin_conn.execute(
        "SELECT count(*) FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner "
        "WHERE r.rolname = 'secureai_app'").fetchone()[0]
    funcs = admin_conn.execute(
        "SELECT count(*) FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner "
        "WHERE r.rolname = 'secureai_app'").fetchone()[0]
    memberships = admin_conn.execute(
        "SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.member "
        "WHERE r.rolname = 'secureai_app'").fetchone()[0]
    assert (owned, funcs, memberships) == (0, 0, 0)


def test_tables_owned_by_nologin_owner_role(admin_conn):
    owners = admin_conn.execute(
        "SELECT DISTINCT pg_get_userbyid(c.relowner) FROM pg_class c "
        "JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = 'secureai' AND c.relkind = 'r'").fetchall()
    assert owners == [("secureai_owner",)]


@pytest.mark.parametrize("table", RLS_TABLES)
def test_rls_enabled_and_forced(admin_conn, table):
    row = admin_conn.execute(
        "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
        "WHERE oid = %s::regclass", (f"secureai.{table}",)).fetchone()
    assert row == (True, True)


def test_every_table_is_either_rls_protected_or_known_reference_data(admin_conn):
    """A new table added without RLS fails this test until it is classified."""
    tables = {r[0] for r in admin_conn.execute(
        "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = 'secureai' AND c.relkind = 'r'").fetchall()}
    assert tables == set(RLS_TABLES) | set(GLOBAL_REFERENCE_TABLES)


@pytest.mark.parametrize("table", TENANT_TABLES)
def test_tenant_tables_have_restrictive_org_fence(admin_conn, table):
    row = admin_conn.execute(
        "SELECT permissive, cmd, qual, with_check FROM pg_policies "
        "WHERE schemaname = 'secureai' AND tablename = %s AND policyname = 'tenant_fence'",
        (table,)).fetchone()
    assert row is not None
    permissive, cmd, qual, with_check = row
    assert (permissive, cmd) == ("RESTRICTIVE", "ALL")
    assert "current_org_id()" in qual and "current_org_id()" in with_check


def test_no_function_in_our_schemas_is_executable_by_public(admin_conn):
    public_exec = admin_conn.execute(
        "SELECT n.nspname || '.' || p.proname FROM pg_proc p "
        "JOIN pg_namespace n ON n.oid = p.pronamespace "
        "WHERE n.nspname IN ('secureai', 'secureai_rls') "
        "AND has_function_privilege('public', p.oid, 'EXECUTE')").fetchall()
    assert public_exec == []


def test_security_definer_functions_pin_search_path(admin_conn):
    unpinned = admin_conn.execute(
        "SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
        "WHERE n.nspname IN ('secureai', 'secureai_rls') AND p.prosecdef "
        "AND NOT EXISTS (SELECT 1 FROM unnest(p.proconfig) c WHERE c LIKE 'search_path=%%')"
    ).fetchall()
    assert unpinned == []


@pytest.mark.parametrize("sql", [
    "INSERT INTO secureai.role_permissions (role_id, permission_id) "
    "SELECT r.id, p.id FROM secureai.roles r, secureai.permissions p "
    "WHERE r.key = 'employee' AND p.code = 'audit.read'",
    "UPDATE secureai.roles SET rank = 1000 WHERE key = 'employee'",
    "DELETE FROM secureai.permissions",
])
def test_app_cannot_modify_rbac_catalogue_even_as_admin(app_conn, sql):
    with pytest.raises(errors.InsufficientPrivilege):
        with as_user(app_conn, "akshay", "org_a"):
            app_conn.execute(sql)


@pytest.mark.parametrize("sql", [
    "SELECT password_hash FROM secureai.user_credentials",
    "SELECT * FROM secureai.password_reset_tokens",
    "SELECT token_hash FROM secureai.refresh_token_sessions",
])
def test_app_cannot_read_secrets(app_conn, sql):
    with pytest.raises(errors.InsufficientPrivilege):
        with as_user(app_conn, "akshay", "org_a"):
            app_conn.execute(sql)


def test_db_rejects_non_argon2id_password_hash(admin_conn):
    with pytest.raises(errors.CheckViolation):
        with admin_conn.transaction(force_rollback=True):
            admin_conn.execute(
                "UPDATE secureai.user_credentials SET password_hash = 'hunter2' WHERE user_id = %s",
                (ID.user("priya"),))


def test_refresh_session_scoped_to_self(app_conn):
    token_hash = b"\x01" * 32
    with as_user(app_conn, "priya"):
        cur = app_conn.execute(
            "INSERT INTO secureai.refresh_token_sessions (user_id, family_id, token_hash, expires_at) "
            "VALUES (%s, gen_random_uuid(), %s, now() + interval '7 days') RETURNING id",
            (ID.user("priya"), token_hash))
        assert cur.fetchone() is not None

    with pytest.raises(errors.InsufficientPrivilege, match="row-level security"):
        with as_user(app_conn, "priya"):
            app_conn.execute(
                "INSERT INTO secureai.refresh_token_sessions (user_id, family_id, token_hash, expires_at) "
                "VALUES (%s, gen_random_uuid(), %s, now() + interval '7 days')",
                (ID.user("rahul"), token_hash))


def test_owner_role_is_subject_to_rls(admin_conn):
    """FORCE RLS: even the table owner sees nothing without a policy match."""
    with admin_conn.transaction(force_rollback=True):
        admin_conn.execute("SET LOCAL ROLE secureai_owner")
        assert admin_conn.execute("SELECT count(*) FROM secureai.tasks").fetchone()[0] == 0


def test_application_role_has_no_access_to_migration_schema(app_conn):
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        app_conn.execute("SELECT * FROM secureai_migrations.alembic_version")
