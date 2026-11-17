"""Privilege escalation via memberships and permission overrides (brief items 6, 14)."""

from __future__ import annotations

import pytest
from psycopg import errors

from app.db.seed_dev import ID
from tests.conftest import as_user, ids, rowcount

SET_ROLE = ("UPDATE secureai.organization_memberships "
            "SET role_id = (SELECT id FROM secureai.roles WHERE key = %s) "
            "WHERE organization_id = %s AND user_id = %s")


def role_of(admin_conn, org: str, user: str) -> str:
    return admin_conn.execute(
        "SELECT r.key FROM secureai.organization_memberships m JOIN secureai.roles r ON r.id = m.role_id "
        "WHERE m.organization_id = %s AND m.user_id = %s", (ID.org(org), ID.user(user))).fetchone()[0]


# ------------------------------------------------------ self-promotion (item 6)
@pytest.mark.parametrize("target_role", ["org_admin", "super_admin", "manager"])
def test_employee_cannot_promote_self(app_conn, admin_conn, target_role):
    with as_user(app_conn, "priya", "org_a", commit=True):
        assert rowcount(app_conn, SET_ROLE, (target_role, ID.org("org_a"), ID.user("priya"))) == 0
    assert role_of(admin_conn, "org_a", "priya") == "employee"


def test_admin_cannot_change_own_role(app_conn):
    with as_user(app_conn, "akshay", "org_a"):
        assert rowcount(app_conn, SET_ROLE, ("super_admin", ID.org("org_a"), ID.user("akshay"))) == 0


def test_manager_without_user_update_cannot_promote_others(app_conn):
    with as_user(app_conn, "rahul", "org_a"):
        assert rowcount(app_conn, SET_ROLE, ("manager", ID.org("org_a"), ID.user("priya"))) == 0


def test_admin_can_promote_employee_to_manager(app_conn):
    with as_user(app_conn, "akshay", "org_a"):
        assert rowcount(app_conn, SET_ROLE, ("manager", ID.org("org_a"), ID.user("priya"))) == 1


def test_admin_cannot_grant_non_assignable_super_admin(app_conn):
    with pytest.raises(errors.InsufficientPrivilege, match="row-level security"):
        with as_user(app_conn, "akshay", "org_a"):
            app_conn.execute(SET_ROLE, ("super_admin", ID.org("org_a"), ID.user("priya")))


def test_admin_cannot_touch_memberships_of_other_org(app_conn):
    with as_user(app_conn, "akshay", "org_a"):
        assert rowcount(app_conn, SET_ROLE, ("viewer", ID.org("org_b"), ID.user("david"))) == 0


def test_cannot_move_membership_to_other_org(app_conn):
    with pytest.raises(errors.InsufficientPrivilege, match="permission denied"):
        with as_user(app_conn, "akshay", "org_a"):
            app_conn.execute("UPDATE secureai.organization_memberships SET organization_id = %s "
                             "WHERE user_id = %s", (ID.org("org_b"), ID.user("priya")))


def test_user_cannot_join_other_org_by_inserting_membership(app_conn):
    with pytest.raises(errors.InsufficientPrivilege, match="row-level security"):
        with as_user(app_conn, "priya", "org_a"):
            app_conn.execute(
                "INSERT INTO secureai.organization_memberships (organization_id, user_id, role_id, status, invited_by) "
                "SELECT %s, %s, id, 'active', %s FROM secureai.roles WHERE key = 'org_admin'",
                (ID.org("org_b"), ID.user("priya"), ID.user("priya")))


def test_admin_cannot_add_member_with_role_above_own_rank(app_conn):
    with pytest.raises(errors.InsufficientPrivilege, match="row-level security"):
        with as_user(app_conn, "john", "org_b"):
            app_conn.execute(
                "INSERT INTO secureai.organization_memberships (organization_id, user_id, role_id, status, invited_by) "
                "SELECT %s, %s, id, 'invited', %s FROM secureai.roles WHERE key = 'super_admin'",
                (ID.org("org_b"), ID.user("akshay"), ID.user("john")))


def test_removing_member_requires_user_delete(app_conn):
    sql = ("UPDATE secureai.organization_memberships SET status = 'removed' "
           "WHERE organization_id = %s AND user_id = %s")
    with as_user(app_conn, "akshay", "org_a"):
        assert rowcount(app_conn, sql, (ID.org("org_a"), ID.user("priya"))) == 1
    with as_user(app_conn, "rahul", "org_a"):
        assert rowcount(app_conn, sql, (ID.org("org_a"), ID.user("priya"))) == 0


def test_employee_sees_directory_but_not_membership_changes(app_conn):
    with as_user(app_conn, "priya", "org_a"):
        members = ids(app_conn, "SELECT user_id FROM secureai.organization_memberships")
    assert members == {ID.user(u) for u in ("akshay", "rahul", "priya", "meera")}


# ----------------------------------------------------------------- overrides
INSERT_OVERRIDE = (
    "INSERT INTO secureai.user_permission_overrides "
    "(organization_id, user_id, permission_id, effect, reason, created_by) "
    "SELECT %s, %s, p.id, %s, 'test', %s FROM secureai.permissions p WHERE p.code = %s")


def test_user_cannot_grant_self_permission(app_conn):
    with pytest.raises(errors.InsufficientPrivilege, match="row-level security"):
        with as_user(app_conn, "akshay", "org_a"):
            app_conn.execute(INSERT_OVERRIDE, (ID.org("org_a"), ID.user("akshay"), "grant",
                                               ID.user("akshay"), "audit.read"))


def test_employee_cannot_grant_overrides(app_conn):
    with pytest.raises(errors.InsufficientPrivilege, match="row-level security"):
        with as_user(app_conn, "priya", "org_a"):
            app_conn.execute(INSERT_OVERRIDE, (ID.org("org_a"), ID.user("meera"), "grant",
                                               ID.user("priya"), "task.read"))


def test_admin_grant_override_takes_effect(app_conn, admin_conn):
    try:
        with as_user(app_conn, "akshay", "org_a", commit=True):
            app_conn.execute(INSERT_OVERRIDE, (ID.org("org_a"), ID.user("priya"), "grant",
                                               ID.user("akshay"), "audit.read"))
        with as_user(app_conn, "priya", "org_a"):
            assert app_conn.execute("SELECT count(*) FROM secureai.audit_logs").fetchone()[0] >= 1
    finally:
        admin_conn.execute("DELETE FROM secureai.user_permission_overrides")
    with as_user(app_conn, "priya", "org_a"):
        assert app_conn.execute("SELECT count(*) FROM secureai.audit_logs").fetchone()[0] == 0


def test_explicit_deny_beats_role_grant_and_blocks_delegation(app_conn, admin_conn):
    """Akshay's role grants document.delete, but an explicit deny wins - and he can
    no longer delegate a permission he does not effectively hold."""
    admin_conn.execute(INSERT_OVERRIDE, (ID.org("org_a"), ID.user("akshay"), "deny",
                                         ID.user("john"), "document.delete"))
    try:
        with as_user(app_conn, "akshay", "org_a"):
            assert rowcount(app_conn, "DELETE FROM secureai.documents WHERE id = %s",
                            (ID.document("a_comp_bands"),)) == 0
        with pytest.raises(errors.InsufficientPrivilege, match="row-level security"):
            with as_user(app_conn, "akshay", "org_a"):
                app_conn.execute(INSERT_OVERRIDE, (ID.org("org_a"), ID.user("meera"), "grant",
                                                   ID.user("akshay"), "document.delete"))
    finally:
        admin_conn.execute("DELETE FROM secureai.user_permission_overrides")


def test_expired_override_is_ignored(app_conn, admin_conn):
    admin_conn.execute(
        "INSERT INTO secureai.user_permission_overrides "
        "(organization_id, user_id, permission_id, effect, reason, created_at, expires_at) "
        "SELECT %s, %s, id, 'deny', 'expired', now() - interval '2 days', now() - interval '1 day' "
        "FROM secureai.permissions WHERE code = 'task.read'",
        (ID.org("org_a"), ID.user("priya")))
    try:
        with as_user(app_conn, "priya", "org_a"):
            assert app_conn.execute("SELECT secureai_rls.has_permission('task.read')").fetchone()[0] is True
    finally:
        admin_conn.execute("DELETE FROM secureai.user_permission_overrides")


def test_override_in_other_org_has_no_effect(app_conn, admin_conn):
    """Meera's deny in org B must not affect her in org A (and vice versa)."""
    admin_conn.execute(INSERT_OVERRIDE, (ID.org("org_b"), ID.user("meera"), "deny",
                                         ID.user("john"), "document.read"))
    try:
        with as_user(app_conn, "meera", "org_a"):
            assert ids(app_conn, "SELECT id FROM secureai.documents") == {ID.document("a_handbook")}
        with as_user(app_conn, "meera", "org_b"):
            assert ids(app_conn, "SELECT id FROM secureai.documents") == set()
    finally:
        admin_conn.execute("DELETE FROM secureai.user_permission_overrides")


def test_unknown_permission_code_fails_closed(app_conn):
    with as_user(app_conn, "akshay", "org_a"):
        assert app_conn.execute("SELECT secureai_rls.has_permission('task.reed')").fetchone()[0] is False
