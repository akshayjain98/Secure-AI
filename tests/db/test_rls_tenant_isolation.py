"""Cross-organization isolation (brief items 5, 7, 12).

Every SELECT here deliberately omits a WHERE organization_id = ... filter:
the point is that RLS alone produces the correct, isolated result set.
"""

from __future__ import annotations

import pytest
from psycopg import errors

from app.db.seed_dev import ID, TASKS
from tests.conftest import as_user, ids

ORG_A_TASKS = {ID.task(k) for k, v in TASKS.items() if v[0] == "org_a"}
ORG_B_TASKS = {ID.task(k) for k, v in TASKS.items() if v[0] == "org_b"}


def T(*keys: str) -> set:
    return {ID.task(k) for k in keys}


# Exact expected visibility for an unfiltered "SELECT id FROM tasks".
EXPECTED_TASKS = {
    ("priya", "org_a"): T("priya_validation", "priya_private_learning", "priya_private_review",
                          "rahul_cutover", "rahul_runbook"),
    ("rahul", "org_a"): T("rahul_cutover", "rahul_runbook", "rahul_private", "priya_validation",
                          "akshay_atlas_access"),
    ("akshay", "org_a"): T("akshay_atlas_access", "akshay_vendor", "akshay_budget",
                           "rahul_cutover", "rahul_runbook", "priya_validation"),
    ("meera", "org_a"): set(),
    ("meera", "org_b"): T("meera_catalog", "david_ci"),
    ("david", "org_b"): T("david_ci", "david_onboarding", "meera_catalog"),
    ("john", "org_b"): T("john_planning", "david_ci", "meera_catalog"),
}


@pytest.mark.parametrize(("user", "org"), list(EXPECTED_TASKS))
def test_unfiltered_select_returns_exactly_authorized_tasks(app_conn, user, org):
    with as_user(app_conn, user, org):
        visible = ids(app_conn, "SELECT id FROM secureai.tasks")
    assert visible == EXPECTED_TASKS[(user, org)]


@pytest.mark.parametrize(("user", "org", "foreign"), [
    ("akshay", "org_a", ORG_B_TASKS), ("priya", "org_a", ORG_B_TASKS),
    ("john", "org_b", ORG_A_TASKS), ("david", "org_b", ORG_A_TASKS),
])
def test_foreign_org_tasks_invisible_even_by_exact_id(app_conn, user, org, foreign):
    with as_user(app_conn, user, org):
        found = ids(app_conn, "SELECT id FROM secureai.tasks WHERE id = ANY(%s)", (list(foreign),))
    assert found == set()


def test_multi_org_user_is_isolated_per_context(app_conn):
    """Meera belongs to both orgs; each context exposes only that org's data."""
    with as_user(app_conn, "meera", "org_a"):
        a = ids(app_conn, "SELECT DISTINCT organization_id FROM secureai.project_members "
                          "UNION SELECT organization_id FROM secureai.documents")
    with as_user(app_conn, "meera", "org_b"):
        b = ids(app_conn, "SELECT DISTINCT organization_id FROM secureai.project_members "
                          "UNION SELECT organization_id FROM secureai.documents")
    assert a == {ID.org("org_a")}
    assert b == {ID.org("org_b")}


@pytest.mark.parametrize("table", ["projects", "documents", "conversations", "messages",
                                   "project_members", "organization_memberships"])
def test_org_b_admin_sees_no_org_a_rows(app_conn, table):
    with as_user(app_conn, "john", "org_b"):
        orgs = ids(app_conn, f"SELECT DISTINCT organization_id FROM secureai.{table}")
    assert ID.org("org_a") not in orgs


def test_user_directory_is_scoped_to_current_org(app_conn):
    with as_user(app_conn, "priya", "org_a"):
        a = ids(app_conn, "SELECT id FROM secureai.users")
    with as_user(app_conn, "david", "org_b"):
        b = ids(app_conn, "SELECT id FROM secureai.users")
    assert a == {ID.user(u) for u in ("akshay", "rahul", "priya", "meera")}
    assert b == {ID.user(u) for u in ("john", "david", "meera")}


def test_viewer_without_user_read_sees_only_self(app_conn):
    with as_user(app_conn, "meera", "org_a"):
        assert ids(app_conn, "SELECT id FROM secureai.users") == {ID.user("meera")}


def test_organizations_visible_only_by_membership(app_conn):
    with as_user(app_conn, "priya", "org_a"):
        assert ids(app_conn, "SELECT id FROM secureai.organizations") == {ID.org("org_a")}
    with as_user(app_conn, "meera", "org_a"):
        assert ids(app_conn, "SELECT id FROM secureai.organizations") == {ID.org("org_a"), ID.org("org_b")}


# ---------------------------------------- tampering with organization_id (item 7)
def test_cannot_insert_task_into_other_org(app_conn):
    with pytest.raises(errors.InsufficientPrivilege, match="row-level security"):
        with as_user(app_conn, "priya", "org_a"):
            app_conn.execute(
                "INSERT INTO secureai.tasks (organization_id, project_id, owner_id, title) "
                "VALUES (%s, %s, %s, 'cross-tenant write')",
                (ID.org("org_b"), ID.project("polaris"), ID.user("priya")))


def test_cannot_reference_other_org_project_from_own_org(app_conn):
    with pytest.raises((errors.InsufficientPrivilege, errors.ForeignKeyViolation)):
        with as_user(app_conn, "akshay", "org_a"):
            app_conn.execute(
                "INSERT INTO secureai.tasks (organization_id, project_id, owner_id, title) "
                "VALUES (%s, %s, %s, 'mixed tenant')",
                (ID.org("org_a"), ID.project("polaris"), ID.user("akshay")))


def test_composite_fk_blocks_cross_tenant_reference_even_when_rls_is_bypassed(admin_conn):
    """Integrity layer independent of RLS: the BYPASSRLS migrator still cannot do it."""
    with pytest.raises(errors.ForeignKeyViolation):
        with admin_conn.transaction(force_rollback=True):
            admin_conn.execute(
                "INSERT INTO secureai.tasks (organization_id, project_id, owner_id, title) "
                "VALUES (%s, %s, %s, 'mixed tenant')",
                (ID.org("org_a"), ID.project("polaris"), ID.user("akshay")))


@pytest.mark.parametrize(("table", "row_id"), [
    ("tasks", ID.task("priya_validation")),
    ("documents", ID.document("a_priya_notes")),
    ("projects", ID.project("apollo")),
    ("conversations", ID.conversation("priya_chat")),
])
def test_cannot_move_row_to_another_org_via_update(app_conn, table, row_id):
    user = "rahul" if table == "projects" else "priya"
    with pytest.raises(errors.InsufficientPrivilege, match="permission denied"):
        with as_user(app_conn, user, "org_a"):
            app_conn.execute(f"UPDATE secureai.{table} SET organization_id = %s WHERE id = %s",
                             (ID.org("org_b"), row_id))


def test_cannot_reassign_ownership_via_update(app_conn):
    with pytest.raises(errors.InsufficientPrivilege, match="permission denied"):
        with as_user(app_conn, "priya", "org_a"):
            app_conn.execute("UPDATE secureai.tasks SET owner_id = %s WHERE id = %s",
                             (ID.user("priya"), ID.task("rahul_cutover")))


def test_client_cannot_choose_primary_key(app_conn):
    with pytest.raises(errors.InsufficientPrivilege, match="permission denied"):
        with as_user(app_conn, "priya", "org_a"):
            app_conn.execute(
                "INSERT INTO secureai.tasks (id, organization_id, project_id, owner_id, title) "
                "VALUES (%s, %s, %s, %s, 'chosen id')",
                (ID.task("david_ci"), ID.org("org_a"), ID.project("apollo"), ID.user("priya")))
