"""Resource-level authorization for tasks and projects (brief items 4, 9, 14)."""

from __future__ import annotations

import pytest
from psycopg import errors

from app.db.seed_dev import ID
from tests.conftest import as_user, ids, rowcount

UPDATE_TASK = "UPDATE secureai.tasks SET title = title || ' (edited)' WHERE id = %s"
DELETE_TASK = "DELETE FROM secureai.tasks WHERE id = %s"


# ------------------------------------------------------------ private tasks (4)
@pytest.mark.parametrize(("reader", "org", "task"), [
    ("priya", "org_a", "rahul_private"),            # employee vs manager's private task
    ("rahul", "org_a", "priya_private_learning"),   # manager vs report's private task
    ("rahul", "org_a", "priya_private_review"),
    ("akshay", "org_a", "priya_private_learning"),  # even org admin (read_all) is excluded
    ("akshay", "org_a", "rahul_private"),
    ("john", "org_b", "david_onboarding"),
    ("david", "org_b", "john_planning"),
])
def test_private_task_invisible_to_others(app_conn, reader, org, task):
    with as_user(app_conn, reader, org):
        assert ids(app_conn, "SELECT id FROM secureai.tasks WHERE id = %s", (ID.task(task),)) == set()


def test_owner_sees_own_private_tasks(app_conn):
    with as_user(app_conn, "priya", "org_a"):
        found = ids(app_conn, "SELECT id FROM secureai.tasks WHERE visibility = 'private'")
    assert found == {ID.task("priya_private_learning"), ID.task("priya_private_review")}


def test_manager_sees_team_tasks_in_authorized_project(app_conn):
    with as_user(app_conn, "rahul", "org_a"):
        found = ids(app_conn, "SELECT id FROM secureai.tasks WHERE project_id = %s", (ID.project("apollo"),))
    assert found == {ID.task(k) for k in ("rahul_cutover", "rahul_runbook", "rahul_private", "priya_validation")}


def test_manager_cannot_see_projects_he_is_not_part_of(app_conn):
    with as_user(app_conn, "rahul", "org_a"):
        assert ID.project("helios") not in ids(app_conn, "SELECT id FROM secureai.projects")
        assert ids(app_conn, "SELECT id FROM secureai.tasks WHERE project_id = %s",
                   (ID.project("helios"),)) == set()


def test_admin_project_read_all_sees_every_project(app_conn):
    with as_user(app_conn, "akshay", "org_a"):
        found = ids(app_conn, "SELECT id FROM secureai.projects")
    assert found == {ID.project(p) for p in ("apollo", "atlas", "helios")}


def test_assignee_sees_task_assigned_to_them(app_conn):
    with as_user(app_conn, "rahul", "org_a"):
        assert ids(app_conn, "SELECT id FROM secureai.tasks WHERE id = %s",
                   (ID.task("akshay_atlas_access"),)) == {ID.task("akshay_atlas_access")}


# -------------------------------------------------------- UPDATE / DELETE (9)
@pytest.mark.parametrize(("user", "task", "expected"), [
    ("priya", "priya_validation", 1),     # owner
    ("priya", "rahul_runbook", 1),        # assignee
    ("priya", "rahul_cutover", 0),        # plain project member: read yes, write no
    ("priya", "rahul_private", 0),        # cannot even see it
    ("rahul", "priya_validation", 1),     # project lead, project-visible task
    ("rahul", "priya_private_learning", 0),
    ("akshay", "rahul_cutover", 0),       # read_all is not write_all
    ("meera", "rahul_cutover", 0),        # viewer has no task.update
])
def test_task_update_authorization(app_conn, user, task, expected):
    with as_user(app_conn, user, "org_a"):
        assert rowcount(app_conn, UPDATE_TASK, (ID.task(task),)) == expected


@pytest.mark.parametrize(("user", "task", "expected"), [
    ("priya", "priya_validation", 0),     # employee lacks task.delete, even for own task
    ("rahul", "rahul_private", 1),        # owner with task.delete
    ("rahul", "priya_validation", 1),     # project lead with task.delete
    ("rahul", "priya_private_learning", 0),
    ("akshay", "rahul_cutover", 0),       # admin is not a manager of Apollo
])
def test_task_delete_authorization(app_conn, user, task, expected):
    with as_user(app_conn, user, "org_a"):
        assert rowcount(app_conn, DELETE_TASK, (ID.task(task),)) == expected


def test_blocked_writes_leave_data_unchanged(app_conn, admin_conn):
    before = admin_conn.execute("SELECT title FROM secureai.tasks WHERE id = %s",
                                (ID.task("rahul_cutover"),)).fetchone()
    with as_user(app_conn, "priya", "org_a", commit=True):
        app_conn.execute(UPDATE_TASK, (ID.task("rahul_cutover"),))
        app_conn.execute(DELETE_TASK, (ID.task("rahul_cutover"),))
    after = admin_conn.execute("SELECT title FROM secureai.tasks WHERE id = %s",
                               (ID.task("rahul_cutover"),)).fetchone()
    assert before == after


# --------------------------------------------------------------- INSERT rules
INSERT_TASK = ("INSERT INTO secureai.tasks (organization_id, project_id, owner_id, assignee_id, title) "
               "VALUES (%s, %s, %s, %s, 'new task') RETURNING id")


def test_member_can_create_own_task_in_own_project(app_conn):
    with as_user(app_conn, "priya", "org_a"):
        assert app_conn.execute(INSERT_TASK, (ID.org("org_a"), ID.project("apollo"),
                                              ID.user("priya"), None)).fetchone()


@pytest.mark.parametrize(("user", "project", "owner", "assignee"), [
    ("priya", "apollo", "rahul", None),     # impersonating another owner
    ("priya", "helios", "priya", None),     # project she is not part of
    ("meera", "apollo", "meera", None),     # viewer: no task.create
    ("rahul", "apollo", "rahul", "akshay"), # assignee not a participant of Apollo
])
def test_task_insert_violations(app_conn, user, project, owner, assignee):
    with pytest.raises(errors.InsufficientPrivilege, match="row-level security"):
        with as_user(app_conn, user, "org_a"):
            app_conn.execute(INSERT_TASK, (ID.org("org_a"), ID.project(project), ID.user(owner),
                                           ID.user(assignee) if assignee else None))


# ---------------------------------------------------- column-level invariants
def test_assignee_cannot_change_visibility(app_conn):
    with pytest.raises(errors.InsufficientPrivilege, match="only the task owner may change"):
        with as_user(app_conn, "priya", "org_a"):
            app_conn.execute("UPDATE secureai.tasks SET visibility = 'private' WHERE id = %s",
                             (ID.task("rahul_runbook"),))


def test_assignee_can_update_status(app_conn):
    with as_user(app_conn, "priya", "org_a"):
        assert rowcount(app_conn, "UPDATE secureai.tasks SET status = 'in_progress' WHERE id = %s",
                        (ID.task("rahul_runbook"),)) == 1


def test_assignee_cannot_reassign(app_conn):
    with pytest.raises(errors.InsufficientPrivilege, match="reassign"):
        with as_user(app_conn, "priya", "org_a"):
            app_conn.execute("UPDATE secureai.tasks SET assignee_id = NULL WHERE id = %s",
                             (ID.task("rahul_runbook"),))


def test_owner_can_publish_private_task_to_project(app_conn):
    with as_user(app_conn, "priya", "org_a"):
        assert rowcount(app_conn, "UPDATE secureai.tasks SET visibility = 'project' WHERE id = %s",
                        (ID.task("priya_private_review"),)) == 1


def test_lead_cannot_hide_team_task_by_making_it_private(app_conn):
    """WITH CHECK (or the owner-only trigger) stops a lead hijacking visibility."""
    with pytest.raises(errors.InsufficientPrivilege):
        with as_user(app_conn, "rahul", "org_a"):
            app_conn.execute("UPDATE secureai.tasks SET visibility = 'private' WHERE id = %s",
                             (ID.task("priya_validation"),))


# --------------------------------------------------------------- projects
def test_project_insert_must_be_owned_by_caller(app_conn):
    with pytest.raises(errors.InsufficientPrivilege, match="row-level security"):
        with as_user(app_conn, "rahul", "org_a"):
            app_conn.execute("INSERT INTO secureai.projects (organization_id, owner_id, name) "
                             "VALUES (%s, %s, 'spoofed')", (ID.org("org_a"), ID.user("akshay")))


def test_employee_cannot_create_project(app_conn):
    with pytest.raises(errors.InsufficientPrivilege, match="row-level security"):
        with as_user(app_conn, "priya", "org_a"):
            app_conn.execute("INSERT INTO secureai.projects (organization_id, owner_id, name) "
                             "VALUES (%s, %s, 'mine')", (ID.org("org_a"), ID.user("priya")))


def test_lead_cannot_promote_self_within_project(app_conn):
    with as_user(app_conn, "priya", "org_a"):
        assert rowcount(app_conn, "UPDATE secureai.project_members SET project_role = 'lead' "
                                  "WHERE project_id = %s AND user_id = %s",
                        (ID.project("apollo"), ID.user("priya"))) == 0


def test_member_cannot_add_self_to_foreign_project(app_conn):
    with pytest.raises(errors.InsufficientPrivilege, match="row-level security"):
        with as_user(app_conn, "rahul", "org_a"):
            app_conn.execute(
                "INSERT INTO secureai.project_members (organization_id, project_id, user_id, added_by) "
                "VALUES (%s, %s, %s, %s)",
                (ID.org("org_a"), ID.project("helios"), ID.user("rahul"), ID.user("rahul")))


def test_project_owner_can_add_member(app_conn):
    with as_user(app_conn, "rahul", "org_a"):
        assert rowcount(app_conn,
            "INSERT INTO secureai.project_members (organization_id, project_id, user_id, added_by) "
            "VALUES (%s, %s, %s, %s)",
            (ID.org("org_a"), ID.project("apollo"), ID.user("meera"), ID.user("rahul"))) == 1


# ------------------------------------------- revocation takes effect (item 14)
def test_permission_revocation_applies_to_next_transaction(app_conn, admin_conn):
    """Akshay denies Rahul task.read; Rahul's very next query sees nothing."""
    with as_user(app_conn, "rahul", "org_a"):
        assert len(ids(app_conn, "SELECT id FROM secureai.tasks")) == 5
    try:
        with as_user(app_conn, "akshay", "org_a", commit=True):
            app_conn.execute(
                "INSERT INTO secureai.user_permission_overrides "
                "(organization_id, user_id, permission_id, effect, reason, created_by) "
                "SELECT %s, %s, p.id, 'deny', 'access review', %s "
                "FROM secureai.permissions p WHERE p.code = 'task.read'",
                (ID.org("org_a"), ID.user("rahul"), ID.user("akshay")))
        with as_user(app_conn, "rahul", "org_a"):
            assert ids(app_conn, "SELECT id FROM secureai.tasks") == set()
            assert app_conn.execute("SELECT secureai_rls.has_permission('task.read')").fetchone()[0] is False
    finally:
        admin_conn.execute("DELETE FROM secureai.user_permission_overrides WHERE user_id = %s",
                           (ID.user("rahul"),))
    with as_user(app_conn, "rahul", "org_a"):
        assert len(ids(app_conn, "SELECT id FROM secureai.tasks")) == 5


def test_role_downgrade_applies_to_next_transaction(app_conn, admin_conn):
    sql = ("UPDATE secureai.organization_memberships SET role_id = "
           "(SELECT id FROM secureai.roles WHERE key = %s) WHERE organization_id = %s AND user_id = %s")
    admin_conn.execute(sql, ("viewer", ID.org("org_a"), ID.user("rahul")))
    try:
        with as_user(app_conn, "rahul", "org_a"):
            assert rowcount(app_conn, UPDATE_TASK, (ID.task("rahul_cutover"),)) == 0
    finally:
        admin_conn.execute(sql, ("manager", ID.org("org_a"), ID.user("rahul")))
