"""The write-audit triggers (migration 0007) at the SQL level."""

from __future__ import annotations

import uuid

import pytest
from psycopg import errors

from app.db.seed_dev import ID
from tests.conftest import as_user

A = ID.org("org_a")


def audit_rows(admin_conn, resource_id) -> list[tuple]:
    return admin_conn.execute(
        "SELECT action, actor_user_id, organization_id, metadata FROM secureai.audit_logs "
        "WHERE resource_id = %s ORDER BY occurred_at", (resource_id,)).fetchall()


def test_rolled_back_write_leaves_no_audit_row(app_conn, admin_conn):
    task = ID.task("akshay_vendor")                    # Akshay's own task
    before = len(audit_rows(admin_conn, task))
    with as_user(app_conn, "akshay", "org_a"):         # rolled back (as_user default)
        assert app_conn.execute("UPDATE secureai.tasks SET priority = 'high' WHERE id = %s", (task,)).rowcount == 1
        # Inside the transaction the row exists (akshay holds audit.read)...
        assert app_conn.execute("SELECT count(*) FROM secureai.audit_logs WHERE resource_id = %s "
                                "AND action = 'task.update'", (task,)).fetchone()[0] >= 1
    # ...and it goes away with the change it describes.
    assert len(audit_rows(admin_conn, task)) == before


def test_committed_write_has_actor_org_and_safe_values(app_conn, admin_conn):
    task = ID.task("priya_validation")
    before = len(audit_rows(admin_conn, task))
    try:
        with as_user(app_conn, "priya", "org_a", commit=True):
            app_conn.execute("UPDATE secureai.tasks SET priority = 'urgent', title = title || '!' "
                             "WHERE id = %s", (task,))
        action, actor, org, meta = audit_rows(admin_conn, task)[before]
        assert (action, actor, org) == ("task.update", ID.user("priya"), A)
        assert meta == {"changed": ["priority", "title"],
                        "values": {"priority": {"old": "medium", "new": "urgent"}}}
    finally:
        admin_conn.execute("UPDATE secureai.tasks SET priority = 'medium', "
                           "title = rtrim(title, '!') WHERE id = %s", (task,))


def test_noop_update_is_not_logged(app_conn, admin_conn):
    task = ID.task("priya_validation")
    before = len(audit_rows(admin_conn, task))
    with as_user(app_conn, "priya", "org_a", commit=True):
        app_conn.execute("UPDATE secureai.tasks SET priority = priority WHERE id = %s", (task,))
    assert len(audit_rows(admin_conn, task)) == before


def test_maintenance_writes_are_not_attributed_to_anyone(admin_conn):
    task = ID.task("priya_validation")
    before = len(audit_rows(admin_conn, task))
    with admin_conn.transaction(force_rollback=True):
        admin_conn.execute("UPDATE secureai.tasks SET priority = 'low' WHERE id = %s", (task,))
        assert len(audit_rows(admin_conn, task)) == before


@pytest.mark.parametrize("sql", [
    "ALTER TABLE secureai.tasks DISABLE TRIGGER tasks_audit",
    "ALTER TABLE secureai.tasks DISABLE TRIGGER ALL",
    "SET session_replication_role = replica",       # would skip ordinary triggers
    "DROP TRIGGER tasks_audit ON secureai.tasks",
])
def test_app_cannot_switch_auditing_off(app_conn, sql):
    with pytest.raises(errors.InsufficientPrivilege):
        with as_user(app_conn, "akshay", "org_a"):
            app_conn.execute(sql)


def test_every_tenant_write_table_is_audited(admin_conn):
    """A new tenant table without an audit trigger fails here until classified."""
    audited = {r[0] for r in admin_conn.execute(
        "SELECT c.relname FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid "
        "JOIN pg_proc p ON p.oid = t.tgfoid WHERE p.proname = 'audit_row_change'").fetchall()}
    # conversations/messages: personal chat content, audited in the AI phase.
    assert audited == {"organizations", "organization_memberships", "user_permission_overrides",
                       "projects", "project_members", "tasks", "documents"}


def test_audit_trigger_function_is_not_executable_by_public(admin_conn):
    assert admin_conn.execute(
        "SELECT has_function_privilege('secureai_app', 'secureai.audit_row_change()', 'EXECUTE')"
    ).fetchone()[0] is False


def test_document_insert_is_audited_without_title(app_conn, admin_conn):
    doc_id = None
    try:
        with as_user(app_conn, "priya", "org_a", commit=True):
            doc_id = app_conn.execute(
                "INSERT INTO secureai.documents (organization_id, owner_id, title, storage_key, "
                "content_type, size_bytes, sha256) VALUES (secureai_rls.current_org_id(), "
                "secureai_rls.current_user_id(), 'Top secret title', %s, 'text/plain', 5, %s) "
                "RETURNING id", (f"org/test/{uuid.uuid4()}", b"\x00" * 32)).fetchone()[0]
        (action, actor, _, meta), = audit_rows(admin_conn, doc_id)
        assert (action, actor) == ("document.create", ID.user("priya"))
        assert "Top secret title" not in str(meta) and meta["values"]["visibility"] == "private"
    finally:
        if doc_id:
            admin_conn.execute("DELETE FROM secureai.documents WHERE id = %s", (doc_id,))
