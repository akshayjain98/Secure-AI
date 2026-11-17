"""Documents (brief item 8) and AI conversation privacy."""

from __future__ import annotations

import hashlib

import pytest
from psycopg import errors

from app.db.seed_dev import ID
from tests.conftest import as_user, ids, rowcount


def D(*keys: str) -> set:
    return {ID.document(k) for k in keys}


EXPECTED_DOCUMENTS = {
    ("priya", "org_a"): D("a_handbook", "a_apollo_arch", "a_priya_notes"),
    ("rahul", "org_a"): D("a_handbook", "a_apollo_arch"),
    ("akshay", "org_a"): D("a_handbook", "a_comp_bands", "a_apollo_arch", "a_helios_research"),
    ("meera", "org_a"): D("a_handbook"),
    ("john", "org_b"): D("b_security_policy"),
    ("david", "org_b"): D("b_security_policy", "b_david_proposal"),
}


@pytest.mark.parametrize(("user", "org"), list(EXPECTED_DOCUMENTS))
def test_document_visibility(app_conn, user, org):
    with as_user(app_conn, user, org):
        assert ids(app_conn, "SELECT id FROM secureai.documents") == EXPECTED_DOCUMENTS[(user, org)]


@pytest.mark.parametrize(("user", "org", "doc"), [
    ("priya", "org_a", "a_comp_bands"),       # private, other owner
    ("rahul", "org_a", "a_helios_research"),  # project doc, not a member
    ("rahul", "org_a", "a_priya_notes"),
    ("john", "org_b", "b_david_proposal"),    # admin cannot read private docs
    ("david", "org_b", "a_handbook"),         # org-wide in A is still not B
])
def test_unauthorized_document_by_id(app_conn, user, org, doc):
    with as_user(app_conn, user, org):
        assert ids(app_conn, "SELECT id FROM secureai.documents WHERE id = %s", (ID.document(doc),)) == set()


@pytest.mark.parametrize(("user", "doc", "sql", "expected"), [
    ("priya", "a_handbook", "UPDATE secureai.documents SET title = 'x' WHERE id = %s", 0),
    ("priya", "a_handbook", "DELETE FROM secureai.documents WHERE id = %s", 0),
    ("priya", "a_priya_notes", "UPDATE secureai.documents SET title = 'x' WHERE id = %s", 1),
    ("rahul", "a_apollo_arch", "DELETE FROM secureai.documents WHERE id = %s", 1),
    ("akshay", "a_apollo_arch", "DELETE FROM secureai.documents WHERE id = %s", 0),
    ("meera", "a_handbook", "UPDATE secureai.documents SET title = 'x' WHERE id = %s", 0),
])
def test_document_write_authorization(app_conn, user, doc, sql, expected):
    with as_user(app_conn, user, "org_a"):
        assert rowcount(app_conn, sql, (ID.document(doc),)) == expected


INSERT_DOC = ("INSERT INTO secureai.documents (organization_id, owner_id, project_id, title, storage_key, "
              "content_type, size_bytes, sha256, visibility) "
              "VALUES (%s, %s, %s, 'upload', %s, 'text/plain', 1, %s, %s)")


def _doc_params(owner: str, project: str | None, visibility: str, key: str):
    return (ID.org("org_a"), ID.user(owner), ID.project(project) if project else None,
            f"orgs/test/{key}", hashlib.sha256(key.encode()).digest(), visibility)


def test_employee_can_upload_own_document(app_conn):
    with as_user(app_conn, "priya", "org_a"):
        assert rowcount(app_conn, INSERT_DOC, _doc_params("priya", "apollo", "project", "ok1")) == 1


@pytest.mark.parametrize(("user", "owner", "project", "vis"), [
    ("priya", "akshay", None, "organization"),  # upload "as" someone else
    ("priya", "priya", "helios", "project"),    # attach to a project she is not in
    ("meera", "meera", None, "private"),        # viewer cannot upload
])
def test_document_insert_violations(app_conn, user, owner, project, vis):
    with pytest.raises(errors.InsufficientPrivilege, match="row-level security"):
        with as_user(app_conn, user, "org_a"):
            app_conn.execute(INSERT_DOC, _doc_params(owner, project, vis, f"bad-{user}-{owner}"))


def test_owner_cannot_move_document_into_foreign_project(app_conn):
    with pytest.raises(errors.InsufficientPrivilege, match="row-level security"):
        with as_user(app_conn, "priya", "org_a"):
            app_conn.execute("UPDATE secureai.documents SET project_id = %s, visibility = 'project' "
                             "WHERE id = %s", (ID.project("helios"), ID.document("a_priya_notes")))


def test_document_path_traversal_storage_key_rejected(admin_conn):
    with pytest.raises(errors.CheckViolation):
        with admin_conn.transaction(force_rollback=True):
            admin_conn.execute("UPDATE secureai.documents SET storage_key = 'orgs/../../etc/passwd' "
                               "WHERE id = %s", (ID.document("a_handbook"),))


# ------------------------------------------------------- conversations/messages
@pytest.mark.parametrize(("user", "org", "expected"), [
    ("priya", "org_a", {"priya_chat"}),
    ("rahul", "org_a", {"rahul_chat"}),
    ("akshay", "org_a", set()),   # admins do not read other people's AI chats
    ("meera", "org_a", set()),    # viewer has no chatbot.use
    ("david", "org_b", {"david_chat"}),
])
def test_conversations_are_personal(app_conn, user, org, expected):
    with as_user(app_conn, user, org):
        found = ids(app_conn, "SELECT id FROM secureai.conversations")
        msg_convs = ids(app_conn, "SELECT conversation_id FROM secureai.messages")
    assert found == {ID.conversation(c) for c in expected}
    assert msg_convs == found


def test_cannot_append_to_someone_elses_conversation_as_self(app_conn):
    """user_id = me passes RLS, but the composite FK (org, conversation, user) fails."""
    with pytest.raises(errors.ForeignKeyViolation):
        with as_user(app_conn, "rahul", "org_a"):
            app_conn.execute(
                "INSERT INTO secureai.messages (organization_id, conversation_id, user_id, role, content) "
                "VALUES (%s, %s, %s, 'user', 'hi')",
                (ID.org("org_a"), ID.conversation("priya_chat"), ID.user("rahul")))


def test_cannot_append_to_someone_elses_conversation_as_them(app_conn):
    with pytest.raises(errors.InsufficientPrivilege, match="row-level security"):
        with as_user(app_conn, "rahul", "org_a"):
            app_conn.execute(
                "INSERT INTO secureai.messages (organization_id, conversation_id, user_id, role, content) "
                "VALUES (%s, %s, %s, 'user', 'hi')",
                (ID.org("org_a"), ID.conversation("priya_chat"), ID.user("priya")))


def test_messages_are_immutable(app_conn):
    with pytest.raises(errors.InsufficientPrivilege, match="permission denied"):
        with as_user(app_conn, "priya", "org_a"):
            app_conn.execute("UPDATE secureai.messages SET content = 'rewritten history'")


def test_owner_can_continue_own_conversation(app_conn):
    with as_user(app_conn, "priya", "org_a"):
        assert rowcount(app_conn,
            "INSERT INTO secureai.messages (organization_id, conversation_id, user_id, role, content) "
            "VALUES (%s, %s, %s, 'user', 'follow-up')",
            (ID.org("org_a"), ID.conversation("priya_chat"), ID.user("priya"))) == 1
