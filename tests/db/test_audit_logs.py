"""Audit log confidentiality and integrity."""

from __future__ import annotations

import pytest
from psycopg import errors

from app.db.seed_dev import ID
from tests.conftest import as_user, ids

INSERT_AUDIT = ("INSERT INTO secureai.audit_logs (organization_id, actor_user_id, action, outcome) "
                "VALUES (%s, %s, 'task.read', 'success')")


def test_audit_read_requires_permission(app_conn):
    with as_user(app_conn, "priya", "org_a"):
        assert app_conn.execute("SELECT count(*) FROM secureai.audit_logs").fetchone()[0] == 0


def test_admins_read_only_their_org_audit(app_conn):
    with as_user(app_conn, "akshay", "org_a"):
        a = ids(app_conn, "SELECT DISTINCT organization_id FROM secureai.audit_logs")
    with as_user(app_conn, "john", "org_b"):
        b = ids(app_conn, "SELECT DISTINCT organization_id FROM secureai.audit_logs")
    assert a == {ID.org("org_a")} and b == {ID.org("org_b")}


def test_user_can_write_own_audit_event(app_conn):
    with as_user(app_conn, "priya", "org_a"):
        assert app_conn.execute(INSERT_AUDIT, (ID.org("org_a"), ID.user("priya"))).rowcount == 1


@pytest.mark.parametrize(("org", "actor"), [
    ("org_b", "priya"),   # writing into another tenant's audit trail
    ("org_a", "rahul"),   # forging another actor
])
def test_cannot_forge_audit_events(app_conn, org, actor):
    with pytest.raises(errors.InsufficientPrivilege, match="row-level security"):
        with as_user(app_conn, "priya", "org_a"):
            app_conn.execute(INSERT_AUDIT, (ID.org(org), ID.user(actor)))


def test_cannot_backdate_audit_events(app_conn):
    with pytest.raises(errors.InsufficientPrivilege, match="permission denied"):
        with as_user(app_conn, "priya", "org_a"):
            app_conn.execute(
                "INSERT INTO secureai.audit_logs (occurred_at, organization_id, actor_user_id, action, outcome) "
                "VALUES (now() - interval '1 year', %s, %s, 'task.read', 'success')",
                (ID.org("org_a"), ID.user("priya")))


@pytest.mark.parametrize("sql", [
    "UPDATE secureai.audit_logs SET outcome = 'success'",
    "DELETE FROM secureai.audit_logs",
    "TRUNCATE secureai.audit_logs",
])
def test_app_cannot_tamper_with_audit_log(app_conn, sql):
    with pytest.raises(errors.InsufficientPrivilege):
        with as_user(app_conn, "akshay", "org_a"):
            app_conn.execute(sql)


@pytest.mark.parametrize("sql", [
    "UPDATE secureai.audit_logs SET outcome = 'success'",
    "DELETE FROM secureai.audit_logs",
])
def test_even_bypassrls_ops_role_cannot_tamper_with_audit_log(admin_conn, sql):
    with pytest.raises(errors.InsufficientPrivilege, match="append-only"):
        with admin_conn.transaction(force_rollback=True):
            admin_conn.execute(sql)
