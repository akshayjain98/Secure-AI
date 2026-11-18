"""Phase 3 step 3: one audit_logs row for every write to tenant data.

A row trigger on each audited table writes the audit row in the SAME
transaction as the change:
  * nothing can forget it (API handler, future endpoint, ad-hoc SQL as the app);
  * a refused or failed write rolls back, and its audit row with it, so the
    log never claims a change that didn't happen;
  * the actor is secureai_rls.current_user_id(), i.e. the verified identity,
    never a value the request supplied.

The trigger is SECURITY INVOKER: it inserts as the app role, so the existing
audit_logs_insert policy (current org, actor = me) still applies to it.
Trusted maintenance roles (BYPASSRLS: migrator, the definer roles) are not
audited here; the definer functions write their own, more specific rows
(member.invitation_accepted, auth.sessions_revoked, ...).

Confidentiality: audit.read holders (org admins) must not read private
content through the log. The metadata lists WHICH columns changed, and copies
values only for the per-table allow-list passed as trigger arguments
(status, role, visibility, assignee, ...). Titles, names, descriptions and
reasons never enter the log.

Request correlation: the API sets secureai.request_id, secureai.client_ip and
secureai.user_agent (transaction-local) before any write.

Revision ID: 0007_write_audit_trail
Revises: 0006_org_membership_admin
Create Date: 2026-11-18
"""

from alembic import op  # noqa: F401

from app.db.migration_utils import run_sql as _run

revision = "0007_write_audit_trail"
down_revision = "0006_org_membership_admin"
branch_labels = None
depends_on = None

# table -> (resource_type, columns whose VALUES may be logged)
AUDITED = {
    "organizations": ("organization", []),
    "organization_memberships": ("member", ["user_id", "role_id", "status"]),
    "user_permission_overrides": ("permission_override",
                                  ["user_id", "permission_id", "effect", "expires_at"]),
    "projects": ("project", ["owner_id", "status"]),
    "project_members": ("project_member", ["user_id", "project_role"]),
    "tasks": ("task", ["project_id", "owner_id", "assignee_id", "status", "priority", "visibility",
                       "due_date"]),
    "documents": ("document", ["owner_id", "project_id", "visibility", "content_type", "size_bytes"]),
}

# As secureai_owner.
FUNCTION_SQL = r"""
-- TG_ARGV[0] = resource_type; TG_ARGV[1..] = columns whose values may be logged.
CREATE FUNCTION secureai.audit_row_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_old     jsonb := CASE WHEN TG_OP <> 'INSERT' THEN to_jsonb(OLD) END;
    v_new     jsonb := CASE WHEN TG_OP <> 'DELETE' THEN to_jsonb(NEW) END;
    v_row     jsonb := COALESCE(v_new, v_old);
    v_safe    text[] := TG_ARGV[1:];
    v_changed text[];
    v_values  jsonb := '{}'::jsonb;
    v_key     text;
    v_ip      text := NULLIF(current_setting('secureai.client_ip', true), '');
BEGIN
    IF secureai.is_trusted_maintenance_role() THEN
        RETURN NULL;
    END IF;

    IF TG_OP = 'UPDATE' THEN
        SELECT COALESCE(array_agg(n.key ORDER BY n.key), '{}') INTO v_changed
        FROM jsonb_each(v_new) n
        WHERE n.key <> 'updated_at' AND n.value IS DISTINCT FROM v_old -> n.key;
        IF cardinality(v_changed) = 0 THEN
            RETURN NULL;          -- a no-op UPDATE changes nothing worth logging
        END IF;
        FOREACH v_key IN ARRAY v_changed LOOP
            IF v_key = ANY (v_safe) THEN
                v_values := v_values || jsonb_build_object(
                    v_key, jsonb_build_object('old', v_old -> v_key, 'new', v_new -> v_key));
            END IF;
        END LOOP;
    ELSE
        FOREACH v_key IN ARRAY v_safe LOOP
            v_values := v_values || jsonb_build_object(v_key, v_row -> v_key);
        END LOOP;
    END IF;

    INSERT INTO secureai.audit_logs
        (organization_id, actor_user_id, action, outcome, resource_type, resource_id,
         request_id, ip_address, user_agent, metadata)
    VALUES (
        CASE WHEN TG_TABLE_NAME = 'organizations' THEN (v_row ->> 'id')::uuid
             ELSE (v_row ->> 'organization_id')::uuid END,
        secureai_rls.current_user_id(),
        TG_ARGV[0] || '.' || CASE TG_OP WHEN 'INSERT' THEN 'create'
                                        WHEN 'UPDATE' THEN 'update' ELSE 'delete' END,
        'success',
        TG_ARGV[0],
        COALESCE(v_row ->> 'id', v_row ->> 'project_id')::uuid,
        left(NULLIF(current_setting('secureai.request_id', true), ''), 128),
        CASE WHEN v_ip ~ '^[0-9a-fA-F:.]+$' THEN v_ip::inet END,
        left(NULLIF(current_setting('secureai.user_agent', true), ''), 512),
        CASE WHEN TG_OP = 'UPDATE' THEN jsonb_build_object('changed', to_jsonb(v_changed), 'values', v_values)
             ELSE jsonb_build_object('values', v_values) END);
    RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION secureai.audit_row_change() FROM PUBLIC;
"""


def _trigger_sql() -> str:
    out = []
    for table, (rtype, safe) in AUDITED.items():
        ops = "UPDATE" if table == "organizations" else "INSERT OR UPDATE OR DELETE"
        args = ", ".join(f"'{a}'" for a in [rtype, *safe])
        out.append(f"CREATE TRIGGER {table}_audit AFTER {ops} ON secureai.{table} "
                   f"FOR EACH ROW EXECUTE FUNCTION secureai.audit_row_change({args});")
    return "\n".join(out)


def upgrade() -> None:
    _run("SET LOCAL ROLE secureai_owner")
    _run(FUNCTION_SQL)
    _run(_trigger_sql())


def downgrade() -> None:
    _run("SET LOCAL ROLE secureai_owner")
    _run("\n".join(f"DROP TRIGGER {t}_audit ON secureai.{t};" for t in AUDITED))
    _run("DROP FUNCTION secureai.audit_row_change();")
