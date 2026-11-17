"""Security layer: privileges, RLS context helpers, RLS policies, invariant triggers.

Read docs/phase-1-database-architecture.md section 6 alongside this file; every
policy below is explained there.

Layering (each layer must hold even if the one above it is buggy):
  1. GRANTs           - which tables/columns the app role may touch at all.
  2. RLS fence        - RESTRICTIVE policy: organization_id = verified org context.
  3. RLS authz        - PERMISSIVE policies: permission + ownership/membership.
  4. Triggers         - invariants RLS cannot express (who may change a column).
  5. Composite FKs    - (from 0001) cross-tenant references are impossible.

Revision ID: 0002_security_layer
Revises: 0001_core_schema
Create Date: 2026-11-17
"""

from alembic import op  # noqa: F401

from app.db.migration_utils import run_sql as _run

revision = "0002_security_layer"
down_revision = "0001_core_schema"
branch_labels = None
depends_on = None

# Tables that hold tenant data and carry organization_id NOT NULL.
TENANT_TABLES = [
    "organization_memberships",
    "user_permission_overrides",
    "projects",
    "project_members",
    "tasks",
    "documents",
    "conversations",
    "messages",
]
# Tables with RLS but no organization fence (scoped differently, see docs).
OTHER_RLS_TABLES = [
    "organizations",
    "users",
    "user_credentials",
    "refresh_token_sessions",
    "password_reset_tokens",
    "audit_logs",
]


PRIVILEGES_SQL = r"""
-- ===================================================================
-- 1. Schema + table privileges (least privilege, column-level where it matters)
-- ===================================================================
CREATE SCHEMA secureai_rls AUTHORIZATION secureai_owner;
REVOKE ALL ON SCHEMA secureai_rls FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA secureai_rls TO secureai_rls_definer;
GRANT USAGE ON SCHEMA secureai_rls TO secureai_app;

GRANT USAGE ON SCHEMA secureai TO secureai_app, secureai_rls_definer;

-- The definer role reads ONLY what authorization decisions need. No writes.
GRANT SELECT ON
    secureai.users, secureai.organizations, secureai.organization_memberships,
    secureai.roles, secureai.permissions, secureai.role_permissions,
    secureai.user_permission_overrides, secureai.projects, secureai.project_members
TO secureai_rls_definer;

-- RBAC catalogue: read-only for the app. If the app could write
-- role_permissions, one SQL injection would grant every Employee everything.
GRANT SELECT ON secureai.roles, secureai.permissions, secureai.role_permissions TO secureai_app;

GRANT SELECT ON secureai.organizations TO secureai_app;
GRANT UPDATE (name) ON secureai.organizations TO secureai_app;

-- users: profile only. status/email changes go through audited ops paths.
GRANT SELECT ON secureai.users TO secureai_app;
GRANT UPDATE (display_name) ON secureai.users TO secureai_app;

-- user_credentials, password_reset_tokens: NO grants. Phase 2 accesses them
-- only through narrow SECURITY DEFINER functions.

-- Note: no INSERT grant on "id" anywhere. IDs are always DB-generated, so a
-- client cannot pick an ID (and cannot use PK collisions as an existence oracle).
GRANT SELECT ON secureai.organization_memberships TO secureai_app;
GRANT INSERT (organization_id, user_id, role_id, status, invited_by)
    ON secureai.organization_memberships TO secureai_app;
GRANT UPDATE (role_id, status) ON secureai.organization_memberships TO secureai_app;

GRANT SELECT, DELETE ON secureai.user_permission_overrides TO secureai_app;
GRANT INSERT (organization_id, user_id, permission_id, effect, reason, created_by, expires_at)
    ON secureai.user_permission_overrides TO secureai_app;
GRANT UPDATE (effect, reason, expires_at) ON secureai.user_permission_overrides TO secureai_app;

GRANT SELECT, DELETE ON secureai.projects TO secureai_app;
GRANT INSERT (organization_id, owner_id, name, description, status) ON secureai.projects TO secureai_app;
GRANT UPDATE (name, description, status) ON secureai.projects TO secureai_app;

GRANT SELECT, DELETE ON secureai.project_members TO secureai_app;
GRANT INSERT (organization_id, project_id, user_id, project_role, added_by)
    ON secureai.project_members TO secureai_app;
GRANT UPDATE (project_role) ON secureai.project_members TO secureai_app;

-- organization_id / project_id / owner_id are NOT updatable: a row can never
-- be moved to another tenant or re-owned by an UPDATE.
GRANT SELECT, DELETE ON secureai.tasks TO secureai_app;
GRANT INSERT (organization_id, project_id, owner_id, assignee_id, title, description,
              status, priority, visibility, due_date) ON secureai.tasks TO secureai_app;
GRANT UPDATE (assignee_id, title, description, status, priority, visibility, due_date)
    ON secureai.tasks TO secureai_app;

GRANT SELECT, DELETE ON secureai.documents TO secureai_app;
GRANT INSERT (organization_id, owner_id, project_id, title, storage_key, content_type,
              size_bytes, sha256, visibility) ON secureai.documents TO secureai_app;
GRANT UPDATE (title, visibility, project_id) ON secureai.documents TO secureai_app;

GRANT SELECT, DELETE ON secureai.conversations TO secureai_app;
GRANT INSERT (organization_id, user_id, title) ON secureai.conversations TO secureai_app;
GRANT UPDATE (title) ON secureai.conversations TO secureai_app;

-- Messages are immutable: no UPDATE, no DELETE (removed only via conversation cascade).
GRANT SELECT ON secureai.messages TO secureai_app;
GRANT INSERT (organization_id, conversation_id, user_id, role, content, model, token_count)
    ON secureai.messages TO secureai_app;

-- token_hash is write-only for the app: it can store a hash but never read one back.
GRANT SELECT (id, user_id, family_id, parent_id, status, revoked_reason, created_at,
              expires_at, last_used_at, rotated_at, revoked_at, user_agent, ip_address)
    ON secureai.refresh_token_sessions TO secureai_app;
GRANT INSERT (user_id, family_id, parent_id, token_hash, expires_at, user_agent, ip_address)
    ON secureai.refresh_token_sessions TO secureai_app;
GRANT UPDATE (status, revoked_reason, revoked_at, last_used_at, rotated_at)
    ON secureai.refresh_token_sessions TO secureai_app;

-- Audit: append-only. The app cannot choose id or occurred_at (no back-dating).
GRANT SELECT ON secureai.audit_logs TO secureai_app;
GRANT INSERT (organization_id, actor_user_id, action, resource_type, resource_id, outcome,
              request_id, ip_address, user_agent, metadata) ON secureai.audit_logs TO secureai_app;
"""


# Created while SET ROLE secureai_rls_definer, so that role owns them.
HELPERS_SQL = r"""
-- ===================================================================
-- 2. RLS context helpers
-- ===================================================================

-- A per-transaction stamp. set_context() records it; readers compare it.
-- A context value left behind by a session-level SET (pool leak bug) has a
-- stamp from an older transaction and is therefore ignored.
CREATE FUNCTION secureai_rls.tx_stamp() RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT (extract(epoch FROM transaction_timestamp()) * 1000000)::bigint::text
           || ':' || pg_backend_pid()::text
$$;

-- NULL (=> deny) unless a context was set by set_context() in THIS transaction.
-- NULLIF(...,'') matters: after a SET LOCAL ends, a custom GUC reverts to ''
-- (not NULL) and ''::uuid would raise instead of failing closed.
CREATE FUNCTION secureai_rls.current_user_id() RETURNS uuid
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT CASE
        WHEN current_setting('secureai.ctx_tx', true) = secureai_rls.tx_stamp()
        THEN NULLIF(current_setting('secureai.user_id', true), '')::uuid
    END
$$;

CREATE FUNCTION secureai_rls.current_org_id() RETURNS uuid
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT CASE
        WHEN current_setting('secureai.ctx_tx', true) = secureai_rls.tx_stamp()
        THEN NULLIF(current_setting('secureai.org_id', true), '')::uuid
    END
$$;

-- The ONLY supported way to establish identity for a transaction.
-- The application calls it with the user id from a *verified* JWT and the org
-- id from the token's org claim. The database independently re-validates that
-- the user is active and holds an active membership in an active org, so a
-- forged/mistaken org id fails here rather than silently scoping queries.
CREATE FUNCTION secureai_rls.set_context(p_user_id uuid, p_org_id uuid DEFAULT NULL)
RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_stamp text := secureai_rls.tx_stamp();
BEGIN
    IF p_user_id IS NULL THEN
        RAISE EXCEPTION 'secureai: user context is required' USING ERRCODE = '42501';
    END IF;

    -- One identity per transaction. Switching identity mid-transaction is a
    -- confused-deputy risk (rows read as user A written as user B).
    IF current_setting('secureai.ctx_tx', true) = v_stamp THEN
        RAISE EXCEPTION 'secureai: security context already set for this transaction'
            USING ERRCODE = '42501';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM secureai.users u
                   WHERE u.id = p_user_id AND u.status = 'active') THEN
        RAISE EXCEPTION 'secureai: user is not active' USING ERRCODE = '42501';
    END IF;

    IF p_org_id IS NOT NULL AND NOT EXISTS (
        SELECT 1
        FROM secureai.organization_memberships m
        JOIN secureai.organizations o ON o.id = m.organization_id
        WHERE m.user_id = p_user_id AND m.organization_id = p_org_id
          AND m.status = 'active' AND o.status = 'active'
    ) THEN
        RAISE EXCEPTION 'secureai: no active membership in organization' USING ERRCODE = '42501';
    END IF;

    -- is_local = true  => equivalent to SET LOCAL: reverts at COMMIT/ROLLBACK.
    PERFORM set_config('secureai.user_id', p_user_id::text, true);
    PERFORM set_config('secureai.org_id', COALESCE(p_org_id::text, ''), true);
    PERFORM set_config('secureai.ctx_tx', v_stamp, true);
END $$;

-- ===================================================================
-- 3. Authorization helpers (SECURITY DEFINER, owned by a BYPASSRLS role)
--
-- Why definer: policies on table X must read memberships/roles/projects.
-- If those reads were themselves subject to RLS we would get recursive
-- policy evaluation (projects -> project_members -> projects ...).
-- Each function is narrow, read-only, pinned search_path, fully qualified
-- names, and answers questions ONLY about the current context.
-- ===================================================================

-- Effective permission check. Precedence (documented in docs section 5):
--   no active membership  -> false
--   explicit deny         -> false   (deny always wins)
--   explicit grant        -> true
--   role grants it        -> true
--   otherwise             -> false   (default deny)
CREATE FUNCTION secureai_rls.has_permission_id(p_permission_id uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    WITH membership AS (
        SELECT m.role_id, m.user_id, m.organization_id
        FROM secureai.organization_memberships m
        JOIN secureai.users u         ON u.id = m.user_id
        JOIN secureai.organizations o ON o.id = m.organization_id
        WHERE m.user_id = secureai_rls.current_user_id()
          AND m.organization_id = secureai_rls.current_org_id()
          AND m.status = 'active' AND u.status = 'active' AND o.status = 'active'
    ),
    override AS (
        SELECT po.effect
        FROM secureai.user_permission_overrides po
        JOIN membership mb ON mb.user_id = po.user_id AND mb.organization_id = po.organization_id
        WHERE po.permission_id = p_permission_id
          AND (po.expires_at IS NULL OR po.expires_at > now())
    )
    SELECT CASE
        WHEN p_permission_id IS NULL OR NOT EXISTS (SELECT 1 FROM membership) THEN false
        WHEN EXISTS (SELECT 1 FROM override WHERE effect = 'deny')  THEN false
        WHEN EXISTS (SELECT 1 FROM override WHERE effect = 'grant') THEN true
        ELSE EXISTS (
            SELECT 1 FROM secureai.role_permissions rp
            JOIN membership mb ON mb.role_id = rp.role_id
            WHERE rp.permission_id = p_permission_id)
    END
$$;

-- Unknown permission codes resolve to NULL id -> false (fail closed on typos).
CREATE FUNCTION secureai_rls.has_permission(p_code text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT secureai_rls.has_permission_id(
        (SELECT p.id FROM secureai.permissions p WHERE p.code = p_code))
$$;

-- Rank of the caller's role in the current org; NULL when no active membership.
CREATE FUNCTION secureai_rls.current_role_rank() RETURNS integer
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT r.rank
    FROM secureai.organization_memberships m
    JOIN secureai.roles r         ON r.id = m.role_id
    JOIN secureai.users u         ON u.id = m.user_id
    JOIN secureai.organizations o ON o.id = m.organization_id
    WHERE m.user_id = secureai_rls.current_user_id()
      AND m.organization_id = secureai_rls.current_org_id()
      AND m.status = 'active' AND u.status = 'active' AND o.status = 'active'
$$;

-- Rank of another member - answered only for the CURRENT org (no cross-tenant oracle).
CREATE FUNCTION secureai_rls.member_rank(p_org_id uuid, p_user_id uuid) RETURNS integer
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT r.rank
    FROM secureai.organization_memberships m
    JOIN secureai.roles r ON r.id = m.role_id
    WHERE m.organization_id = p_org_id
      AND p_org_id = secureai_rls.current_org_id()
      AND m.user_id = p_user_id
$$;

CREATE FUNCTION secureai_rls.role_rank(p_role_id uuid) RETURNS integer
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT r.rank FROM secureai.roles r WHERE r.id = p_role_id
$$;

-- May the caller hand out this role? Must be API-assignable and not outrank the caller.
CREATE FUNCTION secureai_rls.can_assign_role(p_role_id uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT COALESCE((
        SELECT r.assignable AND r.rank <= secureai_rls.current_role_rank()
        FROM secureai.roles r WHERE r.id = p_role_id), false)
$$;

-- Orgs where the caller has an active membership (org switcher).
-- All array helpers return '{}' rather than NULL: "x = ANY(NULL)" is NULL,
-- and "NOT NULL" is NULL, which an IF treats as false -> a fail-open trap.
CREATE FUNCTION secureai_rls.my_org_ids() RETURNS uuid[]
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT COALESCE(array_agg(m.organization_id), '{}')
    FROM secureai.organization_memberships m
    JOIN secureai.organizations o ON o.id = m.organization_id
    WHERE m.user_id = secureai_rls.current_user_id()
      AND m.status = 'active' AND o.status = 'active'
$$;

-- Projects (current org) the caller owns or is a member of.
CREATE FUNCTION secureai_rls.my_project_ids() RETURNS uuid[]
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT COALESCE(array_agg(DISTINCT x.id), '{}') FROM (
        SELECT p.id FROM secureai.projects p
        WHERE p.organization_id = secureai_rls.current_org_id()
          AND p.owner_id = secureai_rls.current_user_id()
        UNION
        SELECT pm.project_id FROM secureai.project_members pm
        WHERE pm.organization_id = secureai_rls.current_org_id()
          AND pm.user_id = secureai_rls.current_user_id()
    ) x
$$;

-- Projects (current org) the caller manages: owner, or project_role = 'lead'.
CREATE FUNCTION secureai_rls.my_managed_project_ids() RETURNS uuid[]
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT COALESCE(array_agg(DISTINCT x.id), '{}') FROM (
        SELECT p.id FROM secureai.projects p
        WHERE p.organization_id = secureai_rls.current_org_id()
          AND p.owner_id = secureai_rls.current_user_id()
        UNION
        SELECT pm.project_id FROM secureai.project_members pm
        WHERE pm.organization_id = secureai_rls.current_org_id()
          AND pm.user_id = secureai_rls.current_user_id()
          AND pm.project_role = 'lead'
    ) x
$$;

-- Projects (current org) the caller owns.
CREATE FUNCTION secureai_rls.my_owned_project_ids() RETURNS uuid[]
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT COALESCE(array_agg(p.id), '{}') FROM secureai.projects p
    WHERE p.organization_id = secureai_rls.current_org_id()
      AND p.owner_id = secureai_rls.current_user_id()
$$;

-- Is p_user_id a participant (owner or member) of a project in the current org?
CREATE FUNCTION secureai_rls.is_project_participant(p_project_id uuid, p_user_id uuid)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT EXISTS (
        SELECT 1 FROM secureai.projects p
        WHERE p.id = p_project_id AND p.organization_id = secureai_rls.current_org_id()
          AND p.owner_id = p_user_id
    ) OR EXISTS (
        SELECT 1 FROM secureai.project_members pm
        WHERE pm.project_id = p_project_id AND pm.organization_id = secureai_rls.current_org_id()
          AND pm.user_id = p_user_id
    )
$$;
"""


# Must run as the function owner (secureai_rls_definer): only an object's
# owner can GRANT on it.
FUNCTION_GRANTS_SQL = r"""
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA secureai_rls FROM PUBLIC;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA secureai_rls TO secureai_app, secureai_owner;
"""


TRIGGERS_SQL = r"""
-- ===================================================================
-- 4. Invariant triggers (rules RLS cannot express per-column)
-- ===================================================================

-- Roles with BYPASSRLS (migrator/ops) are trusted maintenance paths and skip
-- these checks; every other role is held to them.
CREATE FUNCTION secureai.is_trusted_maintenance_role() RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT COALESCE((SELECT r.rolbypassrls FROM pg_catalog.pg_roles r
                     WHERE r.rolname = current_user), false)
$$;

-- RLS answers "may you update this row?". It cannot answer "may you change
-- THIS column?". An assignee may update status, but flipping a private task to
-- 'project' would publish the owner's private data, so:
--   * only the owner may change visibility
--   * only the owner or a project manager may change the assignee
CREATE FUNCTION secureai.enforce_task_update_rules() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_me uuid;
BEGIN
    IF secureai.is_trusted_maintenance_role() THEN
        RETURN NEW;
    END IF;
    v_me := secureai_rls.current_user_id();

    IF NEW.visibility IS DISTINCT FROM OLD.visibility
       AND OLD.owner_id IS DISTINCT FROM v_me THEN
        RAISE EXCEPTION 'secureai: only the task owner may change task visibility'
            USING ERRCODE = '42501';
    END IF;

    -- "IS NOT TRUE" (not "NOT ...") so that NULL fails closed.
    IF NEW.assignee_id IS DISTINCT FROM OLD.assignee_id
       AND OLD.owner_id IS DISTINCT FROM v_me
       AND (OLD.project_id = ANY (secureai_rls.my_managed_project_ids())) IS NOT TRUE THEN
        RAISE EXCEPTION 'secureai: only the task owner or a project manager may reassign a task'
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER tasks_enforce_update_rules
    BEFORE UPDATE ON secureai.tasks
    FOR EACH ROW EXECUTE FUNCTION secureai.enforce_task_update_rules();

-- Audit log is append-only for EVERYONE, including BYPASSRLS ops roles.
-- Retention purges must explicitly disable this trigger as the table owner,
-- which is itself a DDL event captured by log_statement=ddl.
CREATE FUNCTION secureai.audit_logs_append_only() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'secureai: audit_logs is append-only (% blocked)', TG_OP
        USING ERRCODE = '42501';
END $$;

CREATE TRIGGER audit_logs_no_update_delete
    BEFORE UPDATE OR DELETE ON secureai.audit_logs
    FOR EACH ROW EXECUTE FUNCTION secureai.audit_logs_append_only();
CREATE TRIGGER audit_logs_no_truncate
    BEFORE TRUNCATE ON secureai.audit_logs
    FOR EACH STATEMENT EXECUTE FUNCTION secureai.audit_logs_append_only();

REVOKE ALL ON FUNCTION secureai.is_trusted_maintenance_role() FROM PUBLIC;
REVOKE ALL ON FUNCTION secureai.enforce_task_update_rules() FROM PUBLIC;
REVOKE ALL ON FUNCTION secureai.audit_logs_append_only() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureai.is_trusted_maintenance_role() TO secureai_app;
"""


# Shorthands used in the policy text (expanded verbatim into SQL).
#  (SELECT f()) instead of f(): the planner evaluates the uncorrelated
#  sub-select once per statement (InitPlan) instead of once per row.
#  "x = ANY ((SELECT f())::uuid[])": the cast is required, otherwise
#  ANY(sub-select) compares x with each *row* (a whole uuid[]) and fails.
ME = "(SELECT secureai_rls.current_user_id())"
ORG = "(SELECT secureai_rls.current_org_id())"


def perm(code: str) -> str:
    return f"(SELECT secureai_rls.has_permission('{code}'))"


MY_PROJECTS = "project_id = ANY ((SELECT secureai_rls.my_project_ids())::uuid[])"
MY_MANAGED = "project_id = ANY ((SELECT secureai_rls.my_managed_project_ids())::uuid[])"
MY_OWNED = "project_id = ANY ((SELECT secureai_rls.my_owned_project_ids())::uuid[])"


POLICIES_SQL = f"""
-- ===================================================================
-- 5. Row-Level Security
-- ===================================================================

-- ---- 5.0 Tenant fence (RESTRICTIVE): AND-ed with every other policy.
-- Even if someone later adds a sloppy permissive policy such as USING (true),
-- rows outside the verified org context remain invisible and unwritable.
{"".join(f'''
CREATE POLICY tenant_fence ON secureai.{t} AS RESTRICTIVE FOR ALL TO secureai_app
    USING (organization_id = {ORG})
    WITH CHECK (organization_id = {ORG});''' for t in TENANT_TABLES)}

-- ---- 5.1 organizations
CREATE POLICY organizations_select_member ON secureai.organizations
    FOR SELECT TO secureai_app
    USING (id = ANY ((SELECT secureai_rls.my_org_ids())::uuid[]));

CREATE POLICY organizations_update_admin ON secureai.organizations
    FOR UPDATE TO secureai_app
    USING      (id = {ORG} AND {perm('organization.update')})
    WITH CHECK (id = {ORG} AND {perm('organization.update')});

-- ---- 5.2 users (global identities)
CREATE POLICY users_select_self ON secureai.users
    FOR SELECT TO secureai_app
    USING (id = {ME});

-- Directory: members of the CURRENT org only, and only with user.read.
-- The sub-select on memberships is itself filtered by memberships' RLS.
CREATE POLICY users_select_org_directory ON secureai.users
    FOR SELECT TO secureai_app
    USING ({perm('user.read')} AND EXISTS (
        SELECT 1 FROM secureai.organization_memberships m
        WHERE m.user_id = users.id AND m.organization_id = {ORG}));

CREATE POLICY users_update_self ON secureai.users
    FOR UPDATE TO secureai_app
    USING (id = {ME}) WITH CHECK (id = {ME});

-- ---- 5.3 organization_memberships
CREATE POLICY memberships_select ON secureai.organization_memberships
    FOR SELECT TO secureai_app
    USING (user_id = {ME} OR {perm('user.read')});

CREATE POLICY memberships_insert ON secureai.organization_memberships
    FOR INSERT TO secureai_app
    WITH CHECK (
        {perm('user.create')}
        AND user_id <> {ME}
        AND invited_by = {ME}
        AND status IN ('invited', 'active')
        AND secureai_rls.can_assign_role(role_id));

-- USING sees the OLD row: you may only touch members who do not outrank you,
-- and never your own membership (no self-promotion, no self-reactivation).
-- WITH CHECK sees the NEW row: the resulting role must be assignable by you;
-- marking a member 'removed' additionally needs user.delete.
CREATE POLICY memberships_update ON secureai.organization_memberships
    FOR UPDATE TO secureai_app
    USING (
        {perm('user.update')}
        AND user_id <> {ME}
        AND secureai_rls.role_rank(role_id) <= (SELECT secureai_rls.current_role_rank()))
    WITH CHECK (
        {perm('user.update')}
        AND user_id <> {ME}
        AND secureai_rls.can_assign_role(role_id)
        AND (status <> 'removed' OR {perm('user.delete')}));

-- ---- 5.4 user_permission_overrides
CREATE POLICY overrides_select ON secureai.user_permission_overrides
    FOR SELECT TO secureai_app
    USING (user_id = {ME} OR {perm('permission.manage')});

-- "You cannot delegate what you do not hold": a GRANT override requires the
-- grantor to effectively hold that permission. Deny overrides are always allowed
-- for managers of a lower-or-equal-ranked member. Never on yourself.
CREATE POLICY overrides_insert ON secureai.user_permission_overrides
    FOR INSERT TO secureai_app
    WITH CHECK (
        {perm('permission.manage')}
        AND user_id <> {ME}
        AND created_by = {ME}
        AND secureai_rls.member_rank(organization_id, user_id) <= (SELECT secureai_rls.current_role_rank())
        AND (effect = 'deny' OR secureai_rls.has_permission_id(permission_id)));

CREATE POLICY overrides_update ON secureai.user_permission_overrides
    FOR UPDATE TO secureai_app
    USING (
        {perm('permission.manage')}
        AND user_id <> {ME}
        AND secureai_rls.member_rank(organization_id, user_id) <= (SELECT secureai_rls.current_role_rank()))
    WITH CHECK (
        {perm('permission.manage')}
        AND user_id <> {ME}
        AND secureai_rls.member_rank(organization_id, user_id) <= (SELECT secureai_rls.current_role_rank())
        AND (effect = 'deny' OR secureai_rls.has_permission_id(permission_id)));

CREATE POLICY overrides_delete ON secureai.user_permission_overrides
    FOR DELETE TO secureai_app
    USING (
        {perm('permission.manage')}
        AND user_id <> {ME}
        AND secureai_rls.member_rank(organization_id, user_id) <= (SELECT secureai_rls.current_role_rank()));

-- ---- 5.5 projects
CREATE POLICY projects_select ON secureai.projects
    FOR SELECT TO secureai_app
    USING ({perm('project.read')} AND (
        owner_id = {ME}
        OR id = ANY ((SELECT secureai_rls.my_project_ids())::uuid[])
        OR {perm('project.read_all')}));

-- owner_id must be the caller: nobody can create a project "as" someone else.
CREATE POLICY projects_insert ON secureai.projects
    FOR INSERT TO secureai_app
    WITH CHECK ({perm('project.create')} AND owner_id = {ME});

CREATE POLICY projects_update ON secureai.projects
    FOR UPDATE TO secureai_app
    USING      ({perm('project.update')} AND id = ANY ((SELECT secureai_rls.my_managed_project_ids())::uuid[]))
    WITH CHECK ({perm('project.update')} AND id = ANY ((SELECT secureai_rls.my_managed_project_ids())::uuid[]));

CREATE POLICY projects_delete ON secureai.projects
    FOR DELETE TO secureai_app
    USING ({perm('project.delete')} AND owner_id = {ME});

-- ---- 5.6 project_members
CREATE POLICY project_members_select ON secureai.project_members
    FOR SELECT TO secureai_app
    USING (user_id = {ME} OR {MY_PROJECTS} OR {perm('project.read_all')});

-- Managers (owner/lead) manage membership. A lead may not add/alter their
-- own row (no self-promotion); only the project owner may add themselves.
CREATE POLICY project_members_insert ON secureai.project_members
    FOR INSERT TO secureai_app
    WITH CHECK (
        {perm('project.update')}
        AND {MY_MANAGED}
        AND added_by = {ME}
        AND (user_id <> {ME} OR {MY_OWNED}));

CREATE POLICY project_members_update ON secureai.project_members
    FOR UPDATE TO secureai_app
    USING      ({perm('project.update')} AND {MY_MANAGED} AND user_id <> {ME})
    WITH CHECK ({perm('project.update')} AND {MY_MANAGED} AND user_id <> {ME});

-- Managers remove members; anyone may leave a project themselves.
CREATE POLICY project_members_delete ON secureai.project_members
    FOR DELETE TO secureai_app
    USING (user_id = {ME} OR ({perm('project.update')} AND {MY_MANAGED}));

-- ---- 5.7 tasks
--   private  -> owner and assignee only. Not managers, not admins.
--   project  -> also project participants, and holders of project.read_all.
CREATE POLICY tasks_select ON secureai.tasks
    FOR SELECT TO secureai_app
    USING ({perm('task.read')} AND (
        owner_id = {ME}
        OR assignee_id = {ME}
        OR (visibility = 'project' AND ({MY_PROJECTS} OR {perm('project.read_all')}))));

CREATE POLICY tasks_insert ON secureai.tasks
    FOR INSERT TO secureai_app
    WITH CHECK (
        {perm('task.create')}
        AND owner_id = {ME}
        AND {MY_PROJECTS}
        AND (assignee_id IS NULL OR secureai_rls.is_project_participant(project_id, assignee_id)));

CREATE POLICY tasks_update ON secureai.tasks
    FOR UPDATE TO secureai_app
    USING ({perm('task.update')} AND (
        owner_id = {ME}
        OR assignee_id = {ME}
        OR (visibility = 'project' AND {MY_MANAGED})))
    WITH CHECK ({perm('task.update')}
        AND (owner_id = {ME}
             OR assignee_id = {ME}
             OR (visibility = 'project' AND {MY_MANAGED}))
        AND (assignee_id IS NULL OR secureai_rls.is_project_participant(project_id, assignee_id)));

CREATE POLICY tasks_delete ON secureai.tasks
    FOR DELETE TO secureai_app
    USING ({perm('task.delete')} AND (
        owner_id = {ME}
        OR (visibility = 'project' AND {MY_MANAGED})));

-- ---- 5.8 documents
CREATE POLICY documents_select ON secureai.documents
    FOR SELECT TO secureai_app
    USING ({perm('document.read')} AND (
        owner_id = {ME}
        OR visibility = 'organization'
        OR (visibility = 'project' AND ({MY_PROJECTS} OR {perm('project.read_all')}))));

CREATE POLICY documents_insert ON secureai.documents
    FOR INSERT TO secureai_app
    WITH CHECK (
        {perm('document.upload')}
        AND owner_id = {ME}
        AND (project_id IS NULL OR {MY_PROJECTS}));

CREATE POLICY documents_update ON secureai.documents
    FOR UPDATE TO secureai_app
    USING      ({perm('document.update')} AND owner_id = {ME})
    WITH CHECK ({perm('document.update')} AND owner_id = {ME}
                AND (project_id IS NULL OR {MY_PROJECTS}));

CREATE POLICY documents_delete ON secureai.documents
    FOR DELETE TO secureai_app
    USING ({perm('document.delete')} AND owner_id = {ME});

-- ---- 5.9 conversations / messages: strictly personal, even admins excluded.
CREATE POLICY conversations_owner ON secureai.conversations
    FOR ALL TO secureai_app
    USING      (user_id = {ME} AND {perm('chatbot.use')})
    WITH CHECK (user_id = {ME} AND {perm('chatbot.use')});

CREATE POLICY messages_select ON secureai.messages
    FOR SELECT TO secureai_app
    USING (user_id = {ME} AND {perm('chatbot.use')});

-- user_id = me + composite FK (org, conversation_id, user_id) => you can only
-- append to a conversation you own.
CREATE POLICY messages_insert ON secureai.messages
    FOR INSERT TO secureai_app
    WITH CHECK (user_id = {ME} AND {perm('chatbot.use')});

-- ---- 5.10 refresh_token_sessions: scoped to the user, not the org.
CREATE POLICY refresh_sessions_select ON secureai.refresh_token_sessions
    FOR SELECT TO secureai_app USING (user_id = {ME});
CREATE POLICY refresh_sessions_insert ON secureai.refresh_token_sessions
    FOR INSERT TO secureai_app WITH CHECK (user_id = {ME});
CREATE POLICY refresh_sessions_update ON secureai.refresh_token_sessions
    FOR UPDATE TO secureai_app USING (user_id = {ME}) WITH CHECK (user_id = {ME});

-- ---- 5.11 audit_logs
CREATE POLICY audit_logs_select ON secureai.audit_logs
    FOR SELECT TO secureai_app
    USING (organization_id = {ORG} AND {perm('audit.read')});

-- Writes: only into your current org (or org-less auth events) and only as
-- yourself (or anonymous, for pre-authentication events like failed logins).
CREATE POLICY audit_logs_insert ON secureai.audit_logs
    FOR INSERT TO secureai_app
    WITH CHECK (
        (organization_id IS NULL OR organization_id = {ORG})
        AND (actor_user_id IS NULL OR actor_user_id = {ME}));

-- user_credentials, password_reset_tokens: RLS enabled + forced with NO
-- policies => default deny for every non-BYPASSRLS role, even with a GRANT.
"""


def _enable_rls_sql() -> str:
    stmts = []
    for t in TENANT_TABLES + OTHER_RLS_TABLES:
        stmts.append(f"ALTER TABLE secureai.{t} ENABLE ROW LEVEL SECURITY;")
        # FORCE: the table owner is subject to RLS too. Without it, any code
        # path running as the owner silently sees every tenant's rows.
        stmts.append(f"ALTER TABLE secureai.{t} FORCE ROW LEVEL SECURITY;")
    return "\n".join(stmts)


def upgrade() -> None:
    _run(PRIVILEGES_SQL)
    _run("SET LOCAL ROLE secureai_rls_definer")
    _run(HELPERS_SQL)
    _run(FUNCTION_GRANTS_SQL)
    _run("SET LOCAL ROLE secureai_owner")
    _run("REVOKE ALL ON FUNCTION secureai.set_updated_at() FROM PUBLIC")
    _run(TRIGGERS_SQL)
    _run(_enable_rls_sql())
    _run(POLICIES_SQL)


def downgrade() -> None:
    tables = TENANT_TABLES + OTHER_RLS_TABLES
    _run(
        """
        DO $$
        DECLARE r record;
        BEGIN
            FOR r IN SELECT policyname, tablename FROM pg_policies WHERE schemaname = 'secureai' LOOP
                EXECUTE format('DROP POLICY %I ON secureai.%I', r.policyname, r.tablename);
            END LOOP;
        END $$;
        """
    )
    _run("\n".join(
        f"ALTER TABLE secureai.{t} NO FORCE ROW LEVEL SECURITY; "
        f"ALTER TABLE secureai.{t} DISABLE ROW LEVEL SECURITY;" for t in tables))
    _run(
        """
        DROP TRIGGER tasks_enforce_update_rules ON secureai.tasks;
        DROP TRIGGER audit_logs_no_update_delete ON secureai.audit_logs;
        DROP TRIGGER audit_logs_no_truncate ON secureai.audit_logs;
        DROP FUNCTION secureai.enforce_task_update_rules();
        DROP FUNCTION secureai.audit_logs_append_only();
        DROP FUNCTION secureai.is_trusted_maintenance_role();
        DROP SCHEMA secureai_rls CASCADE;
        REVOKE ALL ON ALL TABLES IN SCHEMA secureai FROM secureai_app, secureai_rls_definer;
        REVOKE ALL ON SCHEMA secureai FROM secureai_app, secureai_rls_definer;
        """
    )
