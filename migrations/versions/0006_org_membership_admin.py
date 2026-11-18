"""Phase 3 step 2: organization membership administration.

Four database-side pieces the member APIs need:

1. resolve_invitee(email): invite by email. RLS correctly hides users outside
   the current org, so the app can't look up "the user with this email". This
   narrow definer function does it, only for a caller holding user.create in
   the current org. It returns the user's id, creating a *pending* identity
   (no password) when nobody has the address yet, so an existing and a new
   address get the same answer (no account enumeration). The membership row
   itself is still INSERTed by the app under RLS, so memberships_insert keeps
   deciding the rank and role rules.

2. Consent: a membership becomes active only when the invitee accepts.
   memberships_insert now requires status = 'invited', and a status trigger
   refuses invited/removed -> active (and other odd jumps) for the app role.
   Acceptance goes through respond_to_invitation(), which only ever touches
   the caller's own invited row.

3. my_invitations(): the invitee can't see their invited rows under RLS
   (there's no org context yet, and the tenant fence needs one), so this
   function lists them for the current user only.

4. Logout on removal: when an active membership becomes suspended or removed,
   a trigger revokes every active refresh session of that user
   ('membership_revoked'). Sessions are per user, not per org, so this signs
   the user out everywhere. Org access itself already ends on the next
   request, because set_context() requires an active membership.

Revision ID: 0006_org_membership_admin
Revises: 0005_registration_hardening
Create Date: 2026-11-18
"""

from alembic import op  # noqa: F401

from app.db.migration_utils import run_sql as _run

revision = "0006_org_membership_admin"
down_revision = "0005_registration_hardening"
branch_labels = None
depends_on = None


# As secureai_owner.
GRANTS_SQL = r"""
GRANT SELECT (id, organization_id, user_id, role_id, status, created_at, updated_at)
    ON secureai.organization_memberships TO secureai_auth_definer;
GRANT UPDATE (status) ON secureai.organization_memberships TO secureai_auth_definer;
GRANT SELECT (id, name, status) ON secureai.organizations TO secureai_auth_definer;
GRANT SELECT (id, key) ON secureai.roles TO secureai_auth_definer;
-- respond_to_invitation() updates memberships, which fires the invoker-rights
-- triggers (last-admin, transitions); they ask whether the caller is trusted.
GRANT EXECUTE ON FUNCTION secureai.is_trusted_maintenance_role() TO secureai_auth_definer;
"""

# As secureai_rls_definer (owns the helpers).
RLS_GRANTS_SQL = r"""
GRANT EXECUTE ON FUNCTION secureai_rls.current_org_id(), secureai_rls.has_permission(text)
    TO secureai_auth_definer;
"""

# As secureai_auth_definer.
AUTH_FUNCTIONS_SQL = r"""
-- Email -> user id, for inviting. Only for callers holding user.create in the
-- current org (has_permission is false without an org context). Creates a
-- pending, passwordless identity for an unknown address: the address owner
-- later sets the password through the normal register/verify flow, so the
-- inviter never controls the credentials. display_name is the email's local
-- part, not inviter-supplied text.
CREATE FUNCTION secureai_auth.resolve_invitee(p_email text) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_email text := secureai_auth.normalize_email(p_email);
    v_user  uuid;
BEGIN
    IF NOT secureai_rls.has_permission('user.create') THEN
        RAISE EXCEPTION 'secureai: not allowed to invite members' USING ERRCODE = '42501';
    END IF;
    IF v_email IS NULL THEN
        RAISE EXCEPTION 'secureai: email is required' USING ERRCODE = '22023';
    END IF;

    INSERT INTO secureai.users (email, display_name)
    VALUES (v_email, left(split_part(v_email, '@', 1), 200))
    ON CONFLICT (email) DO NOTHING
    RETURNING id INTO v_user;

    IF v_user IS NULL THEN
        SELECT u.id INTO v_user FROM secureai.users u WHERE u.email = v_email;
    ELSE
        INSERT INTO secureai.audit_logs
            (organization_id, actor_user_id, action, outcome, resource_type, resource_id,
             request_id, metadata)
        VALUES (secureai_rls.current_org_id(), secureai_rls.current_user_id(),
                'member.invitee_created', 'success', 'user', v_user,
                left(NULLIF(current_setting('secureai.request_id', true), ''), 128),
                '{"status": "pending"}');
    END IF;
    RETURN v_user;
END $$;

-- The caller's pending invitations, across orgs. Nothing about anyone else.
CREATE FUNCTION secureai_auth.my_invitations()
RETURNS TABLE (organization_id uuid, organization_name text, role text, invited_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT m.organization_id, o.name, r.key, m.updated_at
    FROM secureai.organization_memberships m
    JOIN secureai.organizations o ON o.id = m.organization_id
    JOIN secureai.roles r         ON r.id = m.role_id
    WHERE m.user_id = secureai_rls.current_user_id()
      AND m.status = 'invited' AND o.status = 'active'
    ORDER BY m.updated_at DESC, m.organization_id
$$;

-- Accept (-> active) or decline (-> removed) the caller's own invitation.
-- Returns false when there is no such pending invitation. Runs as a
-- BYPASSRLS role, so the status trigger treats it as the trusted path; the
-- WHERE clause is what limits it to the caller's own invited row.
CREATE FUNCTION secureai_auth.respond_to_invitation(p_org_id uuid, p_accept boolean)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_me uuid := secureai_rls.current_user_id();
    v_id uuid;
BEGIN
    IF v_me IS NULL THEN
        RAISE EXCEPTION 'secureai: user context is required' USING ERRCODE = '42501';
    END IF;
    IF p_accept IS NULL THEN
        RAISE EXCEPTION 'secureai: accept must be true or false' USING ERRCODE = '22023';
    END IF;

    UPDATE secureai.organization_memberships m
    SET status = CASE WHEN p_accept THEN 'active' ELSE 'removed' END
    WHERE m.organization_id = p_org_id AND m.user_id = v_me AND m.status = 'invited'
      AND EXISTS (SELECT 1 FROM secureai.organizations o
                  WHERE o.id = m.organization_id AND o.status = 'active')
    RETURNING m.id INTO v_id;
    IF v_id IS NULL THEN
        RETURN false;
    END IF;

    INSERT INTO secureai.audit_logs
        (organization_id, actor_user_id, action, outcome, resource_type, resource_id, request_id)
    VALUES (p_org_id, v_me,
            CASE WHEN p_accept THEN 'member.invitation_accepted' ELSE 'member.invitation_declined' END,
            'success', 'organization_membership', v_id,
            left(NULLIF(current_setting('secureai.request_id', true), ''), 128));
    RETURN true;
END $$;

-- Trigger: an active membership became suspended/removed -> sign the user out.
-- Locks the user's credentials row first, like every other function that
-- changes auth state. Without it, a refresh rotating concurrently could insert
-- a new session after this UPDATE's snapshot was taken, and that session
-- would survive.
CREATE FUNCTION secureai_auth.revoke_sessions_on_membership_end() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_count integer;
BEGIN
    PERFORM 1 FROM secureai.user_credentials c WHERE c.user_id = NEW.user_id FOR UPDATE;
    UPDATE secureai.refresh_token_sessions s
    SET status = 'revoked', revoked_reason = 'membership_revoked', revoked_at = now()
    WHERE s.user_id = NEW.user_id AND s.status = 'active';
    GET DIAGNOSTICS v_count = ROW_COUNT;

    INSERT INTO secureai.audit_logs
        (organization_id, actor_user_id, action, outcome, resource_type, resource_id,
         request_id, metadata)
    VALUES (NEW.organization_id, secureai_rls.current_user_id(), 'auth.sessions_revoked',
            'success', 'user', NEW.user_id,
            left(NULLIF(current_setting('secureai.request_id', true), ''), 128),
            jsonb_build_object('reason', 'membership_' || NEW.status, 'sessions', v_count));
    RETURN NULL;
END $$;

REVOKE ALL ON FUNCTION
    secureai_auth.resolve_invitee(text),
    secureai_auth.my_invitations(),
    secureai_auth.respond_to_invitation(uuid, boolean),
    secureai_auth.revoke_sessions_on_membership_end()
FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
    secureai_auth.resolve_invitee(text),
    secureai_auth.my_invitations(),
    secureai_auth.respond_to_invitation(uuid, boolean)
TO secureai_app;
-- The owner creates the trigger (CREATE TRIGGER checks EXECUTE). A trigger
-- function can't be called directly, so the app gets nothing here.
GRANT EXECUTE ON FUNCTION secureai_auth.revoke_sessions_on_membership_end() TO secureai_owner;
"""

# As secureai_owner.
TRIGGERS_AND_POLICY_SQL = r"""
-- Insert is now invite-only: nobody is put into an org as 'active' by
-- someone else. (Seeds/ops use BYPASSRLS and are not affected.)
DROP POLICY memberships_insert ON secureai.organization_memberships;
CREATE POLICY memberships_insert ON secureai.organization_memberships
    FOR INSERT TO secureai_app
    WITH CHECK (
        (SELECT secureai_rls.has_permission('user.create'))
        AND user_id <> (SELECT secureai_rls.current_user_id())
        AND invited_by = (SELECT secureai_rls.current_user_id())
        AND status = 'invited'
        AND secureai_rls.can_assign_role(role_id));

-- RLS's WITH CHECK sees only the NEW row, so it can't express transitions.
-- Allowed for the app role:
--   active <-> suspended                  (suspend / reinstate)
--   invited | active | suspended -> removed
--   removed -> invited                    (invite again)
-- Everything else, notably invited/removed -> active, is refused: only the
-- invitee activates a membership, via respond_to_invitation().
-- AFTER (not BEFORE), so RLS refusals are reported first, like the last-admin trigger.
CREATE FUNCTION secureai.enforce_membership_transitions() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF secureai.is_trusted_maintenance_role() THEN
        RETURN NULL;
    END IF;
    IF (NEW.status = 'active'    AND OLD.status <> 'suspended')
    OR (NEW.status = 'suspended' AND OLD.status <> 'active')
    OR (NEW.status = 'invited'   AND OLD.status <> 'removed') THEN
        RAISE EXCEPTION 'secureai: membership status cannot change from % to %',
            OLD.status, NEW.status USING ERRCODE = '42501';
    END IF;
    RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION secureai.enforce_membership_transitions() FROM PUBLIC;

CREATE TRIGGER organization_memberships_transitions
    AFTER UPDATE OF status ON secureai.organization_memberships
    FOR EACH ROW WHEN (OLD.status IS DISTINCT FROM NEW.status)
    EXECUTE FUNCTION secureai.enforce_membership_transitions();

CREATE TRIGGER organization_memberships_revoke_sessions
    AFTER UPDATE OF status ON secureai.organization_memberships
    FOR EACH ROW WHEN (OLD.status = 'active' AND NEW.status IN ('suspended', 'removed'))
    EXECUTE FUNCTION secureai_auth.revoke_sessions_on_membership_end();
"""


def upgrade() -> None:
    _run(GRANTS_SQL)
    _run("SET LOCAL ROLE secureai_rls_definer")
    _run(RLS_GRANTS_SQL)
    _run("SET LOCAL ROLE secureai_auth_definer")
    _run(AUTH_FUNCTIONS_SQL)
    _run("SET LOCAL ROLE secureai_owner")
    _run(TRIGGERS_AND_POLICY_SQL)


def downgrade() -> None:
    _run("""
        DROP TRIGGER organization_memberships_revoke_sessions ON secureai.organization_memberships;
        DROP TRIGGER organization_memberships_transitions ON secureai.organization_memberships;
        DROP FUNCTION secureai.enforce_membership_transitions();
        DROP POLICY memberships_insert ON secureai.organization_memberships;
        CREATE POLICY memberships_insert ON secureai.organization_memberships
            FOR INSERT TO secureai_app
            WITH CHECK (
                (SELECT secureai_rls.has_permission('user.create'))
                AND user_id <> (SELECT secureai_rls.current_user_id())
                AND invited_by = (SELECT secureai_rls.current_user_id())
                AND status IN ('invited', 'active')
                AND secureai_rls.can_assign_role(role_id));
    """)
    _run("SET LOCAL ROLE secureai_auth_definer")
    _run("""
        DROP FUNCTION secureai_auth.revoke_sessions_on_membership_end();
        DROP FUNCTION secureai_auth.respond_to_invitation(uuid, boolean);
        DROP FUNCTION secureai_auth.my_invitations();
        DROP FUNCTION secureai_auth.resolve_invitee(text);
    """)
    _run("SET LOCAL ROLE secureai_rls_definer")
    _run("REVOKE EXECUTE ON FUNCTION secureai_rls.current_org_id(), "
         "secureai_rls.has_permission(text) FROM secureai_auth_definer;")
    _run("SET LOCAL ROLE secureai_owner")
    _run("""
        REVOKE SELECT (id, organization_id, user_id, role_id, status, created_at, updated_at),
               UPDATE (status) ON secureai.organization_memberships FROM secureai_auth_definer;
        REVOKE SELECT (id, name, status) ON secureai.organizations FROM secureai_auth_definer;
        REVOKE SELECT (id, key) ON secureai.roles FROM secureai_auth_definer;
        REVOKE EXECUTE ON FUNCTION secureai.is_trusted_maintenance_role() FROM secureai_auth_definer;
    """)
