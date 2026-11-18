"""Phase 2 step 3: self-registration with email verification, request ids in
auth audit rows, and the "at least one active administrator" invariant.

Registration design (pre-account-takeover resistant):
  register_user(email, name)            -> pending user, NO password, verification token
  verify_email_and_set_password(token)  -> sets the password AND activates
The password is chosen only by whoever can read the verification email. If
registration took a password, an attacker could pre-register a victim's
address with a password they know. When the victim clicked "verify" (or
registered again), the account would go live with the attacker's password.

Revision ID: 0005_registration_hardening
Revises: 0004_auth_functions
Create Date: 2026-11-18
"""

from alembic import op  # noqa: F401

from app.db.migration_utils import run_sql as _run

revision = "0005_registration_hardening"
down_revision = "0004_auth_functions"
branch_labels = None
depends_on = None


# As secureai_owner.
SCHEMA_SQL = r"""
CREATE TABLE secureai.email_verification_tokens (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES secureai.users (id) ON DELETE CASCADE,
    token_hash  bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    requested_ip inet,
    CONSTRAINT email_verification_expiry CHECK (
        expires_at > created_at AND expires_at <= created_at + interval '24 hours')
);
CREATE INDEX email_verification_tokens_user_idx ON secureai.email_verification_tokens (user_id);

-- Same posture as password_reset_tokens: RLS on, no policies, no app grants.
ALTER TABLE secureai.email_verification_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE secureai.email_verification_tokens FORCE ROW LEVEL SECURITY;

GRANT SELECT (id, user_id, token_hash, created_at, expires_at, used_at)
    ON secureai.email_verification_tokens TO secureai_auth_definer;
GRANT INSERT (user_id, token_hash, expires_at, requested_ip)
    ON secureai.email_verification_tokens TO secureai_auth_definer;
GRANT UPDATE (used_at) ON secureai.email_verification_tokens TO secureai_auth_definer;
GRANT DELETE ON secureai.email_verification_tokens TO secureai_auth_definer;

-- Registration creates pending users and activates them. UPDATE on status is
-- also what permits SELECT ... FOR UPDATE (the per-user lock for users that
-- have no credentials row yet).
GRANT INSERT (email, display_name) ON secureai.users TO secureai_auth_definer;
GRANT UPDATE (status, email_verified_at) ON secureai.users TO secureai_auth_definer;
GRANT INSERT (user_id, password_hash) ON secureai.user_credentials TO secureai_auth_definer;
"""


# As secureai_auth_definer.
AUTH_FUNCTIONS_SQL = r"""
-- Same signature; now stamps the request id the app set with
-- set_config('secureai.request_id', ..., true) for this transaction.
CREATE OR REPLACE FUNCTION secureai_auth.audit(
    p_action text, p_outcome text, p_actor uuid, p_resource_type text, p_resource_id uuid,
    p_ip inet, p_user_agent text, p_metadata jsonb DEFAULT '{}'::jsonb)
RETURNS void
LANGUAGE sql VOLATILE SET search_path = pg_catalog, pg_temp AS $$
    INSERT INTO secureai.audit_logs
        (actor_user_id, action, outcome, resource_type, resource_id, ip_address, user_agent,
         request_id, metadata)
    VALUES (p_actor, p_action, p_outcome, p_resource_type, p_resource_id, p_ip,
            left(p_user_agent, 512),
            left(NULLIF(current_setting('secureai.request_id', true), ''), 128),
            COALESCE(p_metadata, '{}'::jsonb))
$$;

-- Outcomes (the API responds identically to all of them):
--   created       new pending user, send the verification email
--   resent        existing pending user, send a fresh verification email
--   exists        already active, send an "you already have an account" notice
--   suppressed    disabled/locked account, or a concurrent duplicate: send nothing
--   rate_limited  more than 3 emails per user per hour: send nothing
CREATE FUNCTION secureai_auth.register_user(
    p_email text, p_display_name text, p_token_hash bytea,
    p_ttl interval DEFAULT interval '24 hours',
    p_ip inet DEFAULT NULL, p_user_agent text DEFAULT NULL)
RETURNS TABLE (outcome text, user_id uuid)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    c_max_per_hour constant integer := 3;
    v_email  text := secureai_auth.normalize_email(p_email);
    v_user   uuid;
    v_status text;
    v_recent integer;
BEGIN
    IF p_ttl IS NULL OR p_ttl < interval '10 minutes' OR p_ttl > interval '24 hours' THEN
        RAISE EXCEPTION 'secureai: verification ttl out of range' USING ERRCODE = '22023';
    END IF;
    IF v_email IS NULL THEN
        RAISE EXCEPTION 'secureai: email is required' USING ERRCODE = '22023';
    END IF;

    SELECT u.id, u.status INTO v_user, v_status
    FROM secureai.users u WHERE u.email = v_email
    FOR UPDATE;

    IF v_user IS NULL THEN
        BEGIN
            INSERT INTO secureai.users (email, display_name) VALUES (v_email, p_display_name)
            RETURNING id INTO v_user;
        EXCEPTION WHEN unique_violation THEN
            -- A concurrent registration of the same address won the race.
            outcome := 'suppressed';
            RETURN NEXT;
            RETURN;
        END;
        INSERT INTO secureai.email_verification_tokens (user_id, token_hash, expires_at, requested_ip)
        VALUES (v_user, p_token_hash, now() + p_ttl, p_ip);
        PERFORM secureai_auth.audit('auth.register', 'success', v_user, 'user', v_user,
                                    p_ip, p_user_agent, '{"result": "created"}');
        outcome := 'created';
        user_id := v_user;
        RETURN NEXT;
        RETURN;
    END IF;

    user_id := v_user;
    IF v_status NOT IN ('pending', 'active') THEN
        PERFORM secureai_auth.audit('auth.register', 'denied', v_user, 'user', v_user,
                                    p_ip, p_user_agent, jsonb_build_object('reason', 'account_' || v_status));
        outcome := 'suppressed';
        RETURN NEXT;
        RETURN;
    END IF;

    SELECT count(*) INTO v_recent FROM secureai.audit_logs a
    WHERE a.actor_user_id = v_user AND a.action = 'auth.register' AND a.outcome = 'success'
      AND a.occurred_at > now() - interval '1 hour';
    IF v_recent >= c_max_per_hour THEN
        PERFORM secureai_auth.audit('auth.register', 'denied', v_user, 'user', v_user,
                                    p_ip, p_user_agent, '{"reason": "rate_limited"}');
        outcome := 'rate_limited';
        RETURN NEXT;
        RETURN;
    END IF;

    IF v_status = 'pending' THEN
        DELETE FROM secureai.email_verification_tokens t
        WHERE t.user_id = v_user AND t.used_at IS NULL;
        INSERT INTO secureai.email_verification_tokens (user_id, token_hash, expires_at, requested_ip)
        VALUES (v_user, p_token_hash, now() + p_ttl, p_ip);
        outcome := 'resent';
    ELSE
        outcome := 'exists';
    END IF;
    PERFORM secureai_auth.audit('auth.register', 'success', v_user, 'user', v_user,
                                p_ip, p_user_agent, jsonb_build_object('result', outcome));
    RETURN NEXT;
END $$;

-- Redeem a verification token: set the password and activate. Returns the
-- user id, or NULL (invalid / used / expired / not pending).
CREATE FUNCTION secureai_auth.verify_email_and_set_password(
    p_token_hash bytea, p_password_hash text,
    p_ip inet DEFAULT NULL, p_user_agent text DEFAULT NULL)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    v_token_id uuid;
    v_user     uuid;
    v_used     timestamptz;
    v_expires  timestamptz;
    v_status   text;
    v_reason   text;
BEGIN
    IF p_password_hash IS NULL OR p_password_hash NOT LIKE '$argon2id$v=19$%' THEN
        RAISE EXCEPTION 'secureai: password hash must be argon2id' USING ERRCODE = '22023';
    END IF;

    SELECT t.id, t.user_id, t.used_at, t.expires_at INTO v_token_id, v_user, v_used, v_expires
    FROM secureai.email_verification_tokens t WHERE t.token_hash = p_token_hash
    FOR UPDATE;
    IF v_token_id IS NULL THEN
        PERFORM secureai_auth.audit('auth.email_verified', 'failure', NULL, NULL, NULL,
                                    p_ip, p_user_agent, '{"reason": "unknown_token"}');
        RETURN NULL;
    END IF;

    SELECT u.status INTO v_status FROM secureai.users u WHERE u.id = v_user FOR UPDATE;
    v_reason := CASE
        WHEN v_used IS NOT NULL      THEN 'token_used'
        WHEN v_expires <= now()      THEN 'token_expired'
        WHEN v_status <> 'pending'   THEN 'not_pending'
    END;
    IF v_reason IS NOT NULL THEN
        PERFORM secureai_auth.audit('auth.email_verified', 'denied', v_user,
                                    'email_verification_token', v_token_id, p_ip, p_user_agent,
                                    jsonb_build_object('reason', v_reason));
        RETURN NULL;
    END IF;

    UPDATE secureai.email_verification_tokens t SET used_at = now() WHERE t.id = v_token_id;
    DELETE FROM secureai.email_verification_tokens t WHERE t.user_id = v_user AND t.used_at IS NULL;

    INSERT INTO secureai.user_credentials (user_id, password_hash) VALUES (v_user, p_password_hash)
    ON CONFLICT (user_id) DO UPDATE
        SET password_hash = EXCLUDED.password_hash, password_changed_at = now();
    UPDATE secureai.users u SET status = 'active', email_verified_at = now() WHERE u.id = v_user;

    PERFORM secureai_auth.audit('auth.email_verified', 'success', v_user,
                                'email_verification_token', v_token_id, p_ip, p_user_agent);
    RETURN v_user;
END $$;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA secureai_auth FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
    secureai_auth.register_user(text, text, bytea, interval, inet, text),
    secureai_auth.verify_email_and_set_password(bytea, text, inet, text)
TO secureai_app;
"""


# As secureai_rls_definer (needs to count memberships without RLS).
LAST_ADMIN_HELPER_SQL = r"""
-- Active administrators of the CURRENT org. "Administrator" = a role whose
-- role-level permissions include user.update. That is a permission, not a role
-- name, consistent with Phase 1 §5. Answers only for the current org, so it
-- can't be used as a cross-tenant oracle.
CREATE FUNCTION secureai_rls.active_admin_count(p_org_id uuid) RETURNS integer
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT count(*)::integer
    FROM secureai.organization_memberships m
    JOIN secureai.users u ON u.id = m.user_id
    WHERE m.organization_id = p_org_id
      AND p_org_id = secureai_rls.current_org_id()
      AND m.status = 'active' AND u.status = 'active'
      AND EXISTS (SELECT 1 FROM secureai.role_permissions rp
                  JOIN secureai.permissions p ON p.id = rp.permission_id
                  WHERE rp.role_id = m.role_id AND p.code = 'user.update')
$$;

CREATE FUNCTION secureai_rls.is_admin_role(p_role_id uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT EXISTS (SELECT 1 FROM secureai.role_permissions rp
                   JOIN secureai.permissions p ON p.id = rp.permission_id
                   WHERE rp.role_id = p_role_id AND p.code = 'user.update')
$$;

REVOKE ALL ON FUNCTION secureai_rls.active_admin_count(uuid), secureai_rls.is_admin_role(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureai_rls.active_admin_count(uuid), secureai_rls.is_admin_role(uuid)
    TO secureai_app, secureai_owner;
"""


# As secureai_owner. The trigger function is SECURITY INVOKER on purpose, so
# that is_trusted_maintenance_role() sees the real caller.
LAST_ADMIN_TRIGGER_SQL = r"""
-- Phase 1 residual risk: two admins demoting/suspending each other in
-- concurrent transactions both pass RLS (each still sees itself as admin)
-- and leave the org with zero administrators.
--
-- Fix: when an active admin membership stops being one, take a per-org
-- advisory lock, then re-count in a NEW statement. Under READ COMMITTED that
-- statement sees the other transaction's committed change, so the second
-- demotion fails.
CREATE FUNCTION secureai.enforce_last_admin() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF secureai.is_trusted_maintenance_role() THEN
        RETURN NULL;
    END IF;
    IF OLD.status <> 'active' OR NOT secureai_rls.is_admin_role(OLD.role_id) THEN
        RETURN NULL;  -- the row wasn't an active admin, nothing to lose
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.status = 'active' AND secureai_rls.is_admin_role(NEW.role_id) THEN
        RETURN NULL;  -- still an active admin
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('secureai.org_admins:' || OLD.organization_id::text, 0));
    IF secureai_rls.active_admin_count(OLD.organization_id) < 1 THEN
        RAISE EXCEPTION 'secureai: an organization must keep at least one active administrator'
            USING ERRCODE = '42501';
    END IF;
    RETURN NULL;
END $$;

REVOKE ALL ON FUNCTION secureai.enforce_last_admin() FROM PUBLIC;

CREATE TRIGGER organization_memberships_last_admin
    AFTER UPDATE OF role_id, status OR DELETE ON secureai.organization_memberships
    FOR EACH ROW EXECUTE FUNCTION secureai.enforce_last_admin();
"""


def upgrade() -> None:
    _run(SCHEMA_SQL)
    _run("SET LOCAL ROLE secureai_auth_definer")
    _run(AUTH_FUNCTIONS_SQL)
    _run("SET LOCAL ROLE secureai_rls_definer")
    _run(LAST_ADMIN_HELPER_SQL)
    _run("SET LOCAL ROLE secureai_owner")
    _run(LAST_ADMIN_TRIGGER_SQL)


def downgrade() -> None:
    _run("""
        DROP TRIGGER organization_memberships_last_admin ON secureai.organization_memberships;
        DROP FUNCTION secureai.enforce_last_admin();
    """)
    _run("SET LOCAL ROLE secureai_rls_definer")
    _run("DROP FUNCTION secureai_rls.active_admin_count(uuid), secureai_rls.is_admin_role(uuid);")
    _run("SET LOCAL ROLE secureai_auth_definer")
    _run("""
        DROP FUNCTION secureai_auth.verify_email_and_set_password(bytea, text, inet, text);
        DROP FUNCTION secureai_auth.register_user(text, text, bytea, interval, inet, text);
        CREATE OR REPLACE FUNCTION secureai_auth.audit(
            p_action text, p_outcome text, p_actor uuid, p_resource_type text, p_resource_id uuid,
            p_ip inet, p_user_agent text, p_metadata jsonb DEFAULT '{}'::jsonb)
        RETURNS void
        LANGUAGE sql VOLATILE SET search_path = pg_catalog, pg_temp AS $$
            INSERT INTO secureai.audit_logs
                (actor_user_id, action, outcome, resource_type, resource_id, ip_address, user_agent, metadata)
            VALUES (p_actor, p_action, p_outcome, p_resource_type, p_resource_id, p_ip,
                    left(p_user_agent, 512), COALESCE(p_metadata, '{}'::jsonb))
        $$;
    """)
    _run("SET LOCAL ROLE secureai_owner")
    _run("""
        REVOKE INSERT (email, display_name), UPDATE (status, email_verified_at)
            ON secureai.users FROM secureai_auth_definer;
        REVOKE INSERT (user_id, password_hash) ON secureai.user_credentials FROM secureai_auth_definer;
        DROP TABLE secureai.email_verification_tokens;
    """)
