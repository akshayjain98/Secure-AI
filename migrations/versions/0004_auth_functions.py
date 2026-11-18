"""Phase 2 authentication layer: the secureai_auth schema of SECURITY DEFINER functions.

Pre-authentication flows (login, refresh rotation, logout by refresh token,
password reset) run before any user identity exists, so RLS (which keys on
secureai_rls.current_user_id()) can't authorize them. Instead of giving the app
role broad grants, each flow is a narrow function owned by secureai_auth_definer:

  begin_login               email -> argon2 hash, counting the attempt up front
  complete_login            record the app-side verification result
  rotate_refresh_session    single-use refresh tokens with family reuse detection
  revoke_refresh_session    logout using only the refresh token
  request_password_reset    store a reset-token hash (rate-limited, enumeration-safe)
  consume_password_reset    one-time token -> new hash + revoke every session
  change_password           authenticated; uses the RLS context, not a parameter

Hashing split: Argon2id and HMAC-SHA256(pepper, token) are computed in the
application. The DB never sees a plaintext password or token, and the app never
reads a reset-token or refresh-token hash back.

Concurrency: every function that changes a user's auth state first locks that
user's user_credentials row (FOR UPDATE). That one per-user lock serialises
rotation, reuse revocation, logout, password reset and the login counter, so
"two refreshes with the same token" and "refresh racing a password reset"
can't interleave. See docs/phase-2-authentication.md section 4.

Requires the secureai_auth_definer role (created by the superuser bootstrap,
or by docker/postgres/upgrades/0004_auth_definer_role.sh on older volumes).

Revision ID: 0004_auth_functions
Revises: 0003_rbac_reference_data
Create Date: 2026-11-18
"""

from alembic import op  # noqa: F401

from app.db.migration_utils import run_sql as _run

revision = "0004_auth_functions"
down_revision = "0003_rbac_reference_data"
branch_labels = None
depends_on = None


PREFLIGHT_SQL = r"""
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'secureai_auth_definer') THEN
        RAISE EXCEPTION 'role secureai_auth_definer is missing: run '
            'docker/postgres/upgrades/0004_auth_definer_role.sh as the superuser first';
    END IF;
    IF NOT pg_has_role(session_user, 'secureai_auth_definer', 'MEMBER') THEN
        RAISE EXCEPTION '% must be a member of secureai_auth_definer', session_user;
    END IF;
END $$;
"""

# Runs as secureai_owner (owns the schemas and tables, so it can grant on them).
PRIVILEGES_SQL = r"""
CREATE SCHEMA secureai_auth AUTHORIZATION secureai_owner;
REVOKE ALL ON SCHEMA secureai_auth FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA secureai_auth TO secureai_auth_definer;
GRANT USAGE ON SCHEMA secureai_auth TO secureai_app;

GRANT USAGE ON SCHEMA secureai, secureai_rls TO secureai_auth_definer;

-- Exactly the columns the auth flows touch. No DELETE except on reset tokens.
GRANT SELECT (id, email, status) ON secureai.users TO secureai_auth_definer;

GRANT SELECT (user_id, password_hash, failed_login_count, locked_until)
    ON secureai.user_credentials TO secureai_auth_definer;
GRANT UPDATE (password_hash, password_changed_at, failed_login_count, locked_until)
    ON secureai.user_credentials TO secureai_auth_definer;

-- token_hash: needed to filter on it (WHERE token_hash = ...). No function
-- ever returns a hash.
GRANT SELECT (id, user_id, family_id, token_hash, status, created_at, expires_at)
    ON secureai.refresh_token_sessions TO secureai_auth_definer;
GRANT INSERT (user_id, family_id, parent_id, token_hash, expires_at, user_agent, ip_address)
    ON secureai.refresh_token_sessions TO secureai_auth_definer;
GRANT UPDATE (status, revoked_reason, revoked_at, last_used_at, rotated_at)
    ON secureai.refresh_token_sessions TO secureai_auth_definer;

-- token_hash is in the SELECT grant because lookups filter on it. Raw hashes
-- are never returned by any function.
GRANT SELECT (id, user_id, token_hash, created_at, expires_at, used_at)
    ON secureai.password_reset_tokens TO secureai_auth_definer;
GRANT INSERT (user_id, token_hash, expires_at, requested_ip)
    ON secureai.password_reset_tokens TO secureai_auth_definer;
GRANT UPDATE (used_at) ON secureai.password_reset_tokens TO secureai_auth_definer;
GRANT DELETE ON secureai.password_reset_tokens TO secureai_auth_definer;

-- Audit: append, plus the columns needed to count recent reset requests.
GRANT INSERT (organization_id, actor_user_id, action, resource_type, resource_id, outcome,
              request_id, ip_address, user_agent, metadata)
    ON secureai.audit_logs TO secureai_auth_definer;
GRANT SELECT (actor_user_id, action, outcome, occurred_at)
    ON secureai.audit_logs TO secureai_auth_definer;
"""

# Runs as secureai_rls_definer, which owns these functions.
RLS_HELPER_GRANTS_SQL = r"""
GRANT EXECUTE ON FUNCTION secureai_rls.current_user_id(), secureai_rls.tx_stamp()
    TO secureai_auth_definer;
"""

# Runs as secureai_auth_definer, so that role owns every function below.
#
# Conventions (same as secureai_rls):
#   * SECURITY DEFINER + SET search_path = pg_catalog, pg_temp + fully qualified names.
#   * "#variable_conflict use_column": OUT parameters such as user_id share names
#     with table columns. Inside SQL the column always wins; OUT values are
#     set only by plain PL/pgSQL assignment.
#   * Outcomes are returned as text codes for the application to map. The API
#     must collapse them to one uniform client response (no account enumeration).
FUNCTIONS_SQL = r"""
-- ---------------------------------------------------------------- internals
CREATE FUNCTION secureai_auth.audit(
    p_action text, p_outcome text, p_actor uuid, p_resource_type text, p_resource_id uuid,
    p_ip inet, p_user_agent text, p_metadata jsonb DEFAULT '{}'::jsonb)
RETURNS void
LANGUAGE sql VOLATILE SET search_path = pg_catalog, pg_temp AS $$
    INSERT INTO secureai.audit_logs
        (actor_user_id, action, outcome, resource_type, resource_id, ip_address, user_agent, metadata)
    VALUES (p_actor, p_action, p_outcome, p_resource_type, p_resource_id, p_ip,
            left(p_user_agent, 512), COALESCE(p_metadata, '{}'::jsonb))
$$;

-- Normalise exactly the way users.email is constrained (lowercase). Over-long
-- input can't match any row; NULL makes the lookup miss instead of erroring.
CREATE FUNCTION secureai_auth.normalize_email(p_email text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT CASE WHEN char_length(p_email) <= 320 THEN lower(btrim(p_email)) END
$$;

-- --------------------------------------------------------------------- login
-- Step 1 of 2. Returns the stored Argon2id hash so the app can verify it.
--
-- The attempt is counted pessimistically: failed_login_count is incremented
-- HERE, before verification, and reset by complete_login(success => true).
-- So the counter also advances when complete_login is never called (crash,
-- killed request), and bulk hash extraction through this function trips the
-- lockout and leaves an audit trail.
--
-- Outcomes: ok | unknown | inactive | locked.  Only 'ok' carries a hash.
CREATE FUNCTION secureai_auth.begin_login(
    p_email text, p_ip inet DEFAULT NULL, p_user_agent text DEFAULT NULL)
RETURNS TABLE (outcome text, user_id uuid, password_hash text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    c_max_failures  constant integer  := 5;
    c_lock_duration constant interval := interval '15 minutes';
    v_user_id  uuid;
    v_status   text;
    v_hash     text;
    v_failed   integer;
    v_locked   timestamptz;
BEGIN
    SELECT u.id, u.status INTO v_user_id, v_status
    FROM secureai.users u WHERE u.email = secureai_auth.normalize_email(p_email);

    IF v_user_id IS NULL THEN
        -- The attempted email is NOT recorded: users paste passwords into it.
        PERFORM secureai_auth.audit('auth.login', 'failure', NULL, NULL, NULL,
                                    p_ip, p_user_agent, '{"reason": "unknown_user"}');
        outcome := 'unknown';
        RETURN NEXT;
        RETURN;
    END IF;

    SELECT c.password_hash, c.failed_login_count, c.locked_until
      INTO v_hash, v_failed, v_locked
    FROM secureai.user_credentials c WHERE c.user_id = v_user_id
    FOR UPDATE;

    IF NOT FOUND THEN
        PERFORM secureai_auth.audit('auth.login', 'failure', v_user_id, 'user', v_user_id,
                                    p_ip, p_user_agent, '{"reason": "no_credentials"}');
        outcome := 'unknown';
        RETURN NEXT;
        RETURN;
    END IF;

    IF v_status <> 'active' THEN
        PERFORM secureai_auth.audit('auth.login', 'denied', v_user_id, 'user', v_user_id,
                                    p_ip, p_user_agent,
                                    jsonb_build_object('reason', 'account_' || v_status));
        outcome := 'inactive';
        RETURN NEXT;
        RETURN;
    END IF;

    IF v_locked > now() THEN
        PERFORM secureai_auth.audit('auth.login', 'denied', v_user_id, 'user', v_user_id,
                                    p_ip, p_user_agent, '{"reason": "locked_out"}');
        outcome := 'locked';
        RETURN NEXT;
        RETURN;
    END IF;

    -- A lockout that has expired starts a fresh window.
    IF v_locked IS NOT NULL THEN
        v_failed := 0;
    END IF;
    v_failed := v_failed + 1;

    UPDATE secureai.user_credentials c
    SET failed_login_count = v_failed,
        locked_until = CASE WHEN v_failed >= c_max_failures THEN now() + c_lock_duration END
    WHERE c.user_id = v_user_id;

    outcome := 'ok';
    user_id := v_user_id;
    password_hash := v_hash;
    RETURN NEXT;
END $$;

-- Step 2 of 2. On success: clear the counter/lockout and optionally store a
-- rehashed password (argon2 parameters upgraded). Fails closed if the account
-- was disabled in between.
CREATE FUNCTION secureai_auth.complete_login(
    p_user_id uuid, p_success boolean, p_rehashed_password text DEFAULT NULL,
    p_ip inet DEFAULT NULL, p_user_agent text DEFAULT NULL)
RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    v_failed integer;
BEGIN
    IF p_user_id IS NULL OR p_success IS NULL THEN
        RAISE EXCEPTION 'secureai: complete_login requires user and result' USING ERRCODE = '22023';
    END IF;

    IF NOT p_success THEN
        SELECT c.failed_login_count INTO v_failed
        FROM secureai.user_credentials c WHERE c.user_id = p_user_id;
        PERFORM secureai_auth.audit('auth.login', 'failure', p_user_id, 'user', p_user_id,
                                    p_ip, p_user_agent,
                                    jsonb_build_object('reason', 'bad_password',
                                                       'consecutive_failures', v_failed));
        RETURN;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM secureai.users u WHERE u.id = p_user_id AND u.status = 'active') THEN
        RAISE EXCEPTION 'secureai: user is not active' USING ERRCODE = '42501';
    END IF;

    UPDATE secureai.user_credentials c
    SET failed_login_count = 0,
        locked_until = NULL,
        password_hash = COALESCE(p_rehashed_password, c.password_hash)
    WHERE c.user_id = p_user_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'secureai: no credentials for user' USING ERRCODE = '42501';
    END IF;

    PERFORM secureai_auth.audit('auth.login', 'success', p_user_id, 'user', p_user_id,
                                p_ip, p_user_agent,
                                jsonb_build_object('rehashed', p_rehashed_password IS NOT NULL));
END $$;

-- ------------------------------------------------------------ refresh tokens
-- Starts a new token family right after a successful login.
CREATE FUNCTION secureai_auth.create_refresh_session(
    p_user_id uuid, p_token_hash bytea, p_ttl interval,
    p_ip inet DEFAULT NULL, p_user_agent text DEFAULT NULL)
RETURNS TABLE (session_id uuid, family_id uuid, expires_at timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    v_id      uuid;
    v_family  uuid := gen_random_uuid();
    v_expires timestamptz;
BEGIN
    IF p_ttl IS NULL OR p_ttl < interval '1 minute' OR p_ttl > interval '30 days' THEN
        RAISE EXCEPTION 'secureai: refresh ttl out of range' USING ERRCODE = '22023';
    END IF;

    PERFORM 1 FROM secureai.user_credentials c WHERE c.user_id = p_user_id FOR UPDATE;
    IF NOT EXISTS (SELECT 1 FROM secureai.users u WHERE u.id = p_user_id AND u.status = 'active') THEN
        RAISE EXCEPTION 'secureai: user is not active' USING ERRCODE = '42501';
    END IF;

    v_expires := now() + p_ttl;
    INSERT INTO secureai.refresh_token_sessions
        (user_id, family_id, token_hash, expires_at, user_agent, ip_address)
    VALUES (p_user_id, v_family, p_token_hash, v_expires, left(p_user_agent, 512), p_ip)
    RETURNING id INTO v_id;

    session_id := v_id;
    family_id := v_family;
    expires_at := v_expires;
    RETURN NEXT;
END $$;

-- Exchange a refresh token for a new one. Each token is single-use.
--
-- Outcomes:
--   ok              new session row inserted (same family, parent = old row)
--   invalid         no such token
--   reuse_detected  token was already rotated => stolen or replayed: the
--                   whole family is revoked, which logs out the attacker AND
--                   the victim, who must then sign in again
--   revoked | expired | inactive
--
-- Lifetime: sliding p_idle_ttl per rotation, capped at 30 days from the
-- family's first login (re-authentication is forced eventually).
CREATE FUNCTION secureai_auth.rotate_refresh_session(
    p_presented_hash bytea, p_new_hash bytea, p_idle_ttl interval,
    p_ip inet DEFAULT NULL, p_user_agent text DEFAULT NULL)
RETURNS TABLE (outcome text, user_id uuid, family_id uuid, session_id uuid, expires_at timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    c_max_family_lifetime constant interval := interval '30 days';
    v_user_id  uuid;
    v_id       uuid;
    v_family   uuid;
    v_status   text;
    v_expires  timestamptz;
    v_started  timestamptz;
    v_new_exp  timestamptz;
    v_new_id   uuid;
    v_revoked  integer;
BEGIN
    IF p_idle_ttl IS NULL OR p_idle_ttl < interval '1 minute' OR p_idle_ttl > c_max_family_lifetime THEN
        RAISE EXCEPTION 'secureai: refresh ttl out of range' USING ERRCODE = '22023';
    END IF;

    -- 1. Find the owner without locking, then take the per-user auth lock.
    SELECT s.user_id INTO v_user_id
    FROM secureai.refresh_token_sessions s WHERE s.token_hash = p_presented_hash;
    IF v_user_id IS NULL THEN
        PERFORM secureai_auth.audit('auth.refresh', 'failure', NULL, NULL, NULL,
                                    p_ip, p_user_agent, '{"reason": "unknown_token"}');
        outcome := 'invalid';
        RETURN NEXT;
        RETURN;
    END IF;
    PERFORM 1 FROM secureai.user_credentials c WHERE c.user_id = v_user_id FOR UPDATE;

    -- 2. Re-read AFTER the lock. Under READ COMMITTED this new statement sees
    --    whatever a concurrent rotation/reset committed while we waited.
    SELECT s.id, s.family_id, s.status, s.expires_at
      INTO v_id, v_family, v_status, v_expires
    FROM secureai.refresh_token_sessions s WHERE s.token_hash = p_presented_hash
    FOR UPDATE;

    user_id := v_user_id;
    family_id := v_family;

    IF v_status = 'rotated' THEN
        UPDATE secureai.refresh_token_sessions s
        SET status = 'revoked', revoked_reason = 'reuse_detected', revoked_at = now()
        WHERE s.family_id = v_family AND s.status = 'active';
        GET DIAGNOSTICS v_revoked = ROW_COUNT;
        PERFORM secureai_auth.audit('auth.refresh_reuse_detected', 'denied', v_user_id,
                                    'refresh_session', v_id, p_ip, p_user_agent,
                                    jsonb_build_object('family_id', v_family,
                                                       'sessions_revoked', v_revoked));
        outcome := 'reuse_detected';
        RETURN NEXT;
        RETURN;
    END IF;

    IF v_status = 'revoked' THEN
        PERFORM secureai_auth.audit('auth.refresh', 'denied', v_user_id, 'refresh_session', v_id,
                                    p_ip, p_user_agent, '{"reason": "revoked"}');
        outcome := 'revoked';
        RETURN NEXT;
        RETURN;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM secureai.users u WHERE u.id = v_user_id AND u.status = 'active') THEN
        UPDATE secureai.refresh_token_sessions s
        SET status = 'revoked', revoked_reason = 'account_disabled', revoked_at = now()
        WHERE s.family_id = v_family AND s.status = 'active';
        PERFORM secureai_auth.audit('auth.refresh', 'denied', v_user_id, 'refresh_session', v_id,
                                    p_ip, p_user_agent, '{"reason": "account_inactive"}');
        outcome := 'inactive';
        RETURN NEXT;
        RETURN;
    END IF;

    SELECT min(s.created_at) INTO v_started
    FROM secureai.refresh_token_sessions s WHERE s.family_id = v_family;
    v_new_exp := least(now() + p_idle_ttl, v_started + c_max_family_lifetime);

    IF v_expires <= now() OR v_new_exp <= now() THEN
        PERFORM secureai_auth.audit('auth.refresh', 'denied', v_user_id, 'refresh_session', v_id,
                                    p_ip, p_user_agent, '{"reason": "expired"}');
        outcome := 'expired';
        RETURN NEXT;
        RETURN;
    END IF;

    UPDATE secureai.refresh_token_sessions s
    SET status = 'rotated', rotated_at = now(), last_used_at = now()
    WHERE s.id = v_id;

    INSERT INTO secureai.refresh_token_sessions
        (user_id, family_id, parent_id, token_hash, expires_at, user_agent, ip_address)
    VALUES (v_user_id, v_family, v_id, p_new_hash, v_new_exp, left(p_user_agent, 512), p_ip)
    RETURNING id INTO v_new_id;

    outcome := 'ok';
    session_id := v_new_id;
    expires_at := v_new_exp;
    RETURN NEXT;
END $$;

-- Logout using only the refresh token (the access token may already have
-- expired). Revokes the whole family. Returns false for unknown tokens.
CREATE FUNCTION secureai_auth.revoke_refresh_session(
    p_presented_hash bytea, p_ip inet DEFAULT NULL, p_user_agent text DEFAULT NULL)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    v_user_id uuid;
    v_family  uuid;
    v_revoked integer;
BEGIN
    SELECT s.user_id, s.family_id INTO v_user_id, v_family
    FROM secureai.refresh_token_sessions s WHERE s.token_hash = p_presented_hash;
    IF v_user_id IS NULL THEN
        RETURN false;
    END IF;
    PERFORM 1 FROM secureai.user_credentials c WHERE c.user_id = v_user_id FOR UPDATE;

    UPDATE secureai.refresh_token_sessions s
    SET status = 'revoked', revoked_reason = 'logout', revoked_at = now()
    WHERE s.family_id = v_family AND s.status = 'active';
    GET DIAGNOSTICS v_revoked = ROW_COUNT;

    PERFORM secureai_auth.audit('auth.logout', 'success', v_user_id, 'refresh_family', v_family,
                                p_ip, p_user_agent, jsonb_build_object('sessions_revoked', v_revoked));
    RETURN true;
END $$;

-- ------------------------------------------------------------ password reset
-- Returns the user id when a reset email should be sent, otherwise NULL. The
-- API must respond identically in both cases.
--
-- Rules: active accounts only; at most 3 requests per user per hour (counted
-- from the audit log, which can't be edited); a new token invalidates all
-- earlier unused ones; TTL 5..60 minutes (the table CHECK caps it at 1 hour).
CREATE FUNCTION secureai_auth.request_password_reset(
    p_email text, p_token_hash bytea, p_ttl interval DEFAULT interval '30 minutes',
    p_ip inet DEFAULT NULL, p_user_agent text DEFAULT NULL)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    c_max_per_hour constant integer := 3;
    v_user_id uuid;
    v_status  text;
    v_recent  integer;
    v_token   uuid;
BEGIN
    IF p_ttl IS NULL OR p_ttl < interval '5 minutes' OR p_ttl > interval '1 hour' THEN
        RAISE EXCEPTION 'secureai: reset ttl out of range' USING ERRCODE = '22023';
    END IF;

    SELECT u.id, u.status INTO v_user_id, v_status
    FROM secureai.users u WHERE u.email = secureai_auth.normalize_email(p_email);

    IF v_user_id IS NULL THEN
        PERFORM secureai_auth.audit('auth.password_reset_requested', 'failure', NULL, NULL, NULL,
                                    p_ip, p_user_agent, '{"reason": "unknown_user"}');
        RETURN NULL;
    END IF;

    PERFORM 1 FROM secureai.user_credentials c WHERE c.user_id = v_user_id FOR UPDATE;

    IF v_status <> 'active' OR NOT FOUND THEN
        PERFORM secureai_auth.audit('auth.password_reset_requested', 'denied', v_user_id,
                                    'user', v_user_id, p_ip, p_user_agent,
                                    '{"reason": "account_inactive"}');
        RETURN NULL;
    END IF;

    SELECT count(*) INTO v_recent
    FROM secureai.audit_logs a
    WHERE a.actor_user_id = v_user_id
      AND a.action = 'auth.password_reset_requested'
      AND a.outcome = 'success'
      AND a.occurred_at > now() - interval '1 hour';
    IF v_recent >= c_max_per_hour THEN
        PERFORM secureai_auth.audit('auth.password_reset_requested', 'denied', v_user_id,
                                    'user', v_user_id, p_ip, p_user_agent,
                                    '{"reason": "rate_limited"}');
        RETURN NULL;
    END IF;

    DELETE FROM secureai.password_reset_tokens t
    WHERE t.user_id = v_user_id AND t.used_at IS NULL;

    INSERT INTO secureai.password_reset_tokens (user_id, token_hash, expires_at, requested_ip)
    VALUES (v_user_id, p_token_hash, now() + p_ttl, p_ip)
    RETURNING id INTO v_token;

    PERFORM secureai_auth.audit('auth.password_reset_requested', 'success', v_user_id,
                                'password_reset_token', v_token, p_ip, p_user_agent);
    RETURN v_user_id;
END $$;

-- Redeem a reset token: set the new hash, clear lockout, revoke EVERY refresh
-- session (an attacker who stole one is logged out too). Returns the user id
-- on success, otherwise NULL (invalid / used / expired / inactive).
CREATE FUNCTION secureai_auth.consume_password_reset(
    p_token_hash bytea, p_new_password_hash text,
    p_ip inet DEFAULT NULL, p_user_agent text DEFAULT NULL)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    v_token_id uuid;
    v_user_id  uuid;
    v_used     timestamptz;
    v_expires  timestamptz;
    v_reason   text;
    v_revoked  integer;
BEGIN
    IF p_new_password_hash IS NULL OR p_new_password_hash NOT LIKE '$argon2id$v=19$%' THEN
        RAISE EXCEPTION 'secureai: password hash must be argon2id' USING ERRCODE = '22023';
    END IF;

    SELECT t.id, t.user_id, t.used_at, t.expires_at INTO v_token_id, v_user_id, v_used, v_expires
    FROM secureai.password_reset_tokens t WHERE t.token_hash = p_token_hash
    FOR UPDATE;

    IF v_token_id IS NULL THEN
        PERFORM secureai_auth.audit('auth.password_reset', 'failure', NULL, NULL, NULL,
                                    p_ip, p_user_agent, '{"reason": "unknown_token"}');
        RETURN NULL;
    END IF;

    PERFORM 1 FROM secureai.user_credentials c WHERE c.user_id = v_user_id FOR UPDATE;

    v_reason := CASE
        WHEN v_used IS NOT NULL THEN 'token_used'
        WHEN v_expires <= now() THEN 'token_expired'
        WHEN NOT EXISTS (SELECT 1 FROM secureai.users u
                         WHERE u.id = v_user_id AND u.status = 'active') THEN 'account_inactive'
    END;
    IF v_reason IS NOT NULL THEN
        PERFORM secureai_auth.audit('auth.password_reset', 'denied', v_user_id,
                                    'password_reset_token', v_token_id, p_ip, p_user_agent,
                                    jsonb_build_object('reason', v_reason));
        RETURN NULL;
    END IF;

    UPDATE secureai.password_reset_tokens t SET used_at = now() WHERE t.id = v_token_id;
    DELETE FROM secureai.password_reset_tokens t
    WHERE t.user_id = v_user_id AND t.used_at IS NULL;

    UPDATE secureai.user_credentials c
    SET password_hash = p_new_password_hash, password_changed_at = now(),
        failed_login_count = 0, locked_until = NULL
    WHERE c.user_id = v_user_id;

    UPDATE secureai.refresh_token_sessions s
    SET status = 'revoked', revoked_reason = 'password_changed', revoked_at = now()
    WHERE s.user_id = v_user_id AND s.status = 'active';
    GET DIAGNOSTICS v_revoked = ROW_COUNT;

    PERFORM secureai_auth.audit('auth.password_reset', 'success', v_user_id,
                                'password_reset_token', v_token_id, p_ip, p_user_agent,
                                jsonb_build_object('sessions_revoked', v_revoked));
    RETURN v_user_id;
END $$;

-- ------------------------------------------------------------ password change
-- Authenticated: the user comes from the verified RLS context, never from a
-- parameter. The API must verify the CURRENT password first (begin_login +
-- argon2 verify + complete_login), so guesses here count toward lockout.
-- Revokes every other refresh family; p_keep_family_id keeps the caller's own.
CREATE FUNCTION secureai_auth.change_password(
    p_new_password_hash text, p_keep_family_id uuid DEFAULT NULL,
    p_ip inet DEFAULT NULL, p_user_agent text DEFAULT NULL)
RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    v_me      uuid := secureai_rls.current_user_id();
    v_revoked integer;
BEGIN
    IF v_me IS NULL THEN
        RAISE EXCEPTION 'secureai: user context is required' USING ERRCODE = '42501';
    END IF;
    IF p_new_password_hash IS NULL OR p_new_password_hash NOT LIKE '$argon2id$v=19$%' THEN
        RAISE EXCEPTION 'secureai: password hash must be argon2id' USING ERRCODE = '22023';
    END IF;

    UPDATE secureai.user_credentials c
    SET password_hash = p_new_password_hash, password_changed_at = now(),
        failed_login_count = 0, locked_until = NULL
    WHERE c.user_id = v_me;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'secureai: no credentials for user' USING ERRCODE = '42501';
    END IF;

    UPDATE secureai.refresh_token_sessions s
    SET status = 'revoked', revoked_reason = 'password_changed', revoked_at = now()
    WHERE s.user_id = v_me AND s.status = 'active'
      AND s.family_id IS DISTINCT FROM p_keep_family_id;
    GET DIAGNOSTICS v_revoked = ROW_COUNT;

    PERFORM secureai_auth.audit('auth.password_changed', 'success', v_me, 'user', v_me,
                                p_ip, p_user_agent, jsonb_build_object('sessions_revoked', v_revoked));
    RETURN v_revoked;
END $$;
"""

# Only the entry points are callable by the app; the internals (audit,
# normalize_email) are not.
PUBLIC_FUNCTIONS = [
    "begin_login(text, inet, text)",
    "complete_login(uuid, boolean, text, inet, text)",
    "create_refresh_session(uuid, bytea, interval, inet, text)",
    "rotate_refresh_session(bytea, bytea, interval, inet, text)",
    "revoke_refresh_session(bytea, inet, text)",
    "request_password_reset(text, bytea, interval, inet, text)",
    "consume_password_reset(bytea, text, inet, text)",
    "change_password(text, uuid, inet, text)",
]

FUNCTION_GRANTS_SQL = "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA secureai_auth FROM PUBLIC;\n" + "".join(
    f"GRANT EXECUTE ON FUNCTION secureai_auth.{f} TO secureai_app;\n" for f in PUBLIC_FUNCTIONS)


def upgrade() -> None:
    _run(PREFLIGHT_SQL)
    _run(PRIVILEGES_SQL)
    _run("SET LOCAL ROLE secureai_rls_definer")
    _run(RLS_HELPER_GRANTS_SQL)
    _run("SET LOCAL ROLE secureai_auth_definer")
    _run(FUNCTIONS_SQL)
    _run(FUNCTION_GRANTS_SQL)
    _run("SET LOCAL ROLE secureai_owner")


def downgrade() -> None:
    _run("SET LOCAL ROLE secureai_rls_definer")
    _run("REVOKE ALL ON FUNCTION secureai_rls.current_user_id(), secureai_rls.tx_stamp() "
         "FROM secureai_auth_definer")
    _run("SET LOCAL ROLE secureai_owner")
    _run("""
        DROP SCHEMA secureai_auth CASCADE;
        REVOKE ALL ON ALL TABLES IN SCHEMA secureai FROM secureai_auth_definer;
        REVOKE ALL ON SCHEMA secureai, secureai_rls FROM secureai_auth_definer;
    """)
