# SecureAI Workspace — Phase 2: Authentication

**Status:** step 1 of 3 done (DB auth layer + Python auth core). JWT and HTTP endpoints are next (§10).

Read [phase-1-database-architecture.md](phase-1-database-architecture.md) first. This phase builds on its roles, RLS context (`set_context`) and audit log.

| Piece | File |
|---|---|
| Definer role (fresh volumes) | [docker/postgres/init/00-bootstrap.sh](../docker/postgres/init/00-bootstrap.sh) |
| Definer role (existing volumes) | [docker/postgres/upgrades/0004_auth_definer_role.sh](../docker/postgres/upgrades/0004_auth_definer_role.sh) |
| Auth functions | [migrations/versions/0004_auth_functions.py](../migrations/versions/0004_auth_functions.py) |
| Argon2id + password policy | [app/auth/passwords.py](../app/auth/passwords.py) |
| Opaque tokens + HMAC | [app/auth/tokens.py](../app/auth/tokens.py) |
| Flows (login/refresh/logout/reset/change) | [app/auth/service.py](../app/auth/service.py) |
| Tests | [tests/db/test_auth_functions.py](../tests/db/test_auth_functions.py), [tests/auth/](../tests/auth/) |

## 1. Problem

Phase 1 authorizes everything through RLS keyed on `secureai_rls.current_user_id()`. Login, token refresh and password reset happen **before** an identity exists, so RLS can't authorize them. `user_credentials` and `password_reset_tokens` therefore have no app grants at all.

The two obvious ways out are both bad. Granting the app SELECT on `user_credentials` means one SQL injection dumps every hash. Running these flows as the migrator puts a BYPASSRLS credential inside the API. Instead, each pre-auth flow is one narrow `SECURITY DEFINER` function in a new `secureai_auth` schema.

## 2. Role: `secureai_auth_definer`

`NOLOGIN BYPASSRLS`, owns every function in `secureai_auth`, and holds only these column-level grants:

| Table | SELECT | INSERT / UPDATE / DELETE |
|---|---|---|
| `users` | `id, email, status` | — |
| `user_credentials` | `user_id, password_hash, failed_login_count, locked_until` | UPDATE same minus `user_id`, plus `password_changed_at` |
| `refresh_token_sessions` | `id, user_id, family_id, token_hash, status, created_at, expires_at` | INSERT new rows; UPDATE status/revocation columns |
| `password_reset_tokens` | `id, user_id, token_hash, created_at, expires_at, used_at` | INSERT; UPDATE `used_at`; DELETE |
| `audit_logs` | `actor_user_id, action, outcome, occurred_at` (rate-limit counting) | INSERT |

It has **no** access to tenant tables (tested). Why not reuse `secureai_rls_definer`? That role is read-only by design, because it is evaluated inside every RLS policy. Giving it write access to credentials would widen the blast radius of every policy helper.

The migrator is NOCREATEROLE, so a migration can't create the role. A superuser has to do it once, and migration 0004 fails early with instructions if it is missing.

## 3. Function catalogue

`secureai_app` may EXECUTE only these. The internal helpers `audit()` and `normalize_email()` are not callable (tested).

| Function | Purpose | Returns |
|---|---|---|
| `begin_login(email, ip, ua)` | Look up the user, **count the attempt**, return the hash | `outcome ∈ {ok, unknown, inactive, locked}`, `user_id`, `password_hash` (only for `ok`) |
| `complete_login(user_id, success, rehash, ip, ua)` | Success: reset counter and lockout, optionally store an upgraded hash. Failure: audit only | void |
| `create_refresh_session(user_id, token_hash, ttl, ip, ua)` | Start a token family after login | `session_id, family_id, expires_at` |
| `rotate_refresh_session(old_hash, new_hash, idle_ttl, ip, ua)` | Single-use exchange, reuse detection | `outcome ∈ {ok, invalid, reuse_detected, revoked, expired, inactive}` + new session |
| `revoke_refresh_session(hash, ip, ua)` | Logout with only the refresh token, revoking the whole family | boolean |
| `request_password_reset(email, token_hash, ttl, ip, ua)` | Store a reset-token hash | `user_id` if an email should be sent, else NULL |
| `consume_password_reset(token_hash, new_hash, ip, ua)` | One-time redeem: new hash, clear lockout, revoke **all** sessions | `user_id` or NULL |
| `change_password(new_hash, keep_family_id, ip, ua)` | Authenticated. The user comes from `current_user_id()`, **never** from a parameter | sessions revoked |

Every function writes its own audit rows (`auth.login`, `auth.refresh`, `auth.refresh_reuse_detected`, `auth.logout`, `auth.password_reset_requested`, `auth.password_reset`, `auth.password_changed`). The app therefore can't "forget" to audit an auth event. Attempted emails for unknown users are **not** logged, because users sometimes paste a password into the email field.

## 4. Concurrency: one lock per user

Every function that changes a user's auth state first runs `SELECT … FROM user_credentials WHERE user_id = $1 FOR UPDATE`. It then **re-reads** the session or token row in a new statement. Under READ COMMITTED, that fresh statement sees whatever a concurrent transaction committed while this one waited.

| Race | Without the lock | With it |
|---|---|---|
| Same refresh token sent twice (two tabs, or attacker vs. victim) | Both rotate and the family forks into two live tokens | Second caller sees `rotated` and gets `reuse_detected`; the whole family, including the winner's new token, is revoked. Tested with two real connections in `test_concurrent_rotation_of_same_token_cannot_fork_the_family` |
| Attacker replays old token A while victim rotates B | Revocation's snapshot misses the victim's just-inserted C, and C stays live | Serialized: C is either visible to the revocation or never created |
| Refresh racing a password reset | A new session minted after "revoke all" survives the reset | Reset holds the lock while revoking; the rotation then sees `revoked` |
| Parallel login attempts | Lost updates to `failed_login_count` | Counter is exact |

Argon2 verification happens **outside** any transaction, so no lock is held during the ~50 ms of hashing.

## 5. Flows

### 5.1 Login
```
tx1: begin_login(email)          -> counter += 1 (COMMITTED before verifying)
     outcome != ok               -> dummy argon2 verify (equal timing), InvalidCredentials
app: argon2.verify(hash, pw)     -> outside any transaction
tx2: complete_login(ok, rehash?) -> success resets counter; failure is audited
tx3: create_refresh_session      -> raw token to client, HMAC to DB
```
Counting **before** verification means a crashed or killed request still counts, so the lockout can't be dodged by aborting requests. The lock threshold is 5 attempts per 15 minutes. The 5th attempt sets `locked_until` pessimistically, and a correct password on that attempt clears it (tested). An expired lock starts a fresh window.

### 5.2 Refresh rotation
- Each token is **single-use**. Each rotation inserts a child row with `parent_id` set, so the family is a chain you can audit.
- Presenting an already-`rotated` token means it was stolen or replayed. The whole family is revoked and both attacker and victim must sign in again. This is the standard OAuth 2.0 Security BCP behaviour.
- Lifetime: a sliding `idle_ttl` (default 14 days), hard-capped at **30 days from the family's first login**. A stolen-and-refreshed token can't live forever.
- If the user is disabled, the next refresh fails and the family is revoked.

### 5.3 Password reset
- `request_password_reset` returns `user_id` or NULL. **The API must answer identically in both cases** and send the email asynchronously.
- Only active accounts get a token. Limit: 3 requests per user per hour, counted from the append-only audit log. A new token deletes earlier unused ones. TTL is 5–60 min; the table CHECK independently caps it at 1 h.
- Consuming a token sets the new hash, updates `password_changed_at`, clears the lockout and revokes **every** refresh session. If an attacker had a stolen session, the reset kicks them out.
- A bad new hash (non-argon2id) aborts the transaction **before** the token is spent, so the user can retry (tested).

### 5.4 Password change
The app verifies the *current* password through `begin_login`/`complete_login`, so guessing at the change endpoint counts toward lockout. `change_password` then takes the identity from the RLS context and revokes every other family except the caller's own.

## 6. Secrets handling

| Secret | Generated | Stored in DB | Why |
|---|---|---|---|
| Password | user | `argon2id`, m=64 MiB, t=3, p=4 (RFC 9106), NFKC-normalised input | Slow hash against offline cracking; parameters pinned so a library bump can't weaken them silently; `needs_rehash` upgrades old hashes at login |
| Refresh token `sart_…` | `secrets.token_urlsafe(32)` (256 bit) | `HMAC-SHA256(pepper, "refresh\0" ‖ token)` | 256-bit random needs no slow hash. The pepper lives outside the DB, so a dump alone can't be used to check or forge tokens |
| Reset token `sapr_…` | same | `HMAC-SHA256(pepper, "reset\0" ‖ token)` | Purpose prefix gives domain separation between the two token kinds |

The visible prefixes let secret scanners and log redaction recognise leaked tokens. Malformed tokens are rejected before any DB call. `TokenHasher.__repr__` redacts the pepper.

**Password policy** (NIST SP 800-63B): 12–256 characters, no composition rules. It rejects whitespace-only, highly repetitive, and "contains your email name" passwords. A breached-password check is still to come (§10).

## 7. Threat notes

- **Account enumeration.** Every failure is an `InvalidCredentials` / `InvalidRefreshToken` / `InvalidResetToken` subclass. The outcome string is for logs and metrics only; the HTTP layer must collapse each family to a single response. Unknown-user login runs a dummy Argon2 verify so timing matches.
- **Hash exposure (honest limit).** Argon2 isn't available in PostgreSQL, so the app has to see a hash to verify it. `begin_login` hands out one hash per call, counts the call toward lockout first, and audits it. An attacker with SQL injection gets about 5 hashes per account per 15 minutes and leaves a loud audit trail, not a bulk dump.
- **Compromised app process.** As in Phase 1 §3, it can already impersonate anyone through `set_context`. `complete_login(user, true)` and `create_refresh_session` don't widen that. What still holds: no reading of token hashes, no bulk hash dump, no back-dating or deleting audit rows.
- **Lockout as DoS.** Anyone who knows an email can lock that account for 15 minutes. Planned mitigation: per-IP and per-email rate limiting at the API edge, applied *before* `begin_login` (§10).

## 8. Testing

```bash
uv run pytest -v          # 273 passed (202 Phase 1 + 71 Phase 2)
```

| Area | Tests |
|---|---|
| Posture | definer role attributes and ownership; no tenant-table access; internal helpers not executable; no PUBLIC EXECUTE and pinned `search_path` across `secureai_auth` |
| Login | unknown user returns no hash and doesn't log the email; attempt counted before verify; case/whitespace normalisation; lockout after 5; correct 5th attempt; lock expiry; inactive states; disabled-mid-login fails closed; non-argon2 rehash rejected |
| Refresh | parent/child chain; reuse revokes the family; reuse leaves other devices alone; invalid/expired/revoked; 30-day cap; disabled user; TTL bounds; logout; **real two-connection race** |
| Reset | unknown/inactive return NULL; full flow (hash, lockout, all sessions); single use; supersession; expiry; rate limit; TTL bounds; bad hash leaves token usable |
| Change | requires RLS context; keeps only the current family; rolled back cleanly |
| Service (e2e) | login→refresh→logout; same error for wrong password and unknown email; lockout; transparent rehash; replay kills attacker and victim; reset and change flows; autocommit guard |
| Primitives | Argon2 params, NFKC, rehash detection, policy, token format, HMAC keying, pepper handling |

**Mutation checks run:** raising `c_max_failures` to 500 fails 2 lockout tests. Disabling the `rotated` branch fails 3 reuse/race tests.

## 9. Operations

Existing dev volume, once:
```bash
docker exec -i secureai-postgres bash < docker/postgres/upgrades/0004_auth_definer_role.sh
uv run alembic upgrade head
```
Add `SECUREAI_TOKEN_PEPPER` (`openssl rand -hex 32`) to `.env`. Rotating the pepper invalidates every outstanding refresh and reset token, which makes it a fast "log everyone out" switch.

## 10. Next steps

**Step 2: tokens and HTTP API**
1. Access tokens: short-lived JWT (10–15 min), pinned algorithm, required `iss/aud/exp/iat/sub/jti`, key from env with a `kid` for rotation.
2. FastAPI app: `/auth/login`, `/auth/refresh`, `/auth/logout`, `/auth/password-reset/request`, `/auth/password-reset/confirm`, `/auth/password/change`, `/me`.
3. Refresh token in an `HttpOnly; Secure; SameSite=Strict; Path=/auth` cookie; access token in the response body.
4. Request dependency: verify JWT, then `BEGIN; set_context(sub, X-Org-Id)` per request. Map "0 rows affected" to 404 (Phase 1 §8).
5. Uniform error responses, async email sender (console sink in dev), per-IP and per-email rate limiting in front of login and reset.

**Step 3: hardening**
6. Registration with email verification (needs an `email_verification_tokens` table plus definer functions) and enumeration-safe responses.
7. Breached-password check (HIBP k-anonymity range API, optional and fail-open in dev).
8. "≥1 active org_admin" trigger (Phase 1 residual risk).
9. API-level tests that fill the "Phase 2 adds" column of Phase 1 §8.2.
