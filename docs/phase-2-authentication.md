# SecureAI Workspace — Phase 2: Authentication

**Status:** ✅ complete (steps 1–3): DB auth layer, auth core, JWT + HTTP API, registration and hardening. Phase 3 (authorization APIs) is also complete: [phase-3-authorization-apis.md](phase-3-authorization-apis.md).

Read [phase-1-database-architecture.md](phase-1-database-architecture.md) first. This phase builds on its roles, RLS context (`set_context`) and audit log.

| Piece | File |
|---|---|
| Definer role (fresh volumes) | [docker/postgres/init/00-bootstrap.sh](../docker/postgres/init/00-bootstrap.sh) |
| Definer role (existing volumes) | [docker/postgres/upgrades/0004_auth_definer_role.sh](../docker/postgres/upgrades/0004_auth_definer_role.sh) |
| Auth functions | [migrations/versions/0004_auth_functions.py](../migrations/versions/0004_auth_functions.py) |
| Registration, request ids, last-admin guard | [migrations/versions/0005_registration_hardening.py](../migrations/versions/0005_registration_hardening.py) |
| Breached-password check | [app/auth/breach.py](../app/auth/breach.py) |
| Argon2id + password policy | [app/auth/passwords.py](../app/auth/passwords.py) |
| Opaque tokens + HMAC | [app/auth/tokens.py](../app/auth/tokens.py) |
| Flows (login/refresh/logout/reset/change) | [app/auth/service.py](../app/auth/service.py) |
| Access tokens (JWT) | [app/auth/jwt_tokens.py](../app/auth/jwt_tokens.py) |
| Settings (fail-fast env parsing) | [app/config.py](../app/config.py) |
| HTTP API | [app/api/](../app/api/): `main.py`, `deps.py`, `routes_auth.py`, `routes_me.py`, `ratelimit.py`, `email.py` |
| Tests | [tests/db/test_auth_functions.py](../tests/db/test_auth_functions.py), [tests/auth/](../tests/auth/), [tests/api/](../tests/api/) |

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
uv run pytest -v          # 339 passed (202 Phase 1 + 137 Phase 2)
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

**Mutation checks run:** raising `c_max_failures` to 500 fails 2 lockout tests. Disabling the `rotated` branch fails 3 reuse/race tests. Disabling the CSRF-header check fails 2 API tests. Ignoring `X-Org-Id` fails 2 API tests. Disabling the last-admin count fails both race tests. Skipping the breach check fails the breach API test.

## 9. Operations

Existing dev volume, once:
```bash
docker exec -i secureai-postgres bash < docker/postgres/upgrades/0004_auth_definer_role.sh
uv run alembic upgrade head
```
Add `SECUREAI_TOKEN_PEPPER` and `SECUREAI_JWT_KEYS` (see `.env.example`) to `.env`, then run:
```bash
uv run uvicorn app.api.main:create_app --factory --port 8000   # docs at /docs (dev only)
``` Rotating the pepper invalidates every outstanding refresh and reset token, which makes it a fast "log everyone out" switch.

## 10. HTTP API (step 2)

| Endpoint | Auth | Success | Failure (always generic) |
|---|---|---|---|
| `POST /auth/login` | — | 200 `{access_token, expires_in}` + refresh cookie | 401 `Invalid email or password` (unknown, wrong, locked and disabled all look the same) |
| `POST /auth/refresh` | cookie + `X-SecureAI-CSRF: 1` | 200 new access token + rotated cookie | 401, cookie cleared |
| `POST /auth/logout` | cookie + CSRF header | 204, family revoked, cookie cleared | — (idempotent) |
| `POST /auth/password-reset/request` | — | **always** 202, same body | — |
| `POST /auth/password-reset/confirm` | reset token | 204, all sessions revoked | 400 invalid/expired, 422 policy |
| `POST /auth/password/change` | Bearer | 204, other devices logged out | 403 wrong current password, 422 policy |
| `GET /me` (+ optional `X-Org-Id`) | Bearer | profile, orgs, and in org context the **live** role and permissions | 401 / 403 `No access to this organization` |

**Access token.** HS256 JWT, 10 min. Header `typ: at+jwt` and a `kid` from a keyset (the first key signs, all verify), so keys rotate without logging anyone out. The algorithm is pinned on decode. Required claims are `iss aud sub sid iat nbf exp jti`. The token carries **no roles or permissions**: authorization is evaluated live in PostgreSQL on every request, so a revocation applies to the very next request even with the same JWT (tested). `sid` is the refresh family, which lets password change keep the current device.

**Request pipeline.** `Bearer` → `codec.verify` → `pool.connection()` → `BEGIN` → `set_context(sub, X-Org-Id)` → handler → `COMMIT`. The org header is untrusted input: the DB rejects a foreign or inactive org with 403. The dependency uses `scope="function"`, so COMMIT happens **before** the response is sent. A disabled user's still-valid JWT fails at `set_context` (401).

**Refresh token transport.** `__Secure-secureai_refresh` cookie with `HttpOnly; Secure; SameSite=Strict; Path=/auth`. It never appears in a response body, so XSS can't read it. Cookie-authenticated endpoints also require `X-SecureAI-CSRF: 1`, which a cross-site request can't set without a CORS preflight that this API never approves.

**Password reset.** The DB call and the email both run in a background task after the 202 is sent, so latency doesn't reveal whether the account exists. The link carries the token in the URL **fragment** (`/reset-password#token=…`), so it never reaches server logs, proxies or `Referer`.

**Edge hardening.** Per-IP and per-email fixed-window rate limits return 429 with `Retry-After`. The limiter is **in-process**, so multiple workers need Redis behind the same interface. The client IP is the validated direct peer only; `X-Forwarded-For` is never parsed (use uvicorn `--forwarded-allow-ips` behind a trusted proxy). Request models forbid extra fields. Every response gets `no-store`, `nosniff`, `DENY`, `no-referrer` and a `default-src 'none'` CSP. Unhandled errors return a bare 500 with no SQL or stack trace. `/docs` and `/openapi.json` are disabled in production.

## 11. Registration and hardening (step 3)

**Registration without a password (pre-account-takeover defence).**

| Step | Endpoint | DB function | Result |
|---|---|---|---|
| 1 | `POST /auth/register {email, display_name}` | `register_user` | `pending` user, **no credentials row**, 24 h verification token. Always 202 with the same body |
| 2 | `POST /auth/verify-email {token, password}` | `verify_email_and_set_password` | Password set **and** account activated in one transaction. 204, then the user signs in |

If registration accepted a password, an attacker could register `victim@corp` with a password they know. The account would sit pending until the victim registered or clicked a link, then go live with the attacker's password. Here, only the holder of the inbox ever chooses a password. Re-registering a pending address deletes earlier tokens, so a link the attacker obtained dies (tested in `test_pre_account_takeover_is_impossible`).

Every registration outcome looks the same to the client. The DB work and the email run after the 202 is sent:

| Outcome | Email sent |
|---|---|
| `created` / `resent` | verification link (`/verify-email#token=save_…`, fragment as in §10) |
| `exists` (active account) | "you already have an account, reset your password here", sent to the **owner**, never shown to the requester |
| `suppressed` (disabled/locked, or a concurrent duplicate) / `rate_limited` (>3 per address per hour) | none |

The new `email_verification_tokens` table has the same posture as reset tokens: RLS forced, no policies, no app grants, hash only, CHECK caps the TTL at 24 h. The posture test that flags unclassified tables caught it until it was registered.

**Breached passwords.** Every path that sets a password (verify, reset, change) runs the policy check and then `BreachChecker`. `HibpChecker` uses the Have I Been Pwned range API with k-anonymity (only 5 hex characters of SHA-1 leave the server) and `Add-Padding`. Padded zero-count rows are ignored. It **fails open** with a warning when the API is unavailable. `SECUREAI_BREACH_CHECK=hibp|off` defaults to `hibp` in production and `off` elsewhere, so dev and tests never call out.

**Last-admin invariant (Phase 1 residual risk, now closed).** Sequentially, an org can't lose its last admin: RLS forbids self-edits, and the first demotion strips the second actor's rights. The real hole was **concurrency**. Two admins demoting or suspending each other in parallel both pass RLS. `AFTER UPDATE OF role_id, status OR DELETE` trigger `organization_memberships_last_admin`:
1. Ignores rows that weren't, or still are, an active admin. "Admin" means the role grants `user.update`, a permission, not a role name.
2. Takes `pg_advisory_xact_lock` on the org.
3. Re-counts in a new statement, which under READ COMMITTED sees the other transaction's commit. If the count is zero, it raises `42501`.

The counting helper `secureai_rls.active_admin_count` answers only for the current org, so it can't be used as a cross-tenant oracle. Trusted maintenance roles (BYPASSRLS) are exempt so ops can repair data. Tested with real parallel transactions for both demote and suspend.

**Request correlation.** Middleware assigns a server-generated `X-Request-ID` to every response; a client-supplied one is ignored. Each auth transaction runs `set_config('secureai.request_id', …, true)`, and `secureai_auth.audit()` stamps it into `audit_logs.request_id`. One HTTP request can therefore be traced to every audit row it caused.

**Security alert.** Refresh-token reuse logs `security_alert refresh_token_reuse` with structured `event`, `user_id`, `request_id` and `ip` fields, ready for a log-based alert rule.

**Deliberately deferred:**
- *Shared rate-limit store (Redis).* The limiter interface is ready, but adding Redis is an infrastructure choice (compose service, HA, auth) better made alongside deployment. Until then, run one worker or accept per-process limits.
- *CAPTCHA/proof-of-work after the lockout threshold.* This needs a frontend to present the challenge.
- *Cleanup of stale pending users.* A scheduled job to delete `pending` users older than N days with no live token. Phase 3 invites create pending users too (phase-3 doc §8.2), so the job must skip those that still hold an `invited` membership.

## 12. Next steps — Phase 3: authorization APIs

1. Resource endpoints on top of `RlsConn`: organizations (read/update), members (invite/role change/remove, exercising the rank rules and the last-admin trigger), projects, project members, tasks, documents metadata.
2. A `rows_or_404` helper: RLS-filtered UPDATE/DELETE that affects 0 rows becomes 404, never 403, so the API doesn't confirm that a row exists.
3. Map DB errors (`42501` from triggers and WITH CHECK, `23503` FK) to 403/404/409 without leaking constraint names.
4. Pagination with keyset cursors (no OFFSET scans over RLS-filtered sets).
5. API tests that fill the "Phase 2 adds" column of Phase 1 §8.2, covering IDOR, cross-tenant ids, mass assignment (`extra="forbid"`) and privilege escalation via role changes.
