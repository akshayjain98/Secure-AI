# SecureAI Workspace — Phase 3: Authorization APIs

**Status:** ✅ complete. Step 1: shared building blocks, projects, project members, tasks. Step 2: organization, members, invitations, permission overrides (§8). Step 3: document metadata, the write-audit trail and the audit-log API (§9). Next phase: §10.

Read [phase-1-database-architecture.md](phase-1-database-architecture.md) §5–§6 first. This phase adds **no authorization logic in Python**. The handlers issue plain SQL inside an RLS-bound transaction, and Phase 1's policies and triggers decide. The API layer has three jobs:

1. Bind the verified identity and the requested org to the transaction (`set_context`).
2. Refuse input that should never reach SQL (unknown fields, bad types, oversized strings).
3. Turn the database's answer into the right HTTP status **without leaking anything**.

| Piece | File |
|---|---|
| Org-scoped transaction (`OrgConn`) | [app/api/deps.py](../app/api/deps.py) |
| DB error → HTTP mapping | [app/api/errors.py](../app/api/errors.py) |
| 404-versus-403 helpers | [app/api/rows.py](../app/api/rows.py) |
| Keyset pagination | [app/api/pagination.py](../app/api/pagination.py) |
| Strict request models | [app/api/models.py](../app/api/models.py) |
| Projects + project members | [app/api/routes_projects.py](../app/api/routes_projects.py) |
| Tasks | [app/api/routes_tasks.py](../app/api/routes_tasks.py) |
| Organization, members, overrides | [app/api/routes_org.py](../app/api/routes_org.py) |
| Invitations (invitee side) | [app/api/routes_me.py](../app/api/routes_me.py) |
| Invite resolver, consent rule, logout on removal | [migrations/versions/0006_org_membership_admin.py](../migrations/versions/0006_org_membership_admin.py) |
| Documents (metadata) | [app/api/routes_documents.py](../app/api/routes_documents.py) |
| Audit-log API | [app/api/routes_audit.py](../app/api/routes_audit.py) |
| Write-audit triggers | [migrations/versions/0007_write_audit_trail.py](../migrations/versions/0007_write_audit_trail.py) |
| Tests | [tests/api/test_projects_api.py](../tests/api/test_projects_api.py), [tests/api/test_tasks_api.py](../tests/api/test_tasks_api.py), [tests/api/test_org_members_api.py](../tests/api/test_org_members_api.py), [tests/db/test_membership_admin.py](../tests/db/test_membership_admin.py), [tests/api/test_documents_audit_api.py](../tests/api/test_documents_audit_api.py), [tests/db/test_audit_triggers.py](../tests/db/test_audit_triggers.py) |

## 1. Endpoints (step 1)

All require `Authorization: Bearer <access token>`.

| Method | Path | DB rule that decides |
|---|---|---|
| GET | `/orgs/{org}/projects?status=&cursor=&limit=` | `projects_select` |
| POST | `/orgs/{org}/projects` | `projects_insert`: `project.create` ∧ owner = me |
| GET / PATCH / DELETE | `/orgs/{org}/projects/{id}` | select / `projects_update` (manager) / `projects_delete` (owner, RESTRICT FKs) |
| GET / POST | `/orgs/{org}/projects/{id}/members` | `project_members_select` / `_insert` |
| PATCH / DELETE | `/orgs/{org}/projects/{id}/members/{user}` | `_update` (manager, not self) / `_delete` (manager or self) |
| GET | `/orgs/{org}/tasks?project_id=&status=&assigned_to_me=&cursor=&limit=` | `tasks_select` |
| POST | `/orgs/{org}/projects/{id}/tasks` | `tasks_insert`: participant ∧ owner = me ∧ assignee participates |
| GET / PATCH / DELETE | `/orgs/{org}/tasks/{id}` | select / `tasks_update` + `tasks_enforce_update_rules` / `tasks_delete` |

## 2. The org lives in the path, and is verified, not trusted

`/orgs/{org_id}/...` is the tenant selector. The `OrgConn` dependency passes the path value to `secureai_rls.set_context(user_from_jwt, org_id)`, which checks on every request that the user, the membership and the org are all active.

- Another tenant's org, a random uuid and a suspended membership all get the **same** `403 No access to this organization`, so the response can't tell an attacker which org ids exist.
- Request bodies never carry `organization_id` or `owner_id`. INSERTs take them from `secureai_rls.current_org_id()` / `current_user_id()` in SQL.
- `/me` keeps the optional `X-Org-Id` header, because it also works with no org selected.

**Why the path and not the header:** a path is part of the resource identity. It shows up in logs, it can't be lost by a proxy that strips custom headers, and a single URL can't name one org in the path and another in a header.

## 3. 404 versus 403

Under RLS, "hidden" and "doesn't exist" look identical. SELECT returns nothing, and UPDATE/DELETE affect **0 rows without an error**. [rows.py](../app/api/rows.py) turns that into:

| Situation | Answer | Why |
|---|---|---|
| Row not visible to the caller (another user's private task, another tenant's id, nonexistent) | **404** `<Thing> not found` | Never confirm that a hidden id exists (IDOR / enumeration). |
| Row visible, but the write affected 0 rows | **403** `Not allowed` | The caller can already read it, so this reveals nothing. A 404 for something on screen would just be confusing. |
| WITH CHECK refusal on INSERT/UPDATE (raises 42501) | **403** `Not allowed` | e.g. creating a task in a project you can see but don't participate in. |
| Our own trigger rule (`secureai: ...`) | **403** with the rule text | Written for humans, e.g. "Only the task owner may change task visibility". |

The visibility probe after a 0-row write runs in the same transaction and RLS context, so it answers exactly the caller's question.

Parent resources are checked first. `POST /projects/{id}/tasks` and `/projects/{id}/members` return 404 when the project is hidden, before any write is tried. Without that, a WITH CHECK 403 would confirm that a hidden project exists.

> This refines the Phase 2 hand-off note ("0 rows → 404, never 403"). "Never 403" is only required for rows the caller can't see.

## 4. Database errors never reach the client verbatim

[errors.py](../app/api/errors.py) maps SQLSTATEs to short generic messages. Raw PostgreSQL messages name tables, policies and constraints, which is free reconnaissance for an attacker. `new row violates row-level security policy for table "tasks"` becomes `Not allowed`.

| SQLSTATE | HTTP |
|---|---|
| 42501 (WITH CHECK, grants, our triggers) | 403; last-admin trigger → 409 |
| 23503 (FK) | 409, or endpoint-specific (project still has tasks → 409 "archive it instead"; member not in org → 422) |
| 23505 (unique) | 409 |
| 23514 / 23502 / 22xxx | 422 |

A `permission denied` (column-grant refusal) is also logged as a warning. The request models should make it unreachable, so seeing one means a code bug.

**Known, accepted leak:** FK checks don't apply RLS. When an owner deletes a project, a 409 means *something* still references it, even if every referencing task is private to someone else. The owner learns that a reference exists, not what it is.

## 5. Mass assignment: strict request models

Every request model extends `StrictModel` (`extra="forbid"`). Sending `owner_id`, `organization_id`, `project_id`, `id`, `created_at` or `added_by` is a **422**, not silently ignored. Column grants would refuse most of these anyway, but the explicit refusal can be tested, and it surfaces client bugs.

PATCH models type non-nullable fields without `| None` but default them to `None`. Pydantic doesn't validate defaults, so an omitted field is skipped (`exclude_unset`), while an explicit `null` for `title`/`name`/`status` is a 422. Nullable columns (`description`, `due_date`, `assignee_id`) accept `null` to clear them. An empty PATCH is a 422. The SET clause is built with `psycopg.sql.Identifier` from the model's own field names, so the client never supplies SQL.

## 6. Keyset pagination

`ORDER BY created_at DESC, id DESC` and resume with `WHERE (created_at, id) < (cursor)`. OFFSET would make PostgreSQL produce, policy-check and discard every skipped row, so deep pages would get linearly slower, and slower again under RLS. `limit` is 1–100 (default 50).

The cursor is opaque base64url but **not** signed, because it isn't a security boundary. It only positions the scan, and every row is still RLS-filtered. `test_forged_cursor_cannot_widen_the_result` checks this. A malformed cursor is a 422.

## 7. Testing

```bash
uv run pytest tests/api -v
```

- **Fast auth in tests:** access tokens are stateless, so `auth_as("priya")` mints one with the app's own codec instead of paying for Argon2 per test. Login itself is covered in `test_auth_api.py`.
- **Isolation:** API writes commit, as in production. An autouse fixture deletes every non-seed project, task and project-member row after each test, so the exact-set assertions in `tests/db` always see pristine seed data.

| Brief item | API test |
|---|---|
| 1 Unauthenticated | `test_unauthenticated_is_401` |
| 4 Private tasks | `test_task_list_is_exactly_the_rls_set`, `test_private_task_idor_is_404_for_read_update_and_delete` (manager, org admin, viewer) |
| 5 Org isolation | `test_meera_sees_each_org_only_in_its_own_context`, `test_cross_tenant_task_and_project_ids_are_404` |
| 7 Org id tampering | `test_foreign_and_nonexistent_orgs_get_the_same_403`, mass-assignment tests (`organization_id` in body) |
| 9 Unauthorized UPDATE/DELETE | `test_update_is_403_when_visible_and_404_when_hidden`, `test_delete_rules`, `test_assignee_can_progress_but_not_publish_or_reassign` |
| 12 Omitted app filters | handlers have no owner/org WHERE clauses; list tests assert exact RLS sets |
| 14 Revocation | `test_permission_revocation_applies_to_the_next_request` |

**Mutation checks** (each broken safeguard must fail at least one test; the source was restored afterwards):

| Mutation | Failing tests |
|---|---|
| Hidden rows answer 403 instead of 404 | 5 |
| Raw DB message returned for 42501 | 4 |
| `extra="ignore"` instead of `"forbid"` | 10 |
| Cursor ignored | 1 |
| Path org ignored (`set_context(user, NULL)`) | 18 |
| Task owner hard-coded instead of `current_user_id()` | 2 |

## 8. Step 2: organization, members, invitations, overrides

### 8.1 Endpoints

| Method | Path | DB rule that decides |
|---|---|---|
| GET | `/orgs/{org}` | `organizations_select_member` (any active member) |
| PATCH | `/orgs/{org}` | `organizations_update_admin`: `organization.update`; `name` only (column grant) |
| GET | `/orgs/{org}/members?status=&cursor=&limit=` | `memberships_select`: own row ∨ `user.read` |
| GET | `/orgs/{org}/members/{user}` | same |
| POST | `/orgs/{org}/members` `{email, role}` | `resolve_invitee()` (`user.create`), then `memberships_insert` |
| PATCH | `/orgs/{org}/members/{user}` `{role?, status?: active\|suspended}` | `memberships_update` (`user.update`, rank, not self) + transition trigger + last-admin trigger |
| DELETE | `/orgs/{org}/members/{user}` | `memberships_update` with `status='removed'` (+ `user.delete`) |
| GET | `/orgs/{org}/members/{user}/overrides` | `overrides_select`: own ∨ `permission.manage` |
| PUT / DELETE | `/orgs/{org}/members/{user}/overrides/{permission}` | `overrides_insert/update/delete` |
| GET | `/me/invitations` | `secureai_auth.my_invitations()` |
| POST | `/me/invitations/{org}/accept` · `/decline` | `secureai_auth.respond_to_invitation()` |

`DELETE /members/{user}` doesn't delete the row. It sets `removed`. The membership row anchors the member's tasks, projects and documents (composite FKs), and the app role has no DELETE grant on memberships.

### 8.2 Inviting by email without an email-lookup oracle

RLS hides every user outside the current org, so the API can't run `SELECT id FROM users WHERE email = …` for an invitee. That's correct, and it shouldn't be loosened. `secureai_auth.resolve_invitee(email)` is the narrow exception:

- It runs only for a caller holding `user.create` **in the context org** (otherwise 42501, shown as 403 "Not allowed to invite members").
- It returns the user id for the address. When there's no account, it creates a **pending, passwordless** identity. The address owner later sets the password through the normal register → verify flow (Phase 2), so the inviter never controls credentials (no pre-account takeover). The display name is the email's local part, not inviter-supplied text.
- It only resolves the identity. The membership row is still INSERTed by the app **under RLS**, so `memberships_insert` keeps deciding role assignability and rank. If RLS refuses (e.g. `role: super_admin`), the pending identity is rolled back with the transaction (`test_refused_invite_rolls_back_the_pending_identity`).

**No account enumeration.** An existing and an unknown address get the same status code and the same body. While a membership is `invited`, `display_name` is withheld (`null`). Otherwise an existing account would show its real name and a new one its email local part. Re-inviting a current member is a 409, but that only says something about the caller's own org, which they can already list.

**Accepted risk.** Each invite of an unknown address creates a `pending` user row. Invites are rate-limited per inviter (30/hour, in-process limiter, §Phase 2 caveat), and stale pending users join the cleanup job already deferred in Phase 2.

### 8.3 Consent: only the invitee activates a membership

Phase 1's `memberships_insert` accepted `status IN ('invited','active')`, and `memberships_update` let an admin set any status. Together that meant an admin could put any user into their org as `active` without asking: the user would suddenly see the org in `/me`, which is a phishing vector. Migration 0006 closes that:

- `memberships_insert` now requires `status = 'invited'`.
- An `AFTER UPDATE OF status` trigger allows only these transitions for the app role: `active ↔ suspended`, `{invited, active, suspended} → removed`, `removed → invited`. Anything else, notably `invited/removed → active`, raises 42501 and is shown as 403 *"Membership status cannot change from invited to active"*.
- The invitee accepts or declines through `respond_to_invitation(org, accept)`, which updates only `WHERE user_id = current_user_id() AND status = 'invited'`. It runs as `secureai_auth_definer` (BYPASSRLS), which the trigger treats as a trusted path. The invitee needs a definer function because, before accepting, they have no org context and the tenant fence hides the row from them.

The accept link in the email carries **no token**. Accepting requires signing in as the invited address, so a forwarded or leaked email grants nothing.

### 8.4 Rank, self-edit and last-admin

These are all Phase 1 rules. The API only maps the outcome:

| Attempt | Result |
|---|---|
| Change a member without `user.update` (manager, employee) | 403: the row is visible, the update affects 0 rows |
| Change a member who outranks me, or assign a role above mine / `super_admin` | 403 |
| Change or remove my own membership | 403 (`user_id <> me` in USING) |
| Viewer (no `user.read`) touches someone else | 404: the row is hidden |
| Two admins demote/remove each other concurrently | the second gets **409** "An organization must keep at least one active administrator" |

Sequentially, the last-admin 409 can't be reached through the API at all. Self-edits are refused, and the first demotion strips the second actor's rights. `test_racing_admins_cannot_leave_zero_admins` reproduces the race deterministically. A side transaction (Rahul demotes Akshay) holds the per-org advisory lock. The API request (Akshay demotes or removes Rahul) is started in a thread, the test waits until `pg_locks` shows it blocked, then commits the side transaction.

Role changes take effect on the next request (`test_admin_changes_role_and_it_applies_on_the_next_request`), because access tokens carry no roles.

### 8.5 Logout on removal

When an `active` membership becomes `suspended` or `removed`, the trigger `organization_memberships_revoke_sessions` revokes every active refresh session of that user (`revoked_reason = 'membership_revoked'`) and writes an `auth.sessions_revoked` audit row. It's a trigger, not an API step, so no code path (API, ops script, future endpoint) can forget it, and it commits or rolls back with the status change.

- **Org access** ends on the member's **next request**, independently of this. `set_context()` requires an active membership, and access tokens carry no roles.
- **Sessions** are per user, not per org. So removal from one org signs the user out of all orgs, and they log in again to keep using the others. That's the conservative choice: a suspended person's devices stop refreshing.
- The access token itself stays cryptographically valid until it expires (≤10 min, Phase 2 design). It's useless for the removed org, but still works for other orgs until expiry.
- The trigger function locks the user's `user_credentials` row first, like every Phase 2 auth function. Without it, a concurrent refresh could insert a new session after the revoking UPDATE took its snapshot, and that session would survive.
- Role changes don't revoke sessions (`test_role_change_keeps_sessions_and_reinstatement_works`), because permissions are evaluated live.

### 8.6 Permission overrides

`PUT …/overrides/{permission}` `{effect: grant|deny, reason, expires_at?}` creates or replaces (`INSERT … ON CONFLICT DO UPDATE`). Both the insert and the update path are checked by RLS:

- `permission.manage`, never on yourself, and the target can't outrank you.
- **You can't delegate what you don't hold.** A `grant` requires the caller to *effectively* hold the permission, after their own overrides. Turning an existing deny into a grant is the same delegation and is refused too. A `deny` is always allowed (for lower or equal ranks).
- `expires_at` must be timezone-aware and in the future (422). After expiry, the override stays listed with `active: false` and is ignored by `has_permission`.
- Overrides take effect on the caller's **next request** (`test_grant_and_deny_take_effect_on_the_next_request`).
- Without `permission.manage`, the override list is empty for anyone but yourself. That's RLS answering, not a 403, because the member row itself is visible.
- Unknown permission codes are 404 (the catalogue is public reference data). Malformed codes are 422.

### 8.7 Tests and mutation checks

[tests/api/test_org_members_api.py](../tests/api/test_org_members_api.py) (44 tests) and [tests/db/test_membership_admin.py](../tests/db/test_membership_admin.py) (25 tests). The DB tests exist because the API always sends `invited`: a regression in the insert policy or the transition trigger wouldn't show through the API. The API cleanup fixture restores seed memberships, roles and org names, and deletes all overrides.

| Mutation | Failing tests |
|---|---|
| `display_name` shown while invited | 2 |
| No savepoint around the invite INSERT (re-invite after decline) | 2 |
| `resolve_invitee` skips the `user.create` check | 4 |
| Insert policy allows `active` again | 1 |
| Transition trigger allows `invited → active` | 2 |
| `respond_to_invitation` ignores who the invitee is | 2 |
| Session-revocation trigger never fires | 5 |
| Override PUT skips the visible-member check | 1 |

## 9. Step 3: documents and the audit trail

### 9.1 Endpoints

| Method | Path | DB rule that decides |
|---|---|---|
| GET | `/orgs/{org}/documents?project_id=&visibility=&mine=&cursor=&limit=` | `documents_select` |
| POST | `/orgs/{org}/documents` | `documents_insert`: `document.upload` ∧ owner = me ∧ (no project ∨ I participate) |
| GET / PATCH / DELETE | `/orgs/{org}/documents/{id}` | select / `documents_update` (owner) / `documents_delete` (owner) |
| GET | `/orgs/{org}/audit-logs?action=&actor_id=&resource_type=&resource_id=&outcome=&cursor=&limit=` | `audit_logs_select`: context org ∧ `audit.read` |

### 9.2 Documents: metadata only

File bytes and object storage are a later phase. This step manages the metadata row.

- **`storage_key` is generated by the database** (`org/<org id>/<random uuid>`) and is never accepted from or returned to the client. Sending it is a 422 (`extra="forbid"`). Once real storage exists, a client-chosen key would be a path-traversal or object-overwrite primitive.
- **`size_bytes` and `sha256` are the client's declaration.** The storage phase must verify them against the uploaded bytes before a document is ever served.
- **Admins get no exception.** An org admin can't read, edit or delete a member's private document (404), and can't edit or delete one they *can* see (403). Only the owner writes.
- **Parent first, as in step 1.** A hidden or nonexistent `project_id` on create/PATCH is a 404 before any write. A project the caller can see but doesn't participate in (an admin via `project.read_all`) is a 403 from WITH CHECK.
- `visibility: project` without a project is the table's CHECK constraint, answered as 422. A project that still has documents can't be deleted (409, FK RESTRICT).

### 9.3 Every write is audited by the database

Migration 0007 puts an `AFTER INSERT/UPDATE/DELETE` row trigger, `secureai.audit_row_change()`, on every table the API writes: organizations, memberships, overrides, projects, project members, tasks and documents. Doing this in the database rather than in handlers means:

- **Nothing can forget it.** A new endpoint, a refactor or ad-hoc SQL as the app role is audited the same way. `test_every_tenant_write_table_is_audited` fails when a new tenant table has no trigger.
- **The log never claims a change that didn't happen.** The row is written in the same transaction, so a refused or failed write rolls back with its audit row (`test_refused_writes_leave_no_audit_row`).
- **The actor is the verified identity** (`current_user_id()`), never a request field. The trigger is SECURITY INVOKER, so its insert still passes the `audit_logs_insert` policy (current org, actor = me).
- **Correlation.** The API sets `secureai.request_id`, `secureai.client_ip` and `secureai.user_agent` transaction-locally in `OrgConn`. Every audit row carries the same request id as the response's `X-Request-ID` header.
- **The app can't switch it off.** Disabling or dropping triggers needs table ownership, and `session_replication_role` needs superuser (`test_app_cannot_switch_auditing_off`).

Rows look like `action = task.update`, `resource_type = task`, `resource_id = <task id>`, `metadata = {"changed": ["description", "status"], "values": {"status": {"old": "todo", "new": "done"}}}`. A no-op UPDATE writes nothing.

**Confidentiality: audit.read must not become a back door.** Admins hold `audit.read` but can't read private tasks or documents. If the log copied row contents, they could read them there. The metadata therefore names *which* columns changed, and copies values only for a per-table allow-list of non-content fields (status, role, visibility, assignee, project, effect, …). Titles, names, descriptions and override reasons never enter the log (`test_private_content_never_enters_the_audit_log`).

**Not audited by the trigger:**
- Trusted maintenance roles (BYPASSRLS: migrator, the definer roles). Ops changes would otherwise be logged with no actor. The definer functions write their own, more specific rows (`member.invitation_accepted`, `auth.sessions_revoked`, `member.invitee_created`, all `auth.*` events).
- Conversations and messages: personal chat content, covered in the AI phase.
- **Refused attempts** (`outcome = denied`). Their transaction rolls back, so recording them needs a second transaction after the response is decided. That's deferred (§10). Detecting IDOR probing from the audit log needs it.

### 9.4 Reading the audit log

- RLS returns only the context org's rows, and only to holders of `audit.read`. Org-less auth events (logins, resets) are never listed. Rows from another tenant are invisible even with a correct `resource_id`.
- A caller without `audit.read` gets **403**, not an empty page. That status comes from a `has_permission()` probe, used only to choose the status code. RLS still filters every row, so removing the probe can't leak anything; it would only turn the 403 into an empty page.
- `action=task` matches every `task.*` action at a dot boundary, so `doc` doesn't match `document.*`. `action=task.update` matches exactly.
- Keyset pagination on `(occurred_at, id)`, served by the `(organization_id, occurred_at DESC)` index.
- There is no write route (405). The table is append-only even for BYPASSRLS roles (Phase 1).
- **Accepted:** an `audit.read` holder sees members' IP addresses and user agents in the log. That's normal for an org admin's security log and is stated here so it's a decision, not an accident.

### 9.5 Tests and mutation checks

[tests/api/test_documents_audit_api.py](../tests/api/test_documents_audit_api.py) (38 tests) and [tests/db/test_audit_triggers.py](../tests/db/test_audit_triggers.py) (11 tests). Audit rows are append-only and can't be cleaned up, so audit assertions always filter on something unique to the test: a fresh resource id or the response's `X-Request-ID`.

| Mutation | Failing tests |
|---|---|
| Trigger copies every column's value (allow-list ignored) | 2 |
| Trigger never writes for the app role | 8 |
| Documents table has no audit trigger | 5 |
| Audit-read 403 probe removed | 4 |
| `action` prefix match without the dot boundary | 1 |
| Document create skips the hidden-project check | 1 |
| Request id / IP / user agent not passed to the transaction | 2 |

## 10. Next steps

Phase 3 is complete. Carried forward:

- **Phase 4: AI/LLM security**, the chatbot on top of `conversations`/`messages`. This includes the Phase 1 hand-off: user input must never be stored or replayed as `system`/tool content. Retrieval over documents must reuse these RLS rules, not a parallel permission check.
- **Document storage**: real upload/download with server-generated keys, verified size/SHA-256, content-type sniffing, and download authorization through the same `documents_select` rule.
- **Denied-attempt auditing** (§9.3): a second, short transaction recording `outcome = denied` for 403/404 on writes, with rate limits so it can't be used to flood the log.
- From step 2: leaving an org yourself, invitation expiry, stale pending-user cleanup.
