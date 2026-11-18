# SecureAI Workspace — Phase 3: Authorization APIs

**Status:** step 1 of 3 done (shared building blocks, projects, project members, tasks). Step 2 (organization, members, overrides) is next (§8).

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
| Tests | [tests/api/test_projects_api.py](../tests/api/test_projects_api.py), [tests/api/test_tasks_api.py](../tests/api/test_tasks_api.py) |

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

## 8. Next steps

- **Step 2: organization and members.** `GET/PATCH /orgs/{org}` (`organization.update`, name only). Members: list, invite (needs a narrow definer function, because RLS rightly hides users outside the org from an email lookup), role change and removal. These exercise the rank rules, the not-self rule, `removed`→`user.delete` and the last-admin trigger (→ 409). Permission overrides: grant/deny/expire, "you can't delegate what you don't hold". Membership changes should also revoke the member's refresh sessions (`membership_revoked`).
- **Step 3: documents and audit.** Document metadata CRUD (upload/storage is a later phase; `storage_key` is server-generated), `GET /orgs/{org}/audit-logs` (`audit.read`) with keyset pagination, an `audit_logs` row per API write, and a final pass filling Phase 1 §8.2's "Phase 2 adds" column.
