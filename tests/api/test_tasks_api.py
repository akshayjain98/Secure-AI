"""Tasks over HTTP: private-task IDOR, column rules, assignee validation, pagination, revocation."""

from __future__ import annotations

import base64
import json
import uuid

import pytest

from app.db.seed_dev import ID, TASKS
from tests.api.test_projects_api import A, APOLLO, POLARIS, all_ids, new_project

SEED_TASKS = {ID.task(k) for k in TASKS}
TASKS_URL = f"/orgs/{A}/tasks"


def task_url(tid) -> str:
    return f"{TASKS_URL}/{tid}"


def create(client, headers, project, **body) -> dict:
    r = client.post(f"/orgs/{A}/projects/{project}/tasks", headers=headers,
                    json={"title": "A task", **body})
    assert r.status_code == 201, r.text
    return r.json()


# ------------------------------------------------------------------ reads
def test_task_list_is_exactly_the_rls_set(client, auth_as):
    """Brief items 4 and 12: the handler has no WHERE owner/org filter at all."""
    seen = all_ids(client, auth_as("priya"), TASKS_URL) & SEED_TASKS
    assert seen == {ID.task(k) for k in (
        "rahul_cutover", "rahul_runbook", "priya_validation",        # Apollo, project-visible
        "priya_private_learning", "priya_private_review")}           # her own private tasks


@pytest.mark.parametrize("user", ["rahul", "akshay", "meera"])
def test_private_task_idor_is_404_for_read_update_and_delete(client, auth_as, user):
    """Rahul leads Apollo, Akshay is org admin with project.read_all: neither
    can see, change or delete Priya's private task, and they can't tell it exists."""
    h, tid = auth_as(user), ID.task("priya_private_learning")
    assert client.get(task_url(tid), headers=h).status_code == 404
    assert client.patch(task_url(tid), headers=h, json={"status": "done"}).status_code == 404
    assert client.delete(task_url(tid), headers=h).status_code == 404
    missing = client.get(task_url(uuid.uuid4()), headers=h)
    assert missing.json() == client.get(task_url(tid), headers=h).json() == {"detail": "Task not found"}


def test_cross_tenant_task_and_project_ids_are_404(client, auth_as):
    priya = auth_as("priya")
    assert client.get(task_url(ID.task("david_ci")), headers=priya).status_code == 404
    r = client.post(f"/orgs/{A}/projects/{POLARIS}/tasks", headers=priya, json={"title": "x"})
    assert r.status_code == 404
    # Meera is IN Org B, but in Org A context her Org B task doesn't exist.
    assert client.get(task_url(ID.task("meera_catalog")), headers=auth_as("meera")).status_code == 404


# ------------------------------------------------------------------ writes
@pytest.mark.parametrize("field", ["owner_id", "organization_id", "project_id", "id", "created_at"])
def test_task_mass_assignment_is_rejected(client, auth_as, field):
    r = client.post(f"/orgs/{A}/projects/{APOLLO}/tasks", headers=auth_as("priya"),
                    json={"title": "x", field: str(uuid.uuid4())})
    assert r.status_code == 422
    r = client.patch(task_url(ID.task("priya_validation")), headers=auth_as("priya"),
                     json={field: str(uuid.uuid4())})
    assert r.status_code == 422


def test_new_tasks_are_private_and_owned_by_the_caller(client, auth_as):
    t = create(client, auth_as("priya"), APOLLO)
    assert (t["visibility"], t["owner_id"], t["project_id"]) == ("private", str(ID.user("priya")), str(APOLLO))
    assert client.get(task_url(t["id"]), headers=auth_as("rahul")).status_code == 404


def test_create_needs_project_participation_and_task_create(client, auth_as):
    # Akshay can SEE Apollo (project.read_all) but isn't a participant -> 403, not 404.
    r = client.post(f"/orgs/{A}/projects/{APOLLO}/tasks", headers=auth_as("akshay"), json={"title": "x"})
    assert (r.status_code, r.json()) == (403, {"detail": "Not allowed"})
    # Meera (viewer) can't even see a project.
    assert client.post(f"/orgs/{A}/projects/{APOLLO}/tasks", headers=auth_as("meera"),
                       json={"title": "x"}).status_code == 404


@pytest.mark.parametrize("assignee", ["meera", "david"], ids=["org-member-not-in-project", "other-tenant"])
def test_assignee_must_participate_in_the_project(client, auth_as, assignee):
    r = client.post(f"/orgs/{A}/projects/{APOLLO}/tasks", headers=auth_as("rahul"),
                    json={"title": "x", "assignee_id": str(ID.user(assignee))})
    assert (r.status_code, r.json()) == (403, {"detail": "Not allowed"})


def test_assignee_can_progress_but_not_publish_or_reassign(client, auth_as):
    rahul, priya = auth_as("rahul"), auth_as("priya")
    t = create(client, rahul, APOLLO, assignee_id=str(ID.user("priya")))   # private, assigned
    url = task_url(t["id"])

    assert client.patch(url, headers=priya, json={"status": "in_progress"}).json()["status"] == "in_progress"
    r = client.patch(url, headers=priya, json={"visibility": "project"})
    assert (r.status_code, r.json()) == (403, {"detail": "Only the task owner may change task visibility"})
    r = client.patch(url, headers=priya, json={"assignee_id": None})
    assert r.status_code == 403 and "reassign" in r.json()["detail"]
    assert client.delete(url, headers=priya).status_code == 403   # employee lacks task.delete

    # The owner can do all of it; an explicit null unassigns.
    r = client.patch(url, headers=rahul, json={"assignee_id": None, "visibility": "project"})
    assert r.status_code == 200 and r.json()["assignee_id"] is None
    assert client.get(url, headers=priya).status_code == 200      # now project-visible
    assert client.delete(url, headers=rahul).status_code == 204


def test_patch_validation(client, auth_as):
    priya = auth_as("priya")
    t = create(client, priya, APOLLO, due_date="2026-12-01", description="d")
    url = task_url(t["id"])
    assert client.patch(url, headers=priya, json={}).status_code == 422
    assert client.patch(url, headers=priya, json={"title": None}).status_code == 422
    assert client.patch(url, headers=priya, json={"title": "   "}).status_code == 422
    assert client.patch(url, headers=priya, json={"status": "archived"}).status_code == 422
    r = client.patch(url, headers=priya, json={"due_date": None, "description": None, "title": "T2"})
    assert (r.json()["due_date"], r.json()["description"], r.json()["title"]) == (None, None, "T2")


# ------------------------------------------------------------- pagination
def test_keyset_pagination_walks_every_row_once(client, auth_as):
    rahul = auth_as("rahul")
    p = new_project(client, rahul)
    made = {create(client, rahul, p["id"], title=f"t{i}")["id"] for i in range(5)}

    seen, cursor, pages = [], None, 0
    while pages < 10:
        params = {"project_id": p["id"], "limit": 2, **({"cursor": cursor} if cursor else {})}
        body = client.get(TASKS_URL, headers=rahul, params=params).json()
        seen += [i["id"] for i in body["items"]]
        pages += 1
        if not (cursor := body["next_cursor"]):
            break
    assert pages == 3 and len(seen) == 5 and set(seen) == made


@pytest.mark.parametrize("params", [{"cursor": "!!!"}, {"cursor": "bm9wZQ"}, {"limit": 0}, {"limit": 101}])
def test_bad_paging_input_is_422(client, auth_as, params):
    assert client.get(TASKS_URL, headers=auth_as("priya"), params=params).status_code == 422


def test_forged_cursor_cannot_widen_the_result(client, auth_as):
    """The cursor only positions the scan; RLS still filters every row."""
    forged = base64.urlsafe_b64encode(
        json.dumps(["9999-01-01T00:00:00+00:00", str(uuid.UUID(int=2**128 - 1))]).encode()).decode()
    ids = all_ids(client, auth_as("priya"), TASKS_URL)
    r = client.get(TASKS_URL, headers=auth_as("priya"), params={"cursor": forged, "limit": 100})
    assert {uuid.UUID(i["id"]) for i in r.json()["items"]} <= ids
    assert ID.task("priya_private_learning") not in all_ids(client, auth_as("rahul"), TASKS_URL)


# ------------------------------------------------------------- revocation
def test_permission_revocation_applies_to_the_next_request(client, auth_as, admin_conn):
    """Brief item 14 over HTTP: the token is unchanged, the DB re-evaluates."""
    priya = auth_as("priya")
    assert client.get(task_url(ID.task("priya_validation")), headers=priya).status_code == 200
    admin_conn.execute(
        "INSERT INTO secureai.user_permission_overrides "
        "(organization_id, user_id, permission_id, effect, reason, created_by) "
        "SELECT %s, %s, id, 'deny', 'api revocation test', %s FROM secureai.permissions "
        "WHERE code = 'task.read'", (A, ID.user("priya"), ID.user("akshay")))
    try:
        assert client.get(task_url(ID.task("priya_validation")), headers=priya).status_code == 404
        assert client.get(TASKS_URL, headers=priya).json()["items"] == []
    finally:
        admin_conn.execute("DELETE FROM secureai.user_permission_overrides "
                           "WHERE user_id = %s AND reason = 'api revocation test'", (ID.user("priya"),))
    assert client.get(task_url(ID.task("priya_validation")), headers=priya).status_code == 200
