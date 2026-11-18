"""Projects and project members over HTTP: tenancy, IDOR, mass assignment, 404 vs 403.

Writes commit (as in production), so every test that changes data creates its
own project first; seed rows are only read. The DB tests later in the session
depend on them staying intact.
"""

from __future__ import annotations

import uuid

import pytest

from app.db.seed_dev import ID

A, B = ID.org("org_a"), ID.org("org_b")
APOLLO, ATLAS, HELIOS, POLARIS = (ID.project(k) for k in ("apollo", "atlas", "helios", "polaris"))
SEED_A_PROJECTS = {APOLLO, ATLAS, HELIOS}


def projects(org=A) -> str:
    return f"/orgs/{org}/projects"


def all_ids(client, headers, url) -> set[uuid.UUID]:
    out, cursor = set(), None
    for _ in range(50):   # a broken cursor must fail the test, not hang it
        r = client.get(url, headers=headers, params={"limit": 100, **({"cursor": cursor} if cursor else {})})
        assert r.status_code == 200, r.text
        out |= {uuid.UUID(i["id"]) for i in r.json()["items"]}
        if not (cursor := r.json()["next_cursor"]):
            return out
    raise AssertionError("pagination never terminated")


def new_project(client, headers, name="Scratch project") -> dict:
    r = client.post(projects(), headers=headers, json={"name": name})
    assert r.status_code == 201, r.text
    return r.json()


# ------------------------------------------------------- authn + tenancy
def test_unauthenticated_is_401(client):
    assert client.get(projects()).status_code == 401
    assert client.get(projects(), headers={"Authorization": "Bearer nope"}).status_code == 401


def test_foreign_and_nonexistent_orgs_get_the_same_403(client, auth_as):
    """Brief item 7 (org tampering): the path org is re-validated by set_context.
    A real foreign org and a random uuid are indistinguishable."""
    priya = auth_as("priya")
    foreign = client.get(projects(B), headers=priya)
    random_org = client.get(projects(uuid.uuid4()), headers=priya)
    assert foreign.status_code == random_org.status_code == 403
    assert foreign.json() == random_org.json() == {"detail": "No access to this organization"}


def test_project_lists_are_exactly_what_rls_allows(client, auth_as):
    assert all_ids(client, auth_as("priya"), projects()) & SEED_A_PROJECTS == {APOLLO}
    assert all_ids(client, auth_as("rahul"), projects()) & SEED_A_PROJECTS == {APOLLO, ATLAS}
    akshay = all_ids(client, auth_as("akshay"), projects())   # project.read_all
    assert SEED_A_PROJECTS <= akshay and POLARIS not in akshay


def test_idor_on_hidden_and_cross_tenant_ids_is_404(client, auth_as):
    priya = auth_as("priya")
    for pid in (HELIOS, POLARIS, uuid.uuid4()):   # hidden / other tenant / nonexistent
        r = client.get(f"{projects()}/{pid}", headers=priya)
        assert (r.status_code, r.json()) == (404, {"detail": "Project not found"})


def test_meera_sees_each_org_only_in_its_own_context(client, auth_as):
    meera = auth_as("meera")   # viewer in A (no projects), employee in B (Polaris member)
    assert all_ids(client, meera, projects(A)) & (SEED_A_PROJECTS | {POLARIS}) == set()
    assert POLARIS in all_ids(client, meera, projects(B))
    assert client.get(f"{projects(A)}/{POLARIS}", headers=meera).status_code == 404


# ------------------------------------------------------- create / update / delete
@pytest.mark.parametrize("field,value", [
    ("owner_id", str(ID.user("akshay"))),
    ("organization_id", str(B)),
    ("id", str(uuid.uuid4())),
    ("status_code", "x"),
])
def test_mass_assignment_is_rejected(client, auth_as, field, value):
    r = client.post(projects(), headers=auth_as("rahul"), json={"name": "x", field: value})
    assert r.status_code == 422


def test_create_requires_project_create_and_sets_owner_from_context(client, auth_as):
    r = client.post(projects(), headers=auth_as("priya"), json={"name": "Not allowed"})
    assert (r.status_code, r.json()) == (403, {"detail": "Not allowed"})   # no SQL/policy names

    p = new_project(client, auth_as("rahul"), "  Rahul's new project  ")
    assert p["owner_id"] == str(ID.user("rahul")) and p["name"] == "Rahul's new project"
    assert uuid.UUID(p["id"]) in all_ids(client, auth_as("akshay"), projects())
    assert uuid.UUID(p["id"]) not in all_ids(client, auth_as("john"), projects(B))


def test_update_is_403_when_visible_and_404_when_hidden(client, auth_as):
    priya = auth_as("priya")   # sees Apollo, lacks project.update
    assert client.patch(f"{projects()}/{APOLLO}", headers=priya, json={"name": "x"}).status_code == 403
    assert client.patch(f"{projects()}/{HELIOS}", headers=priya, json={"name": "x"}).status_code == 404
    # Akshay sees Apollo via project.read_all but doesn't manage it: read != write.
    assert client.patch(f"{projects()}/{APOLLO}", headers=auth_as("akshay"),
                        json={"name": "x"}).status_code == 403


def test_owner_updates_and_patch_validation(client, auth_as):
    rahul = auth_as("rahul")
    p = new_project(client, rahul)
    url = f"{projects()}/{p['id']}"
    r = client.patch(url, headers=rahul, json={"status": "archived", "description": None})
    assert r.status_code == 200 and r.json()["status"] == "archived"
    assert client.patch(url, headers=rahul, json={}).status_code == 422
    assert client.patch(url, headers=rahul, json={"name": None}).status_code == 422
    assert client.patch(url, headers=rahul, json={"owner_id": str(ID.user("priya"))}).status_code == 422


def test_delete_rules(client, auth_as):
    rahul = auth_as("rahul")
    p = new_project(client, rahul)
    url = f"{projects()}/{p['id']}"
    assert client.post(f"{url}/tasks", headers=rahul, json={"title": "blocks delete"}).status_code == 201
    r = client.delete(url, headers=rahul)
    assert r.status_code == 409 and "archive" in r.json()["detail"]

    empty = new_project(client, rahul)
    eurl = f"{projects()}/{empty['id']}"
    assert client.delete(eurl, headers=auth_as("akshay")).status_code == 403   # sees it, not owner
    assert client.delete(eurl, headers=rahul).status_code == 204
    assert client.delete(eurl, headers=rahul).status_code == 404


# ------------------------------------------------------------------ members
def test_member_management(client, auth_as):
    rahul, priya = auth_as("rahul"), auth_as("priya")
    p = new_project(client, rahul)
    members = f"{projects()}/{p['id']}/members"

    r = client.post(members, headers=rahul, json={"user_id": str(ID.user("priya"))})
    assert r.status_code == 201 and r.json()["project_role"] == "member"
    assert r.json()["display_name"] == "Priya"
    assert client.post(members, headers=rahul,
                       json={"user_id": str(ID.user("priya"))}).status_code == 409

    # Priya can now see the project but can't manage its members.
    assert client.get(members, headers=priya).status_code == 200
    assert client.post(members, headers=priya,
                       json={"user_id": str(ID.user("meera"))}).status_code == 403
    assert client.patch(f"{members}/{ID.user('priya')}", headers=priya,
                        json={"project_role": "lead"}).status_code == 403   # no self-promotion

    # Another tenant's user can't be added, and the body can't smuggle fields.
    r = client.post(members, headers=rahul, json={"user_id": str(ID.user("david"))})
    assert (r.status_code, r.json()["detail"]) == (422, "User is not a member of this organization")
    assert client.post(members, headers=rahul, json={"user_id": str(ID.user("meera")),
                                                     "added_by": str(ID.user("akshay"))}).status_code == 422

    assert client.patch(f"{members}/{ID.user('priya')}", headers=rahul,
                        json={"project_role": "lead"}).json()["project_role"] == "lead"
    # Anyone may leave; afterwards the project is hidden from them again.
    assert client.delete(f"{members}/{ID.user('priya')}", headers=priya).status_code == 204
    assert client.get(members, headers=priya).status_code == 404
    assert client.delete(f"{members}/{ID.user('priya')}", headers=rahul).status_code == 404


def test_members_of_hidden_projects_are_404(client, auth_as):
    priya = auth_as("priya")
    assert client.get(f"{projects()}/{HELIOS}/members", headers=priya).status_code == 404
    assert client.post(f"{projects()}/{POLARIS}/members", headers=auth_as("akshay"),
                       json={"user_id": str(ID.user("rahul"))}).status_code == 404


def test_directory_names_hidden_without_user_read(client, auth_as, admin_conn):
    """Meera is a Viewer in Org A (no user.read): she sees member ids, not names."""
    rahul = auth_as("rahul")
    p = new_project(client, rahul)
    members = f"{projects()}/{p['id']}/members"
    for who in ("meera", "priya"):
        assert client.post(members, headers=rahul, json={"user_id": str(ID.user(who))}).status_code == 201
    names = {r["user_id"]: r["display_name"]
             for r in client.get(members, headers=auth_as("meera")).json()}
    assert names == {str(ID.user("meera")): "Meera",   # her own row: users_select_self
                     str(ID.user("priya")): None}      # directory hidden
    assert client.get(members, headers=rahul).json()[1]["display_name"] == "Priya"
