"""Document metadata and the audit trail over HTTP.

Seed documents are only read; every write uses a document the test creates
(tests/api/conftest.py deletes them afterwards). Audit rows are append-only,
so audit assertions always filter on something unique to the test: a fresh
resource id or the response's X-Request-ID.
"""

from __future__ import annotations

import hashlib
import json
import uuid

import pytest

from app.db.seed_dev import ID

A, B = ID.org("org_a"), ID.org("org_b")
APOLLO, HELIOS = ID.project("apollo"), ID.project("helios")
SEED_DOCS = {ID.document(k) for k in ("a_handbook", "a_comp_bands", "a_apollo_arch",
                                      "a_helios_research", "a_priya_notes")}


def docs(o=A) -> str:
    return f"/orgs/{o}/documents"


def doc(key_or_id, o=A) -> str:
    did = ID.document(key_or_id) if isinstance(key_or_id, str) else key_or_id
    return f"{docs(o)}/{did}"


def body(**over) -> dict:
    return {"title": "Design notes", "content_type": "text/markdown", "size_bytes": 1234,
            "sha256": hashlib.sha256(b"x").hexdigest(), **over}


def new_doc(client, headers, **over) -> dict:
    r = client.post(docs(), headers=headers, json=body(**over))
    assert r.status_code == 201, r.text
    return r.json()


def listed(client, headers, **params) -> set[uuid.UUID]:
    r = client.get(docs(), headers=headers, params={"limit": 100, **params})
    assert r.status_code == 200, r.text
    return {uuid.UUID(d["id"]) for d in r.json()["items"]}


# ------------------------------------------------------------------ read (brief item 8)
@pytest.mark.parametrize(("user", "expected"), [
    ("priya", {"a_handbook", "a_apollo_arch", "a_priya_notes"}),
    ("rahul", {"a_handbook", "a_apollo_arch"}),
    ("akshay", {"a_handbook", "a_comp_bands", "a_apollo_arch", "a_helios_research"}),
    ("meera", {"a_handbook"}),
])
def test_document_list_is_exactly_the_rls_set(client, auth_as, user, expected):
    assert listed(client, auth_as(user)) & SEED_DOCS == {ID.document(k) for k in expected}


@pytest.mark.parametrize(("user", "key", "o"), [
    ("priya", "a_comp_bands", A),        # someone else's private document
    ("rahul", "a_helios_research", A),   # project document, not a participant
    ("akshay", "a_priya_notes", A),      # admins get no exception for private documents
    ("akshay", "b_security_policy", A),  # another tenant's id under my org
    ("john", "a_handbook", B),           # org-wide in A is invisible from B
])
def test_unauthorized_documents_are_404(client, auth_as, user, key, o):
    r = client.get(doc(key, o), headers=auth_as(user))
    assert r.status_code == 404 and r.json() == {"detail": "Document not found"}


def test_list_filters_never_widen_the_result(client, auth_as):
    priya = auth_as("priya")
    assert listed(client, priya, project_id=str(HELIOS)) == set()
    assert listed(client, priya, visibility="private") & SEED_DOCS == {ID.document("a_priya_notes")}
    assert listed(client, priya, mine="true") & SEED_DOCS == {ID.document("a_priya_notes")}


# ------------------------------------------------------------------ create
def test_create_sets_owner_and_server_side_storage_key(client, auth_as, admin_conn):
    d = new_doc(client, auth_as("priya"), project_id=str(APOLLO), visibility="project")
    assert d["owner_id"] == str(ID.user("priya")) and "storage_key" not in d
    key = admin_conn.execute("SELECT storage_key FROM secureai.documents WHERE id = %s",
                             (d["id"],)).fetchone()[0]
    assert key.startswith(f"org/{A}/")
    # Visible to the project, not to a viewer outside it.
    assert client.get(doc(uuid.UUID(d["id"])), headers=auth_as("rahul")).status_code == 200
    assert client.get(doc(uuid.UUID(d["id"])), headers=auth_as("meera")).status_code == 404


def test_create_refusals(client, auth_as):
    assert client.post(docs(), headers=auth_as("meera"), json=body()).status_code == 403  # no upload
    # Akshay can see Apollo (project.read_all) but doesn't participate in it.
    r = client.post(docs(), headers=auth_as("akshay"), json=body(project_id=str(APOLLO)))
    assert r.status_code == 403
    # A hidden or nonexistent project is 404, before any write.
    for pid in (HELIOS, uuid.uuid4()):
        r = client.post(docs(), headers=auth_as("priya"), json=body(project_id=str(pid)))
        assert r.status_code == 404 and r.json() == {"detail": "Project not found"}


@pytest.mark.parametrize("over", [
    {"visibility": "project"},                                  # project visibility needs a project
    {"content_type": "text/html"},
    {"size_bytes": 50 * 1024 * 1024 + 1}, {"size_bytes": -1},
    {"sha256": "ZZ" * 32}, {"sha256": "ab"},
    {"title": ""},
    {"storage_key": "../../etc/passwd"},                        # mass assignment
    {"owner_id": str(ID.user("akshay"))},
    {"organization_id": str(B)},
    {"id": str(uuid.uuid4())},
])
def test_create_validation(client, auth_as, over):
    assert client.post(docs(), headers=auth_as("priya"), json=body(**over)).status_code == 422


# ------------------------------------------------------------------ update / delete (item 9)
def test_only_the_owner_updates(client, auth_as):
    d = new_doc(client, auth_as("priya"), visibility="organization")
    url = doc(uuid.UUID(d["id"]))
    r = client.patch(url, headers=auth_as("priya"), json={"title": "Renamed"})
    assert r.status_code == 200 and r.json()["title"] == "Renamed"
    for user in ("rahul", "akshay"):     # can see it, may not change it
        assert client.patch(url, headers=auth_as(user), json={"title": "x"}).status_code == 403
    assert client.patch(doc("a_comp_bands"), headers=auth_as("priya"),
                        json={"title": "x"}).status_code == 404


def test_update_project_rules(client, auth_as):
    priya = auth_as("priya")
    d = new_doc(client, priya, project_id=str(APOLLO), visibility="project")
    url = doc(uuid.UUID(d["id"]))
    assert client.patch(url, headers=priya, json={"project_id": str(HELIOS)}).status_code == 404
    # Detaching while still project-visible would orphan the visibility rule.
    assert client.patch(url, headers=priya, json={"project_id": None}).status_code == 422
    r = client.patch(url, headers=priya, json={"project_id": None, "visibility": "private"})
    assert r.status_code == 200 and r.json()["project_id"] is None
    for bad in ({}, {"title": None}, {"owner_id": str(ID.user("rahul"))}, {"sha256": "00" * 32}):
        assert client.patch(url, headers=priya, json=bad).status_code == 422, bad


def test_delete_rules(client, auth_as):
    priya, akshay = auth_as("priya"), auth_as("akshay")
    d = new_doc(client, priya, visibility="organization")
    url = doc(uuid.UUID(d["id"]))
    assert client.delete(url, headers=akshay).status_code == 403   # admin, visible, not owner
    assert client.delete(url, headers=priya).status_code == 204
    assert client.delete(url, headers=priya).status_code == 404
    hidden = new_doc(client, priya)
    assert client.delete(doc(uuid.UUID(hidden["id"])), headers=akshay).status_code == 404


def test_project_with_documents_cannot_be_deleted(client, auth_as):
    rahul = auth_as("rahul")
    p = client.post(f"/orgs/{A}/projects", headers=rahul, json={"name": "Doc holder"}).json()
    new_doc(client, rahul, project_id=p["id"], visibility="project")
    r = client.delete(f"/orgs/{A}/projects/{p['id']}", headers=rahul)
    assert r.status_code == 409


# ------------------------------------------------------------------ audit trail
def audit(client, headers, **params) -> list[dict]:
    r = client.get(f"/orgs/{A}/audit-logs", headers=headers, params={"limit": 100, **params})
    assert r.status_code == 200, r.text
    return r.json()["items"]


def test_every_write_is_audited_with_actor_and_request_id(client, auth_as):
    priya, akshay = auth_as("priya"), auth_as("akshay")
    r = client.post(docs(), headers=priya, json=body())
    did, rid = r.json()["id"], r.headers["X-Request-ID"]
    r2 = client.patch(doc(uuid.UUID(did)), headers=priya, json={"visibility": "organization"})
    r3 = client.delete(doc(uuid.UUID(did)), headers=priya)

    rows = audit(client, akshay, resource_id=did)
    assert [(e["action"], e["actor_user_id"], e["request_id"]) for e in reversed(rows)] == [
        ("document.create", str(ID.user("priya")), rid),
        ("document.update", str(ID.user("priya")), r2.headers["X-Request-ID"]),
        ("document.delete", str(ID.user("priya")), r3.headers["X-Request-ID"]),
    ]
    assert rows[0]["user_agent"] == "testclient" and rows[0]["outcome"] == "success"
    assert rows[1]["metadata"] == {"changed": ["visibility"],
                                   "values": {"visibility": {"old": "private", "new": "organization"}}}


def test_private_content_never_enters_the_audit_log(client, auth_as):
    """Admins hold audit.read but must not read private task text through it."""
    secret_title, secret_desc = f"secret-{uuid.uuid4().hex}", f"secret-{uuid.uuid4().hex}"
    priya = auth_as("priya")
    t = client.post(f"/orgs/{A}/projects/{APOLLO}/tasks", headers=priya,
                    json={"title": secret_title, "description": "first"}).json()
    client.patch(f"/orgs/{A}/tasks/{t['id']}", headers=priya, json={"description": secret_desc})

    rows = audit(client, auth_as("akshay"), resource_id=t["id"])
    assert [e["action"] for e in rows] == ["task.update", "task.create"]
    assert rows[0]["metadata"] == {"changed": ["description"], "values": {}}
    dumped = json.dumps(rows)
    assert secret_title not in dumped and secret_desc not in dumped and "first" not in dumped
    # ...while the admin still can't read the task itself.
    assert client.get(f"/orgs/{A}/tasks/{t['id']}", headers=auth_as("akshay")).status_code == 404


def test_refused_writes_leave_no_audit_row(client, auth_as, admin_conn):
    r = client.patch(doc("a_handbook"), headers=auth_as("rahul"), json={"title": "x"})
    assert r.status_code == 403
    r2 = client.post(docs(), headers=auth_as("meera"), json=body())
    assert r2.status_code == 403
    for resp in (r, r2):
        assert admin_conn.execute("SELECT count(*) FROM secureai.audit_logs WHERE request_id = %s",
                                  (resp.headers["X-Request-ID"],)).fetchone()[0] == 0


def test_membership_and_override_changes_are_audited(client, auth_as):
    akshay = auth_as("akshay")
    assert client.patch(f"/orgs/{A}/members/{ID.user('priya')}", headers=akshay,
                        json={"role": "viewer"}).status_code == 200
    rows = audit(client, akshay, action="member.update", actor_id=str(ID.user("akshay")))
    vals = rows[0]["metadata"]["values"]
    assert rows[0]["metadata"]["changed"] == ["role_id"] and set(vals["role_id"]) == {"old", "new"}

    r = client.put(f"/orgs/{A}/members/{ID.user('priya')}/overrides/audit.read", headers=akshay,
                   json={"effect": "deny", "reason": "auditing test"})
    rows = audit(client, akshay, action="permission_override")
    assert rows[0]["request_id"] == r.headers["X-Request-ID"]
    assert rows[0]["metadata"]["values"]["effect"] == "deny"
    assert "auditing test" not in json.dumps(rows[0])        # free-text reason stays out


@pytest.mark.parametrize("user", ["rahul", "priya", "meera"])
def test_audit_read_needs_audit_read(client, auth_as, user):
    r = client.get(f"/orgs/{A}/audit-logs", headers=auth_as(user))
    assert r.status_code == 403 and r.json() == {"detail": "Not allowed"}


def test_audit_permission_changes_apply_on_the_next_request(client, auth_as):
    akshay, priya = auth_as("akshay"), auth_as("priya")
    url = f"/orgs/{A}/members/{ID.user('priya')}/overrides/audit.read"
    client.put(url, headers=akshay, json={"effect": "grant", "reason": "incident review"})
    assert client.get(f"/orgs/{A}/audit-logs", headers=priya).status_code == 200
    client.delete(url, headers=akshay)
    assert client.get(f"/orgs/{A}/audit-logs", headers=priya).status_code == 403


def test_audit_log_is_tenant_scoped(client, auth_as):
    john = auth_as("john")
    r = client.post(docs(B), headers=john, json=body())
    did = r.json()["id"]
    assert audit(client, auth_as("akshay"), resource_id=did) == []
    rows = client.get(f"/orgs/{B}/audit-logs", headers=john, params={"resource_id": did}).json()["items"]
    assert [e["action"] for e in rows] == ["document.create"]
    assert client.get(f"/orgs/{B}/audit-logs", headers=auth_as("akshay")).status_code == 403


def test_audit_filters_and_pagination(client, auth_as):
    priya, akshay = auth_as("priya"), auth_as("akshay")
    ids = [new_doc(client, priya)["id"] for _ in range(3)]
    created = [e for e in audit(client, akshay, action="document.create")
               if e["resource_id"] in ids]
    assert len(created) == 3
    assert all(e["action"].startswith("document.") for e in audit(client, akshay, action="document"))
    # "doc" is not a prefix of "document." at a dot boundary.
    assert audit(client, akshay, action="doc") == []

    seen, resources, cursor = [], set(), None
    for _ in range(50):
        r = client.get(f"/orgs/{A}/audit-logs", headers=akshay,
                       params={"limit": 1, "resource_type": "document", "actor_id": str(ID.user("priya")),
                               **({"cursor": cursor} if cursor else {})})
        seen += [e["id"] for e in r.json()["items"]]
        resources |= {e["resource_id"] for e in r.json()["items"]}
        if not (cursor := r.json()["next_cursor"]):
            break
    assert set(ids) <= resources and len(seen) == len(set(seen))   # no row twice

    for bad in ({"action": "DROP TABLE"}, {"outcome": "maybe"}, {"actor_id": "1"}, {"limit": 0}):
        assert client.get(f"/orgs/{A}/audit-logs", headers=akshay, params=bad).status_code == 422


def test_there_is_no_audit_write_endpoint(client, auth_as):
    akshay = auth_as("akshay")
    for method in ("post", "put", "patch", "delete"):
        assert getattr(client, method)(f"/orgs/{A}/audit-logs", headers=akshay).status_code == 405
